# Prometheus Custom Exporters & Scrape Target Architecture

## Architecture Overview

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Instrumented   │     │   Custom         │     │   Prometheus    │
│  Application    │────▶│   Exporter       │────▶│   Server        │
│  (Go/Python)    │     │   :9100-9999     │     │   :9090         │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                    ┌─────────────────────────────────────┘
                    ▼
         ┌─────────────────────┐
         │  Service Discovery  │
         │  + relabel_configs  │
         │  + metric_relabel   │
         └─────────────────────┘
```

**Component Contracts:**
- **Exporter**: HTTP `/metrics` endpoint, `text/plain; version=0.0.4` content-type
- **Scrape Interval**: 15s default, 10s minimum for high-cardinality targets
- **Scrape Timeout**: 10s default, must be < scrape_interval
- **Label Cardinality**: Target < 100k unique label combinations per metric

---

## Concrete Configs / Code Recipes

### 1. Go Custom Exporter — `client_golang` Collector Interface

```go
// exporter/main.go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type CustomCollector struct {
	requestDuration *prometheus.HistogramVec
	activeConns     *prometheus.GaugeVec
	errorsTotal     *prometheus.CounterVec
	cacheSize       prometheus.Gauge
}

func NewCustomCollector() *CustomCollector {
	return &CustomCollector{
		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "app_request_duration_seconds",
				Help:    "Request latency distribution",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "endpoint", "status"},
		),
		activeConns: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "app_active_connections",
				Help: "Current active connections",
			},
			[]string{"pool"},
		),
		errorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "app_errors_total",
				Help: "Total errors by type",
			},
			[]string{"type", "severity"},
		),
		cacheSize: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "app_cache_size_bytes",
				Help: "Current cache size in bytes",
			},
		),
	}
}

func (c *CustomCollector) Describe(ch chan<- *prometheus.Desc) {
	c.requestDuration.Describe(ch)
	c.activeConns.Describe(ch)
	c.errorsTotal.Describe(ch)
	c.cacheSize.Describe(ch)
}

func (c *CustomCollector) Collect(ch chan<- prometheus.Metric) {
	c.requestDuration.Collect(ch)
	c.activeConns.Collect(ch)
	c.errorsTotal.Collect(ch)
	c.cacheSize.Collect(ch)
}

func main() {
	collector := NewCustomCollector()
	reg := prometheus.NewRegistry()
	reg.MustRegister(collector)
	reg.MustRegister(prometheus.NewGoCollector())
	reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
		MaxRequestsInFlight: 100,
	}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:         ":9101",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("Exporter listening on :9101")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Graceful shutdown failed: %v", err)
	}
}
```

```go
// Instrumentation middleware example
func InstrumentHandler(collector *CustomCollector, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(wrapped, r)
		duration := time.Since(start).Seconds()
		collector.requestDuration.WithLabelValues(
			r.Method, r.URL.Path, strconv.Itoa(wrapped.statusCode),
		).Observe(duration)
	})
}
```

### 2. Python Custom Exporter — `prometheus_client` Custom Collector

```python
# exporter/custom_collector.py
import time
import random
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from prometheus_client import (
    CollectorRegistry, Gauge, Counter, Histogram, Summary,
    generate_latest, CONTENT_TYPE_LATEST, REGISTRY
)
from prometheus_client.core import Collector, Metric, GaugeMetricFamily, CounterMetricFamily, HistogramMetricFamily

class AppMetricsCollector(Collector):
    """Custom collector implementing the Collector interface for dynamic metrics."""
    
    def __init__(self, app_state):
        self.app_state = app_state
        self._lock = threading.Lock()
        
        # Standard metrics (registered globally)
        self.request_duration = Histogram(
            'app_request_duration_seconds',
            'Request latency distribution',
            ['method', 'endpoint', 'status'],
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
        )
        self.active_connections = Gauge(
            'app_active_connections',
            'Current active connections',
            ['pool']
        )
        self.errors_total = Counter(
            'app_errors_total',
            'Total errors by type',
            ['type', 'severity']
        )
        self.cache_size = Gauge(
            'app_cache_size_bytes',
            'Current cache size in bytes'
        )
    
    def collect(self):
        """Called by Prometheus during scrape. Must yield Metric objects."""
        with self._lock:
            # Dynamic metrics from app state
            yield GaugeMetricFamily(
                'app_thread_pool_active',
                'Active threads in pool',
                value=self.app_state.get('thread_pool_active', 0)
            )
            yield GaugeMetricFamily(
                'app_queue_depth',
                'Current queue depth',
                value=self.app_state.get('queue_depth', 0)
            )
            # Histogram requires manual bucket construction
            hist = HistogramMetricFamily(
                'app_custom_latency_seconds',
                'Custom latency histogram',
                labels=['operation']
            )
            for op, values in self.app_state.get('latencies', {}).items():
                for v in values:
                    hist.add_sample('app_custom_latency_seconds_bucket', 
                                   labels={'operation': op, 'le': '+Inf'}, value=1)
            yield hist

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-Type', CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(generate_latest(REGISTRY))
        elif self.path == '/healthz':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'ok')
        else:
            self.send_response(404)
            self.end_headers()

def run_exporter(port=9102):
    app_state = {
        'thread_pool_active': 10,
        'queue_depth': 0,
        'latencies': {'db_query': [0.01, 0.02, 0.015]}
    }
    
    REGISTRY.register(AppMetricsCollector(app_state))
    
    server = HTTPServer(('', port), MetricsHandler)
    print(f"Python exporter starting on port {port}")
    server.serve_forever()

if __name__ == '__main__':
    run_exporter()
```

```python
# Flask integration with prometheus_client
# app.py
