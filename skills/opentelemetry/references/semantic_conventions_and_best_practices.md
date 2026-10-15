# OpenTelemetry Semantic Conventions & Performance Best Practices
## Architecture Overview
OpenTelemetry is an open standard for collecting and generating telemetry data, providing a unified approach to instrumentation across different languages and frameworks. The OpenTelemetry semantic conventions offer a solution to the problem of inconsistent and confusing telemetry data labeling, ensuring that data is consistently structured and easily understood by everyone.

### Standard Semantic Attribute Namespaces
The following standard semantic attribute namespaces are widely adopted:

* `service.name`: The name of the service or application.
* `http.request.method`: The HTTP request method (e.g., GET, POST, PUT, DELETE).
* `db.system`: The database system (e.g., MySQL, PostgreSQL, MongoDB).
* `exception.message`: The error message.

### Cardinality Explosion Mitigation Rules
To prevent cardinality explosion, follow these rules:

* Use a single attribute for a single piece of information.
* Avoid using arrays or lists for attributes.
* Use a single attribute for a single dimension (e.g., use `http.request.method` instead of `http.request.method[0]`).

### Prometheus Remote-Write Compatibility
To ensure compatibility with Prometheus remote-write, follow these guidelines:

* Use the `otlp.proto` protocol for sending data to Prometheus.
* Set the `prometheus_remote_write` configuration option to `true`.
* Use the `prometheus_remote_write_url` configuration option to specify the URL of the Prometheus server.

## Concrete Configs / Code Recipes
### YAML Configuration
```yml
# OpenTelemetry configuration
otlp:
  endpoint: "http://localhost:4317"
  protocol: "http"

# Prometheus configuration
prometheus:
  remote_write:
    enabled: true
    url: "http://localhost:9090/api/v1/write"
```

### Go Configuration
```go
import (
	"context"
	"fmt"
	"log"

	"google.golang.org/grpc"

	otlp "go.opentelemetry.io/otel/sdk/trace"
	otlpgrpc "go.opentelemetry.io/otel/sdk/trace/otlp"
)

func main() {
	// Create a new OTLP exporter
	exporter, err := otlpgrpc.New(
		otlpgrpc.WithEndpoint("http://localhost:4317"),
		otlpgrpc.WithProtocol(otlpgrpc.ProtoGrpc),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Create a new OTLP tracer provider
	provider := otlp.NewTracerProvider(
		otlp.WithBatcher(exporter),
	)

	// Create a new OTLP client
	client, err := otlpgrpc.NewClient(
		otlpgrpc.WithEndpoint("http://localhost:4317"),
		otlpgrpc.WithProtocol(otlpgrpc.ProtoGrpc),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Create a new OTLP request
	req := &otlp.ExportTraceServiceRequest{
		Resource: &otlp.Resource{
			Attributes: map[string]string{
				"service.name": "my-service",
			},
		},
		Traces: []*otlp.Trace{
			{
				Spans: []*otlp.Span{
					{
						Attributes: map[string]string{
							"http.request.method": "GET",
						},
					},
				},
			},
		},
	}

	// Send the request to the OTLP server
	resp, err := client.Export(context.Background(), req)
	if err != nil {
		log.Fatal(err)
	}

	// Print the response
	fmt.Println(resp)
}

```

### JavaScript/TypeScript Configuration
```javascript
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { registerInstrumentations } from '@opentelemetry/instrumentation';
import { SimpleSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';

// Create a new OTLP exporter
const exporter = new OTLPTraceExporter({
  url: 'http://localhost:4317',
});

// Create a new OTLP tracer provider
const provider = new NodeTracerProvider();
provider.addSpanProcessor(new SimpleSpanProcessor(exporter));
provider.register();

// Register auto-instrumentations
registerInstrumentations({
  instrumentations: [
    // Add your instrumentations here
  ],
});

// Create a new OTLP client
const client = new OTLPTraceExporter({
  url: 'http://localhost:4317',
});

// Create a new OTLP request
const req = {
  resource: {
    attributes: {
      'service.name': 'my-service',
    },
  },
  traces: [
    {
      spans: [
        {
          attributes: {
            'http.request.method': 'GET',
          },
        },
      ],
    },
  ],
};

// Send the request to the OTLP server
client.export(req).then((resp) => {
  console.log(resp);
}).catch((err) => {
  console.error(err);
});
```

### Shell Configuration
```bash
# Create a new OTLP exporter
exporter=$(curl -X POST \
  http://localhost:4317/v1/traces \
  -H 'Content-Type: application/json' \
  -d '{"resource": {"attributes": {"service.name": "my-service"}}}')

# Create a new OTLP tracer provider
provider=$(curl -X POST \
  http://localhost:4317/v1/traces \
  -H 'Content-Type: application/json' \
  -d '{"traces": [{"spans": [{"attributes": {"http.request.method": "GET"}}]}]}')

# Send the request to the OTLP server
curl -X POST \
  http://localhost:4317/v1/traces \
  -H 'Content-Type: application/json' \
  -d '{"resource": {"attributes": {"service.name": "my-service"}}, "traces": [{"spans": [{"attributes": {"http.request.method": "GET"}}]}]}'
```

## Operational Runbook / Failure Modes
### Failure Modes

* **OTLP server failure**: If the OTLP server fails, the tracer provider will not be able to send data to the server.
* **Tracer provider failure**: If the tracer provider fails, the tracer will not be able to collect data.
* **Instrumentation failure**: If the instrumentation fails, the tracer will not be able to collect data.

### Runbook

1. **OTLP server failure**:
	* Check the OTLP server logs for errors.
	* Restart the OTLP server if necessary.
2. **Tracer provider failure**:
	* Check the tracer provider logs for errors.
	* Restart the tracer provider if necessary.
3. **Instrumentation failure**:
	* Check the instrumentation logs for errors.
	* Restart the instrumentation if necessary.

### Monitoring

* **OTLP server monitoring**: Monitor the OTLP server for errors and performance issues.
* **Tracer provider monitoring**: Monitor the tracer provider for errors and performance issues.
* **Instrumentation monitoring**: Monitor the instrumentation for errors and performance issues.

### Logging

* **OTLP server logging**: Log OTLP server errors and performance issues.
* **Tracer provider logging**: Log tracer provider errors and performance issues.
* **Instrumentation logging**: Log instrumentation errors and performance issues.
