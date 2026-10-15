# OpenTelemetry SDK Instrumentation Recipes (Node.js, Python, Go)
## Architecture Overview
OpenTelemetry is an open-source observability framework that provides a unified standard for instrumenting, generating, and propagating telemetry data (metrics, logs, and traces) no matter where they come from. This document provides production-ready reference recipes for automatic and manual tracing & metrics instrumentation in Node.js, Python, and Go.

## Concrete Configs / Code Recipes
### Node.js Recipes
#### Automatic Tracing
```javascript
// Import the OpenTelemetry SDK
const { NodeTracerProvider } = require('@opentelemetry/sdk-trace-node');
const { registerInstrumentations } = require('@opentelemetry/auto-instrumentation-node');

// Create a NodeTracerProvider
const provider = new NodeTracerProvider();

// Register instrumentations
registerInstrumentations({
  instrumentations: [
    {
      // Enable automatic instrumentation for HTTP requests
      '@opentelemetry/auto-instrumentation-node': {
        filters: {
          // Exclude certain modules from instrumentation
          exclude: ['module1', 'module2'],
        },
      },
    },
  ],
});

// Start the tracer provider
provider.register();
```

#### Manual Tracing
```javascript
// Import the OpenTelemetry SDK
const { TracerProvider } = require('@opentelemetry/sdk-trace-node');
const { Tracer } = require('@opentelemetry/sdk-trace-base');

// Create a TracerProvider
const provider = new TracerProvider();

// Create a Tracer
const tracer = new Tracer('my-tracer', provider);

// Create a span
const span = tracer.startSpan('my-span');

// Set span attributes
span.setAttribute('key', 'value');

// End the span
span.end();
```

#### Metrics
```javascript
// Import the OpenTelemetry SDK
const { MeterProvider } = require('@opentelemetry/sdk-metrics-node');

// Create a MeterProvider
const provider = new MeterProvider();

// Create a Meter
const meter = provider.get Meter('my-meter');

// Create a counter
const counter = meter.createCounter('my-counter');

// Increment the counter
counter.add(1);
```

### Python Recipes
#### Automatic Tracing
```python
# Import the OpenTelemetry SDK
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export import ConsoleSpanExporter

# Create a TracerProvider
provider = TracerProvider()

# Create a SimpleSpanProcessor
processor = SimpleSpanProcessor(ConsoleSpanExporter())

# Add the processor to the provider
provider.add_span_processor(processor)

# Create a tracer
tracer = provider.get_tracer(__name__)

# Create a span
with tracer.start_span('my-span') as span:
    # Set span attributes
    span.set_attribute('key', 'value')
```

#### Manual Tracing
```python
# Import the OpenTelemetry SDK
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace import Tracer

# Create a TracerProvider
provider = TracerProvider()

# Create a Tracer
tracer = Tracer('my-tracer', provider)

# Create a span
span = tracer.start_span('my-span')

# Set span attributes
span.set_attribute('key', 'value')

# End the span
span.end()
```

#### Metrics
```python
# Import the OpenTelemetry SDK
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics import Counter

# Create a MeterProvider
provider = MeterProvider()

# Create a Meter
meter = provider.get_meter('my-meter')

# Create a counter
counter = meter.create_counter('my-counter')

# Increment the counter
counter.add(1)
```

### Go Recipes
#### Automatic Tracing
```go
// Import the OpenTelemetry SDK
package main

import (
	"context"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func main() {
	// Create a TracerProvider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(
			otlptrace.NewClient(
				otlptrace.WithEndpoint("http://localhost:4318"),
			),
		),
	)

	// Set the global tracer
	otel.SetTracerProvider(tp)

	// Create a tracer
	tracer := tp.Tracer("my-tracer")

	// Create a span
	ctx := context.Background()
	_, span := tracer.Start(ctx, "my-span")

	// Set span attributes
	span.SetAttributes(
		trace.WithAttributes(
			trace.StringAttribute("key", "value"),
		),
	)

	// End the span
	span.End()
}
```

#### Manual Tracing
```go
// Import the OpenTelemetry SDK
package main

import (
	"context"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func main() {
	// Create a TracerProvider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(
			otlptrace.NewClient(
				otlptrace.WithEndpoint("http://localhost:4318"),
			),
		),
	)

	// Set the global tracer
	otel.SetTracerProvider(tp)

	// Create a tracer
	tracer := tp.Tracer("my-tracer")

	// Create a span
	ctx := context.Background()
	span := tracer.Start(ctx, "my-span")

	// Set span attributes
	span.SetAttributes(
		trace.WithAttributes(
			trace.StringAttribute("key", "value"),
		),
	)

	// End the span
	span.End()
}
```

#### Metrics
```go
// Import the OpenTelemetry SDK
package main

import (
	"context"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/global"
)

func main() {
	// Create a MeterProvider
	mp := metric.NewMeterProvider(
		metric.WithResource(resource.NewWithAttributes(
			"com.example",
			attribute.String("service.name", "my-service"),
		)),
	)

	// Set the global meter provider
	global.SetMeterProvider(mp)

	// Create a meter
	meter := mp.GetMeter("my-meter")

	// Create a counter
	counter := meter.NewInt64Counter("my-counter")

	// Increment the counter
	counter.Add(ctx, 1, nil)
}
```

## Operational Runbook / Failure Modes
### Node.js
*   **TracerProvider not registered**: Make sure to call `provider.register()` to start the tracer provider.
*   **Instrumentations not registered**: Ensure that you have registered the instrumentations using `registerInstrumentations()`.
*   **OTLP endpoint not configured**: Verify that the OTLP endpoint is correctly configured in the `provider` object.

### Python
*   **TracerProvider not created**: Ensure that you have created a `TracerProvider` instance using `TracerProvider()`.
*   **Span processor not added**: Make sure to add a span processor to the provider using `provider.add_span_processor()`.
*   **OTLP endpoint not configured**: Verify that the OTLP endpoint is correctly configured in the `provider` object.

### Go
*   **TracerProvider not created**: Ensure that you have created a `TracerProvider` instance using `sdktrace.NewTracerProvider()`.
*   **OTLP endpoint not configured**: Verify that the OTLP endpoint is correctly configured in the `provider` object.
*   **MeterProvider not created**: Make sure to create a `MeterProvider` instance using `metric.NewMeterProvider()`.
*   **OTLP endpoint not configured**: Verify that the OTLP endpoint is correctly configured in the `provider` object.

## Configuration Blocks
### Node.js
```yml
// .env
OTEL_SERVICE_NAME=my-service
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

### Python
```yml
# otelcol.yaml
exporters:
  - name: otlp
    config:
      endpoint: "http://localhost:4318"
```

### Go
```go
// main.go
package main

import (
	"context"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func main() {
	// Create a TracerProvider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(
			otlptrace.NewClient(
				otlptrace.WithEndpoint("http://localhost:4318"),
			),
		),
	)

	// Set the global tracer
	otel.SetTracerProvider(tp)
}
```

## Context Propagation
OpenTelemetry provides built-in support for context propagation using the W3C TraceContext specification. To enable context propagation, you need to add the `otel.contextpropagation` package to your dependencies and create a `ContextPropagator` instance.

### Node.js
```javascript
// Import the OpenTelemetry SDK
const { ContextPropagator } = require('@opentelemetry/context-propagation');

// Create a ContextPropagator
const propagator = new ContextPropagator();

// Set the propagator
otel.setPropagator(propagator);
```

### Python
```python
# Import the OpenTelemetry SDK
from opentelemetry.context.propagation import ContextPropagator

# Create a ContextPropagator
propagator = ContextPropagator()

# Set the propagator
otel.set_propagator(propagator)
```

### Go
```go
// Import the OpenTelemetry SDK
package main

import (
	"context"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

func main() {
	// Create a ContextPropagator
	propagator := propagation.NewContextPropagator()

	// Set the propagator
	otel.SetPropagator(propagator)
}
```

## Custom Spans
To create custom spans, you can use the `Tracer` API to create a new span and set its attributes.

### Node.js
```javascript
// Import the OpenTelemetry SDK
const { Tracer } = require('@opentelemetry/sdk-trace-base');

// Create a Tracer
const tracer = new Tracer('my-tracer');

// Create a custom span
const span = tracer.startSpan('my-span');

// Set span attributes
span.setAttribute('key', 'value');

// End the span
span.end();
```

### Python
```python
# Import the OpenTelemetry SDK
from opentelemetry.sdk.trace import Tracer

# Create a Tracer
tracer = Tracer('my-tracer')

# Create a custom span
with tracer.start_span('my-span') as span:
    # Set span attributes
    span.set_attribute('key', 'value')
```

### Go
```go
// Import the OpenTelemetry SDK
package main

import (
	"context"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

func main() {
	// Create a Tracer
	tracer := otel.GetTracerProvider().Tracer("my-tracer")

	// Create a custom span
	ctx := context.Background()
	span := tracer.Start(ctx, "my-span")

	// Set span attributes
	span.SetAttributes(
		trace.WithAttributes(
			trace.StringAttribute("key", "value"),
		),
	)

	// End the span
	span.End()
}
```

## Counters and Histograms
To create counters and histograms, you can use the `Meter` API to create a new counter or histogram and set its values.

### Node.js
```javascript
// Import the OpenTelemetry SDK
const { Meter } = require('@opentelemetry/sdk-metrics-node');

// Create a Meter
const meter = new Meter('my-meter');

// Create a counter
const counter = meter.createCounter('my-counter');

// Increment the counter
counter.add(1);
```

### Python
```python
# Import the OpenTelemetry SDK
from opentelemetry.sdk.metrics import Meter

# Create a Meter
meter = Meter('my-meter')

# Create a counter
counter = meter.create_counter('my-counter')

# Increment the counter
counter.add(1)
```

### Go
```go
// Import the OpenTelemetry SDK
package main

import (
	"context"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/global"
)

func main() {
	// Create a MeterProvider
	mp := metric.NewMeterProvider(
		metric.WithResource(resource.NewWithAttributes(
			"com.example",
			attribute.String("service.name", "my-service"),
		)),
	)

	// Set the global meter provider
	global.SetMeterProvider(mp)

	// Create a meter
	meter := mp.GetMeter("my-meter")

	// Create a counter
	counter := meter.NewInt64Counter("my-counter")

	// Increment the counter
	counter.Add(context.Background(), 1, nil)
}
```

## Standard OTLP gRPC and HTTP Ports
OpenTelemetry uses the standard OTLP gRPC port
