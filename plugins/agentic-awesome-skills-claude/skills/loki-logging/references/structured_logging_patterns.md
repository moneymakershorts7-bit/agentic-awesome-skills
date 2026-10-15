# Structured JSON Logging Patterns (Pino, Winston, structlog)

## Architecture Overview

### Standard Schema Conventions
```json
{
  "timestamp": "2024-06-17T08:55:00.123Z",
  "level": "info",
  "message": "User logged in",
  "service": "auth-service",
  "trace_id": "abc123def456",
  "span_id": "span789",
  "fields": {
    "user_id": "user123",
    "ip": "192.168.0.1"
  },
  "error": {
    "type": "DatabaseConnectionError",
    "message": "Connection refused",
    "stack": "..."
  }
}
```

### Field Standards
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timestamp` | ISO8601 | Yes | RFC3339 with milliseconds |
| `level` | string | Yes | trace, debug, info, warn, error, fatal |
| `message` | string | Yes | Human-readable summary |
| `service` | string | Yes | Service name (deployment identifier) |
| `trace_id` | string | No | W3C traceparent trace-id |
| `span_id` | string | No | W3C traceparent span-id |
| `fields` | object | No | Structured context key-values |
| `error` | object | No | Structured error with type, message, stack |

---

## Concrete Configs / Code Recipes

### Node.js Pino (v9.x) — Production Configuration

#### Core Logger with Sonic-Boom & Fast Extreme Mode
```javascript
// logger.js
import pino from 'pino';
import sonicBoom from 'sonic-boom';

const destination = sonicBoom({
  dest: '/var/log/app/app.log',
  minLength: 4096,
  sync: false,
  mkdir: true,
  maxSize: '100m',
  maxFiles: 10
});

const redactPaths = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.body.password',
  'req.body.token',
  'req.body.secret',
  'res.headers["set-cookie"]',
  '*.password',
  '*.token',
  '*.secret',
  '*.apiKey',
  '*.authorization'
];

export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  base: {
    service: process.env.SERVICE_NAME || 'unknown-service',
    hostname: process.env.HOSTNAME,
    pid: process.pid
  },
  timestamp: () => `,"timestamp":"${new Date().toISOString()}"`,
  formatters: {
    level: (label) => ({ level: label }),
    log: (obj) => {
      if (obj.err) {
        obj.error = {
          type: obj.err.name,
          message: obj.err.message,
          stack: obj.err.stack
        };
        delete obj.err;
      }
      return obj;
    }
  },
  redact: {
    paths: redactPaths,
    censor: '[REDACTED]'
  },
  serializers: {
    req: (req) => ({
      method: req.method,
      url: req.url,
      headers: req.headers,
      remoteAddress: req.ip,
      remotePort: req.socket?.remotePort
    }),
    res: (res) => ({
      statusCode: res.statusCode,
      headers: res.getHeaders()
    }),
    err: pino.stdSerializers.err
  },
  hooks: {
    logMethod: (args, method) => {
      if (args[0] instanceof Error) {
        const err = args.shift();
        method.call(this, { err }, ...args);
      } else {
        method.apply(this, args);
      }
    }
  }
}, destination);

// Extreme performance mode for high-throughput services
export const extremeLogger = pino({
  ...logger.options,
  level: 'warn',
  formatters: {
    level: (label) => ({ level: label })
  }
}, sonicBoom({ dest: '/var/log/app/extreme.log', minLength: 65536 }));
```

#### Child Loggers & Correlation ID Binding
```javascript
// middleware/request-context.js
import { logger } from './logger.js';
import { v4 as uuidv4 } from 'uuid';

export function requestContext(req, res, next) {
  const traceId = req.headers['x-request-id'] || req.headers['traceparent']?.split('-')[1] || uuidv4();
  const spanId = req.headers['traceparent']?.split('-')[2]?.split('-')[0] || uuidv4().slice(0, 16);
  
  req.log = logger.child({
    trace_id: traceId,
    span_id: spanId,
    req: req,
    res: res
  });
  
  res.setHeader('x-request-id', traceId);
  res.setHeader('traceparent', `00-${traceId}-${spanId}-01`);
  
  req.log.info({ event: 'request_start' }, `${req.method} ${req.url}`);
  
  const start = process.hrtime.bigint();
  res.on('finish', () => {
    const durationNs = Number(process.hrtime.bigint() - start);
    req.log.info({
      event: 'request_complete',
      duration_ms: durationNs / 1e6,
      status_code: res.statusCode
    }, `${req.method} ${req.url} completed`);
  });
  
  next();
}

// Service-layer child logger
export function createServiceLogger(serviceName, context = {}) {
  return logger.child({ service: serviceName, ...context });
}
```

#### HTTP Request Logging (Pino-HTTP)
```javascript
// http-logger.js
import pinoHttp from 'pino-http';
import { logger } from './logger.js';

export const httpLogger = pinoHttp({
  logger,
  genReqId: (req) => req.headers['x-request-id'] || req.id,
  customProps: (req, res) => ({
    trace_id: req.id,
    service: process.env.SERVICE_NAME
  }),
  customSuccessMessage: (req, res) => `${req.method} ${req.url} - ${res.statusCode}`,
  customErrorMessage: (req, res, err) => `${req.method} ${req.url} - ${res.statusCode} - ${err.message}`,
  redact: logger.options.redact,
  serializers: logger.options.serializers,
  quietReqLogger: true
});
```

#### Pino Transport Configuration (YAML)
```yaml
# pino-transport.yaml
transports:
  - target: 'pino/file'
    level: 'info'
    options:
      destination: '/var/log/app/app.log'
      mkdir: true
      maxSize: '100m'
      maxFiles: 10
  - target: 'pino/file'
    level: 'error'
    options:
      destination: '/var/log/app/error.log'
      mkdir: true
      maxSize: '50m'
      maxFiles: 5
  - target: 'pino-elasticsearch'
    level: 'info'
    options:
      node: 'http://elasticsearch:9200'
      index: 'logs-%{service}-%Y.%m.%d'
      flushBytes: 10000
      consistency: 'one'
  - target: 'pino-loki'
    level: 'info'
    options:
      host: 'http://loki:3100'
      labels: '{service="%{service}",environment="%{NODE_ENV}"}'
      batchWait: 1000
      batchSize: 1000
```

---

### Node.js Winston (v3.x) — Production Configuration

#### Core Logger with Format Pipeline
```javascript
// logger.js
import winston from 'winston';
import 'winston-daily-rotate-file';
import { ElasticsearchTransport } from 'winston-elasticsearch';

const { combine, timestamp, json, errors, printf, metadata } = winston.format;

const logFormat = combine(
  timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
  errors({ stack: true }),
  metadata({ fillExcept: ['message', 'level', 'timestamp', 'service', 'trace_id', 'span_id'] }),
  json()
);

const consoleFormat = combine(
  timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
  errors({ stack: true }),
  printf(({ level, message, timestamp, service, trace_id, span_id, ...meta }) => {
    const base = { timestamp, level, message, service, trace_id, span_id };
    return JSON.stringify({ ...base, ...meta });
  })
);

const transports = [
  new winston.transports.DailyRotateFile({
    filename: '/var/log/app/%DATE%-app.log',
    datePattern: 'YYYY-MM-DD',
    maxSize: '100m',
    maxFiles: '14d',
    format: logFormat,
    zippedArchive: true
  }),
  new winston.transports.DailyRotateFile({
    filename: '/var/log/app/%DATE%-error.log',
    datePattern: 'YYYY-MM-DD',
    maxSize: '50m',
    maxFiles: '30d',
    level: 'error',
    format: logFormat,
    zippedArchive: true
  })
];

if (process.env.NODE_ENV !== 'production') {
  transports.push(new winston.transports.Console({ format: consoleFormat }));
}

if (process.env.ELASTICSEARCH_URL) {
  transports.push(new ElasticsearchTransport({
    level: 'info',
    clientOpts: { node: process.env.ELASTICSEARCH_URL },
    index: `
