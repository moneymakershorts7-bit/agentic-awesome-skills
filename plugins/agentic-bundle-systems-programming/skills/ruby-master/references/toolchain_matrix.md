# 38+ FOSS Ruby Enterprise Toolchain Matrix

The `ruby-master` platform integrates and standardizes 38+ FOSS tools across 6 operational categories:

---

## 1. Compilers, Parsers, Linters & Formatters

| Tool | Type | Purpose | Invocation Recipe |
| :--- | :--- | :--- | :--- |
| **`ruby`** | Runtime | CRuby 3.3+/3.4+ runtime with YJIT | `ruby --yjit -e 'puts RubyVM::YJIT.enabled?'` |
| **`prism`** | Parser | Portable, error-tolerant Ruby parser | `ruby -rprism -e 'Prism.parse_file("app.rb")'` |
| **`rubocop`** | Linter/Formatter | Static code analyzer and style checker | `bundle exec rubocop -a --parallel` |
| **`standard`** | Linter/Formatter | Zero-configuration standard style guide | `bundle exec standardrb --fix` |
| **`syntax_tree`** | Formatter | Fast AST formatter and parser | `bundle exec stree format lib/**/*.rb` |
| **`rubocop-performance`** | Linter | Specialized performance optimization rules | `bundle exec rubocop --require rubocop-performance` |
| **`bundler`** | Package Manager | Dependency manager and lockfile resolver | `bundle install --frozen` |

---

## 2. Static Typing & Interface Verification

| Tool | Type | Purpose | Invocation Recipe |
| :--- | :--- | :--- | :--- |
| **`rbs`** | Language | Standard type signature language for Ruby | `bundle exec rbs validate` |
| **`steep`** | Type Checker | Static type checker powered by RBS | `bundle exec steep check` |
| **`sorbet`** | Type Checker | Stripe's ultra-fast static type checker | `bundle exec srb tc` |
| **`tapioca`** | Generator | Generates RBI files for gems and DSLs | `bundle exec tapioca gems` |
| **`typeprof`** | Analyzer | Generates RBS signatures from plain Ruby | `typeprof app/domain/model.rb` |

---

## 3. Architecture, Structural Governance & Metrics

| Tool | Type | Purpose | Invocation Recipe |
| :--- | :--- | :--- | :--- |
| **`packwerk`** | Architecture | Boundary and privacy governance | `bundle exec packwerk check` |
| **`rubocop-packaging`** | Linter | Enforces clean gem and package layouts | `bundle exec rubocop --require rubocop-packaging` |
| **`flog`** | Metric | ABC metric complexity score per method | `bundle exec flog -a lib/` |
| **`flay`** | Metric | Structural code similarity and duplication | `bundle exec flay -d lib/` |
| **`reek`** | Smell Detector | Code smell analysis for Ruby code | `bundle exec reek lib/` |

---

## 4. Testing, Mutation & Mocking Frameworks

| Tool | Type | Purpose | Invocation Recipe |
| :--- | :--- | :--- | :--- |
| **`rspec`** | Framework | BDD testing framework with rich matchers | `bundle exec rspec --format progress` |
| **`minitest`** | Framework | Fast, lightweight standard unit test runner | `bundle exec ruby -Ilib:test test/test_*.rb` |
| **`mutant`** | Mutation | AST-level mutation testing environment | `bundle exec mutant run --include lib --use rspec 'App*'` |
| **`webmock`** | Mocking | HTTP request stubbing and network blocker | `require "webmock/rspec"; WebMock.disable_net_connect!` |
| **`vcr`** | Recording | Record and replay deterministic HTTP cassettes | `VCR.use_cassette("api") { Net::HTTP.get(...) }` |
| **`factory_bot`** | Fixtures | Rich test domain fixture factory | `FactoryBot.create(:transaction)` |
| **`faker`** | Mock Data | Realistic mock and synthetic test data | `Faker::Internet.email` |
| **`rake`** | Task Runner | Standard Ruby build and task runner | `bundle exec rake default` |

---

## 5. Performance Profiling, Runtimes & Async Concurrency

| Tool | Type | Purpose | Invocation Recipe |
| :--- | :--- | :--- | :--- |
| **`async`** | Concurrency | Composable Fiber-based asynchronous I/O | `Async { |task| task.sleep(0.1) }` |
| **`falcon`** | Web Server | High-performance non-blocking HTTP server | `bundle exec falcon serve -b tcp://127.0.0.1:9292` |
| **`puma`** | Web Server | Concurrent multi-threaded HTTP server | `bundle exec puma -C config/puma.rb` |
| **`stackprof`** | Profiler | Sampling call-stack profiler | `StackProf.run(mode: :cpu, out: "stackprof.dump") { ... }` |
| **`derailed_benchmarks`** | Benchmark | Memory and performance benchmarking for apps | `bundle exec derailed exec perf:mem` |
| **`benchmark-ips`** | Benchmark | Iterations per second benchmarking | `Benchmark.ips { |x| x.report("op") { ... } }` |
| **`memory_profiler`** | Profiler | Detailed memory allocation and retention | `report = MemoryProfiler.report { ... }; report.pretty_print` |

---

## 6. Security, Supply Chain & SecSDLC

| Tool | Type | Purpose | Invocation Recipe |
| :--- | :--- | :--- | :--- |
| **`brakeman`** | SAST | Static analysis security vulnerability scanner | `bundle exec brakeman -z --no-pager` |
| **`bundle-audit`** | SCA | Vulnerability scanner for gem dependencies | `bundle exec bundle audit check --update` |
| **`bundler-leak`** | Leak Detector | Memory leak detector for gem dependencies | `bundle exec bundle leak check` |
| **`trivy`** | Scanner | Filesystem and container vulnerability scanner | `trivy fs --severity HIGH,CRITICAL .` |
| **`semgrep`** | SAST | Semantic security rule engine | `semgrep scan --config=auto .` |
| **`cosign`** | Signing | Container artifact signature verification | `cosign verify --key cosign.pub image:latest` |
