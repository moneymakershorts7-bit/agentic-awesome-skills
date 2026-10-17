# Exhaustive 38+ FOSS C# / .NET Toolchain Matrix

## 1. Compilers & Static Analysis (Roslyn Analyzers)
| Tool | Purpose | Invocation Recipe | Installation Recipe |
| :--- | :--- | :--- | :--- |
| **dotnet build / Roslyn** | Compiler-grade zero-warning gate | `dotnet build /warnaserror` | Built into .NET SDK |
| **Microsoft.CodeAnalysis.NetAnalyzers** | Official Microsoft API design & quality rules | `dotnet build /p:EnableNETAnalyzers=true` | Built into .NET SDK (`<AnalysisLevel>latest-all</AnalysisLevel>`) |
| **SonarAnalyzer.CSharp** | Deep static analysis for bugs & code smells | `dotnet build /p:SonarQube=true` | `dotnet add package SonarAnalyzer.CSharp` |
| **Meziantou.Analyzer** | Enterprise C# code quality & performance rules | `dotnet build` | `dotnet add package Meziantou.Analyzer` |
| **StyleCop.Analyzers** | Consistent style, naming & ordering | `dotnet build` | `dotnet add package StyleCop.Analyzers` |
| **Roslynator.Analyzers** | 500+ analyzers & refactorings | `roslynator analyze` | `dotnet tool install -g roslynator.dotnet.cli` |
| **Sharpen** | Modern C# language idiom suggestions | `sharpen run` | `dotnet tool install -g sharpen` |

## 2. Architecture & Structural Governance
| Tool | Purpose | Invocation Recipe | Installation Recipe |
| :--- | :--- | :--- | :--- |
| **ArchUnitNET** | C# architecture & layer dependency tests | `dotnet test --filter ArchUnitTests` | `dotnet add package ArchUnitNET.xUnit` |
| **NetArchTest.Rules** | Fluent architecture boundary tests | `dotnet test --filter NetArchTests` | `dotnet add package NetArchTest.Rules` |
| **PlantUml.Builder** | Programmatic C4 / UML diagram generation | `dotnet run --project DiagramGenerator` | `dotnet add package PlantUml.Builder` |

## 3. Mutation, Unit & Property Testing
| Tool | Purpose | Invocation Recipe | Installation Recipe |
| :--- | :--- | :--- | :--- |
| **Stryker.NET** | Mutation testing system for C# | `dotnet stryker --break-at 80` | `dotnet tool install -g dotnet-stryker` |
| **xUnit.net** | Industry standard unit test runner | `dotnet test` | `dotnet add package xunit` |
| **NUnit** | Parameterized test runner | `dotnet test` | `dotnet add package NUnit` |
| **FluentAssertions** | Expressive fluent test assertions | `dotnet test` | `dotnet add package FluentAssertions` |
| **Bogus** | Realistic fake data generator | `dotnet test` | `dotnet add package Bogus` |
| **Verify** | Snapshot & golden-master verification | `dotnet test` | `dotnet add package Verify.Xunit` |
| **Testcontainers for .NET** | Isolated Docker containers for testing | `dotnet test --filter IntegrationTests` | `dotnet add package Testcontainers` |
| **Moq** | Interface mocking framework | `dotnet test` | `dotnet add package Moq` |
| **NSubstitute** | Concise mocking alternative | `dotnet test` | `dotnet add package NSubstitute` |
| **FsCheck.Xunit** | QuickCheck random property-based testing | `dotnet test` | `dotnet add package FsCheck.Xunit` |
| **coverlet.collector** | Cross-platform code coverage collector | `dotnet test --collect:"XPlat Code Coverage"` | `dotnet add package coverlet.collector` |

## 4. Performance, Profiling & Benchmarking
| Tool | Purpose | Invocation Recipe | Installation Recipe |
| :--- | :--- | :--- | :--- |
| **BenchmarkDotNet** | Gold standard microbenchmark & memory diagnoser | `dotnet run -c Release` | `dotnet add package BenchmarkDotNet` |
| **dotnet-trace** | Sampling performance profiler | `dotnet-trace collect -p <PID>` | `dotnet tool install -g dotnet-trace` |
| **dotnet-dump** | Post-mortem heap crash dump analyzer | `dotnet-dump collect -p <PID>` | `dotnet tool install -g dotnet-dump` |
| **dotnet-gcdump** | Lightweight GC heap dump capture | `dotnet-gcdump collect -p <PID>` | `dotnet tool install -g dotnet-gcdump` |
| **dotnet-counters** | Real-time runtime performance metrics | `dotnet-counters monitor -p <PID>` | `dotnet tool install -g dotnet-counters` |
| **dotnet-stack** | Thread stack trace capture | `dotnet-stack report -p <PID>` | `dotnet tool install -g dotnet-stack` |

## 5. Security, Supply Chain & SecSDLC
| Tool | Purpose | Invocation Recipe | Installation Recipe |
| :--- | :--- | :--- | :--- |
| **SecurityCodeScan.VS2019** | Vulnerability pattern analyzer for C# | `dotnet build` | `dotnet add package SecurityCodeScan.VS2019` |
| **DevSkim** | Microsoft IDE & CI security pattern analyzer | `devskim analyze /src` | `dotnet tool install -g Microsoft.CST.DevSkim.CLI` |
| **dotnet list package --vulnerable** | Official NuGet vulnerability scanner | `dotnet list package --vulnerable --include-transitive` | Built into .NET SDK |
| **CycloneDX .NET CLI** | Standardized CycloneDX SBOM generation | `dotnet CycloneDX -o ./sbom` | `dotnet tool install -g CycloneDX` |
| **Trivy** | Container vulnerability scanner | `trivy image csharp-master:latest` | `apt-get install trivy` |
| **Gitleaks** | Secret & credential detector | `gitleaks detect --source .` | `go install github.com/zricethezav/gitleaks/v8@latest` |
| **Semgrep** | Fast AST static security scanner | `semgrep scan --config p/csharp` | `pip install semgrep` |

## 6. Formatting, Resilience & Utilities
| Tool | Purpose | Invocation Recipe | Installation Recipe |
| :--- | :--- | :--- | :--- |
| **csharpier** | Deterministic opinionated C# formatter | `dotnet csharpier --check .` | `dotnet tool install -g csharpier` |
| **dotnet format** | Built-in .NET SDK formatter and style fixer | `dotnet format --verify-no-changes` | Built into .NET SDK |
| **Polly** | Resilience and transient fault handling | `dotnet test` | `dotnet add package Polly` |
| **OneOf** | Discriminated union result types | `dotnet test` | `dotnet add package OneOf` |
| **ErrorOr** | Type-safe railway result pattern | `dotnet test` | `dotnet add package ErrorOr` |
| **FluentValidation** | Fluent domain model validation | `dotnet test` | `dotnet add package FluentValidation` |
