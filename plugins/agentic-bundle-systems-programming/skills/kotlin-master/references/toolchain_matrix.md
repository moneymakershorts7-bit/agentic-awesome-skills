# Exhaustive 38+ FOSS Kotlin Enterprise Toolchain Matrix

## 1. Compilers, Linters & Formatters
1. **kotlinc**: Kotlin 2.x K2 compiler with unified FIR frontend and JVM/Native backends.
2. **detekt**: Static code analysis for Kotlin with configurable AST complexity and smell rules.
3. **ktlint**: Anti-bikeshedding Kotlin linter and automatic code formatter.
4. **spotless**: Formatting enforcement Gradle plugin supporting ktlint and custom formatters.
5. **kotlin-compiler-embeddable**: Direct AST and compiler plugin embedding interface.
6. **dokka**: Official API documentation engine for Kotlin multiplatform libraries.

## 2. Build Systems, Dependency Management & Monorepo Tooling
7. **gradle**: Gradle 8.x with Kotlin DSL (`build.gradle.kts`) for type-safe build scripts.
8. **gradle-dependency-verification**: Cryptographic checksum verification (`gradle/verification-metadata.xml`).
9. **dependabot**: Automated dependency update scanner configured via `.github/dependabot.yml`.
10. **renovate**: Multi-platform automated dependency updates.
11. **gradle-doctor**: Build performance, daemon health, and cache scanner.
12. **develocity**: Gradle Enterprise build cache and build scan utility.

## 3. Architecture & Structural Governance
13. **konsist**: Programmatic architectural testing tool asserting layer and package boundaries.
14. **archunit**: Java and Kotlin architecture test framework for bytecode inspection.
15. **diktat**: Strict coding standard analysis engine for Kotlin.
16. **qodana-kotlin**: JetBrains static analysis linter for CI/CD pipelines.

## 4. Testing, Mutation & Concurrency Diagnostics
17. **kotest**: Modern multiplatform testing framework with Property-based testing.
18. **mockk**: Mocking library built specifically for idiomatic Kotlin (coroutines, objects, extensions).
19. **kotlinx-coroutines-test**: Virtual time manipulation and test dispatchers via `runTest`.
20. **pitest**: Mutation testing framework with Kotlin plugin achieving MSI >= 80%.
21. **turbine**: Lightweight testing library for predictable Kotlin Flow assertion.
22. **faker-kotlin**: Realistic mock data generator for domain entities.

## 5. Server-Side, Systems & Runtime Engines
23. **ktor**: Asynchronous microservices and HTTP client framework in pure Kotlin.
24. **spring-boot-starter-webflux**: Reactive Spring Boot with coroutine extensions.
25. **kotlinx-serialization**: Compiler-plugin driven JSON/ProtoBuf serialization without reflection.
26. **exposed**: Kotlin SQL framework with type-safe DSL and DAO API.
27. **jooq**: Type-safe SQL query generator with Kotlin extensions.
28. **arrow-kt**: Functional companion library: typed errors, Either, optics, resilience.
29. **kotlinx-benchmark**: Microbenchmarking library for Kotlin Multiplatform.
30. **graalvm-native-image**: Ahead-of-time native machine code compiler for JVM.
31. **project-loom**: JVM 21+ Virtual Threads lightweight concurrency runtime.
32. **kotlinx-datetime**: Multiplatform Kotlin date and time library.

## 6. Security, Supply Chain & SecSDLC
33. **spotbugs**: Static security bug detector with FindSecBugs plugin.
34. **findsecbugs**: Security vulnerability detector for JVM byte code.
35. **trivy**: Container and filesystem vulnerability scanner.
36. **semgrep**: Semantic AST code search and security rule engine.
37. **owasp-dependency-check**: Vulnerability scanner for project dependencies.
38. **snyk-cli**: Developer-first dependency and container security scanner.
39. **cosign**: Container signing and cryptographic verification utility.
40. **cyclonedx-gradle**: Software Bill of Materials (SBOM) generator for Gradle.
41. **bouncycastle**: Java cryptography provider for post-quantum & modern ciphers.
