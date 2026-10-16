# 38+ FOSS Java Enterprise Toolchain Matrix & Invocation Recipes

The `java-master` platform integrates 38+ canonical open-source tools across 6 operational engineering categories.

---

## 1. Static Analysis & Linters

| Tool | Category | Installation Recipe | Invocation Command |
| :--- | :--- | :--- | :--- |
| **Error Prone** | AST Bug Catcher | Add `com.google.errorprone:error_prone_core:2.31.0` to compiler plugin | `./mvnw compile -Derrorprone` |
| **NullAway** | Nullability Enforcement | Add `com.uber.nullaway:nullaway:0.11.1` to annotationProcessorPaths | `./mvnw compile -Xep:NullAway:ERROR -XepOpt:NullAway:AnnotatedPackages=com.master` |
| **SpotBugs** | AST & Bytecode Analyzer | Add `com.github.spotbugs:spotbugs-maven-plugin:4.8.6.2` | `./mvnw spotbugs:check` |
| **PMD** | Anti-Pattern Detector | Add `org.apache.maven.plugins:maven-pmd-plugin:3.24.0` | `./mvnw pmd:check` |
| **Checkstyle** | Code Style Enforcement | Add `org.apache.maven.plugins:maven-checkstyle-plugin:3.4.0` | `./mvnw checkstyle:check` |
| **SonarScanner CLI** | Technical Debt Scanner | `curl -sL https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli.zip` | `sonar-scanner -Dsonar.projectKey=java-master` |

---

## 2. Architecture & Structural Governance

| Tool | Category | Installation Recipe | Invocation Command |
| :--- | :--- | :--- | :--- |
| **ArchUnit** | Architectural Unit Tests | Add `com.tngtech.archunit:archunit-junit5:1.3.0` | `./mvnw test -Dtest=ArchitectureTest` |
| **JDepend** | Metric & Coupling Quality | Add `org.codehaus.mojo:jdepend-maven-plugin:2.0` | `./mvnw jdepend:generate` |

---

## 3. Reliability, Fuzzing & Mutation Testing

| Tool | Category | Installation Recipe | Invocation Command |
| :--- | :--- | :--- | :--- |
| **PIT (Pitest)** | Mutation Testing | Add `org.pitest:pitest-maven:1.16.1` | `./mvnw pitest:mutationCoverage -DmutationThreshold=80` |
| **Jazzer** | JVM Coverage Fuzzing | `curl -sL https://github.com/CodeIntelligenceTesting/jazzer/releases/download/v0.22.1/jazzer-linux.tar.gz` | `jazzer --cp=target/classes:target/test-classes --target_class=com.master.fuzz.ParserFuzzer` |
| **jqwik** | Property-Based Testing | Add `net.jqwik:jqwik:1.9.0` | `./mvnw test -Dtest=*PropertyTest` |
| **JUnit 5** | Jupiter Test Engine | Add `org.junit.jupiter:junit-jupiter:5.11.0` | `./mvnw test` |
| **AssertJ** | Fluent Assertions | Add `org.assertj:assertj-core:3.26.3` | `./mvnw test` |
| **Awaitility** | Async Testing DSL | Add `org.awaitility:awaitility:4.2.2` | `./mvnw test` |
| **Mockito** | Mocking Framework | Add `org.mockito:mockito-junit-jupiter:5.13.0` | `./mvnw test` |
| **Testcontainers** | Containerized Test Harness | Add `org.testcontainers:junit-jupiter:1.20.1` | `./mvnw test -Dtest=*IntegrationTest` |
| **WireMock** | HTTP Mock Server | Add `org.wiremock:wiremock:3.9.1` | `./mvnw test` |

---

## 4. Security & Supply Chain (SecSDLC)

| Tool | Category | Installation Recipe | Invocation Command |
| :--- | :--- | :--- | :--- |
| **FindSecBugs** | SpotBugs Security Plugin | Add `com.h3xstream.findsecbugs:findsecbugs-plugin:1.13.0` | `./mvnw spotbugs:check` |
| **Dependency-Check** | SCA Known CVE Scanner | Add `org.owasp:dependency-check-maven:10.0.3` | `./mvnw org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7` |
| **CycloneDX** | Standardized SBOM | Add `org.cyclonedx:cyclonedx-maven-plugin:2.8.1` | `./mvnw cyclonedx:makeAggregateBom` |
| **Trivy** | Container & FS Scanner | `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \| sh` | `trivy fs --severity HIGH,CRITICAL .` |
| **Semgrep** | Fast Security SAST | `pip install semgrep` | `semgrep scan --config p/java` |
| **Gitleaks** | Secret & Key Scanner | `curl -sL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz` | `gitleaks detect --source=. --verbose` |

---

## 5. Performance, Profiling & Memory Analysis

| Tool | Category | Installation Recipe | Invocation Command |
| :--- | :--- | :--- | :--- |
| **JMH** | Microbenchmark Harness | Add `org.openjdk.jmh:jmh-core:1.37` | `java -jar target/benchmarks.jar -wi 3 -i 5 -f 1` |
| **JOL** | Object Memory Layout | Add `org.openjdk.jol:jol-core:0.17` | `java -cp target/classes:jol-core.jar org.openjdk.jol.info.ClassLayout com.master.domain.OrderAggregate` |
| **async-profiler** | Low-Overhead Sampling | `curl -sL https://github.com/async-profiler/async-profiler/releases/download/v3.0/async-profiler-3.0-linux-x64.tar.gz` | `asprof -d 10 -e cpu -f profile.html <PID>` |
| **JFR / JMC** | Flight Recorder Events | Built-in OpenJDK | `java -XX:StartFlightRecording=duration=60s,filename=rec.jfr -jar app.jar` |
| **GCViewer** | GC Log Visualizer | `curl -sL https://github.com/chewiebug/GCViewer/releases/download/1.36/gcviewer-1.36.jar` | `java -jar gcviewer.jar gc.log output.png` |
| **javap** | Bytecode Disassembler | Built-in OpenJDK | `javap -c -p -v target/classes/com/master/concurrency/VirtualDispatcher.class` |

---

## 6. Formatters, Build Tools & Bytecode

| Tool | Category | Installation Recipe | Invocation Command |
| :--- | :--- | :--- | :--- |
| **Spotless** | Deterministic Formatter | Add `com.diffplug.spotless:spotless-maven-plugin:2.43.0` | `./mvnw spotless:apply` |
| **Google Java Format**| Pure Google Style | `curl -sL https://github.com/google/google-java-format/releases/download/v1.23.0/google-java-format-1.23.0-all-deps.jar` | `java -jar google-java-format.jar --replace src/**/*.java` |
| **Maven Wrapper** | Pinned Hermetic Maven | `mvn wrapper:wrapper` | `./mvnw clean verify` |
| **Gradle Wrapper**| Pinned Hermetic Gradle| `gradle wrapper` | `./gradlew check` |
| **Byte Buddy** | Bytecode Instrumentation | Add `net.bytebuddy:byte-buddy:1.15.1` | `./mvnw test` |
| **ASM** | Low-Level Bytecode ASM | Add `org.ow2.asm:asm:9.7` | `./mvnw test` |
| **Caffeine** | High-Performance Cache | Add `com.github.ben-manes.caffeine:caffeine:3.1.8` | `./mvnw test` |
| **MapStruct** | Compile-Time Mapping | Add `org.mapstruct:mapstruct:1.6.0` | `./mvnw compile` |
| **Micrometer** | Application Metrics | Add `io.micrometer:micrometer-core:1.13.4` | `./mvnw test` |
