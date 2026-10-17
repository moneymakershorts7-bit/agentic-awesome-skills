# 38+ FOSS PHP Enterprise Toolchain Matrix

This document catalogs the 39 canonical Open Source PHP enterprise tools supported, detected, and orchestrated by `php-master`.

---

## 1. Static Analysis & Linters

| Tool | Purpose | Package / Binary | Invocation Recipe | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **PHPStan** | AST static analysis (Level Max/9) | `phpstan/phpstan` | `./vendor/bin/phpstan analyse -l max src` | `composer require --dev phpstan/phpstan` |
| **Psalm** | Static analysis with taint tracking | `vimeo/psalm` | `./vendor/bin/psalm --taint-analysis` | `composer require --dev vimeo/psalm` |
| **Rector** | Automated AST refactoring & upgrades | `rector/rector` | `./vendor/bin/rector process --dry-run` | `composer require --dev rector/rector` |
| **PHP_CodeSniffer** | Token-based PSR-12 code sniffer | `squizlabs/php_codesniffer` | `./vendor/bin/phpcs --standard=PSR12 src` | `composer require --dev squizlabs/php_codesniffer` |
| **PHP-CS-Fixer** | Automated formatting (PER-CS 2.0) | `friendsofphp/php-cs-fixer` | `./vendor/bin/php-cs-fixer fix --dry-run` | `composer require --dev friendsofphp/php-cs-fixer` |
| **PHPMD** | PHP Mess Detector for cyclomatic complexity | `phpmd/phpmd` | `./vendor/bin/phpmd src text cleancode,codesize` | `composer require --dev phpmd/phpmd` |
| **Phan** | AST analyzer for deep type correctness | `phan/phan` | `./vendor/bin/phan` | `composer require --dev phan/phan` |

---

## 2. Architecture & Structural Governance

| Tool | Purpose | Package / Binary | Invocation Recipe | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **Deptrac** | Architectural dependency layer enforcement | `qossmic/deptrac` | `./vendor/bin/deptrac analyse` | `composer require --dev qossmic/deptrac` |
| **phpat** | PHP Architecture Tester in PHPUnit | `carlosas/phpat` | `./vendor/bin/phpunit --testsuite architecture` | `composer require --dev carlosas/phpat` |
| **Arkitect** | Architectural governance rule checker | `phparkitect/arkitect` | `./vendor/bin/arkitect check` | `composer require --dev phparkitect/arkitect` |
| **PhpMetrics** | Code complexity & maintainability metrics | `phpmetrics/phpmetrics` | `./vendor/bin/phpmetrics --report-html=build src` | `composer require --dev phpmetrics/phpmetrics` |
| **phpda** | Dependency analysis and cycle detection | `mamuz/phpda` | `./vendor/bin/phpda analyze` | `composer require --dev mamuz/phpda` |

---

## 3. Mutation, Unit & Property Testing

| Tool | Purpose | Package / Binary | Invocation Recipe | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **Infection PHP** | AST-based mutation testing (MSI >= 80%) | `infection/infection` | `./vendor/bin/infection --min-msi=80` | `composer require --dev infection/infection` |
| **Pest PHP** | Elegant, expressive testing framework | `pestphp/pest` | `./vendor/bin/pest` | `composer require --dev pestphp/pest` |
| **PHPUnit 11** | Canonical enterprise unit test runner | `phpunit/phpunit` | `./vendor/bin/phpunit` | `composer require --dev phpunit/phpunit` |
| **Mockery** | Expressive mock object framework | `mockery/mockery` | (Used in PHPUnit / Pest tests) | `composer require --dev mockery/mockery` |
| **Eris** | Generative property-based testing | `giorgiosironi/eris` | (Used in PHPUnit tests) | `composer require --dev giorgiosironi/eris` |
| **FakerPHP** | Realistic test data generator | `fakerphp/faker` | (Used in tests) | `composer require --dev fakerphp/faker` |
| **ParaTest** | Parallel test execution for PHPUnit | `brianium/paratest` | `./vendor/bin/paratest -p 4` | `composer require --dev brianium/paratest` |
| **Kahlan** | Unit & BDD test runner with stubs | `kahlan/kahlan` | `./vendor/bin/kahlan` | `composer require --dev kahlan/kahlan` |

---

## 4. Performance, Profiling & Worker Runtimes

| Tool | Purpose | Package / Binary | Invocation Recipe | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **FrankenPHP** | Caddy-powered Go application server | `frankenphp` | `frankenphp run` | `apt-get install frankenphp` |
| **RoadRunner** | High-performance Go application server | `rr` | `./vendor/bin/rr serve` | `composer require spiral/roadrunner-cli` |
| **Swoole** | Event-driven async coroutine engine | `swoole` extension | `php --ri swoole` | `pecl install swoole` |
| **Blackfire CLI** | Continuous profiling and APM | `blackfire` | `blackfire run php script.php` | `apt install blackfire-agent` |
| **Tideways CLI** | Production APM and profiler | `tideways` | `tideways run php script.php` | `apt install tideways-daemon` |
| **phpbench** | PHP micro-benchmark runner | `phpbench/phpbench` | `./vendor/bin/phpbench run` | `composer require --dev phpbench/phpbench` |
| **SPX** | In-engine zero-config PHP profiler | `spx` extension | `php -d spx.http_enabled=1 ...` | Build from source |

---

## 5. Security, Supply Chain & SecSDLC

| Tool | Purpose | Package / Binary | Invocation Recipe | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **composer audit** | Native vulnerability advisory scanner | `composer` | `composer audit --format=table` | Built-in to Composer |
| **local-security-checker** | Standalone dependency scanner | `local-php-security-checker` | `local-php-security-checker` | Download binary from GitHub |
| **Roave/SecurityAdvisories** | Prevents installation of CVEs | `roave/security-advisories` | (Enforced during `composer install`) | `composer require roave/security-advisories:dev-latest` |
| **CycloneDX Composer** | Standardized CycloneDX SBOM generation | `cyclonedx/cyclonedx-php-composer` | `composer make-bom` | `composer require --dev cyclonedx/cyclonedx-php-composer` |
| **Trivy** | Container and dependency scanner | `trivy` | `trivy fs .` | `apt install trivy` |
| **Enlightn** | Static security & performance auditor | `enlightn/enlightn` | `./vendor/bin/enlightn` | `composer require --dev enlightn/enlightn` |

---

## 6. Dependency & Workspace Hygiene

| Tool | Purpose | Package / Binary | Invocation Recipe | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **composer-normalize** | Normalizes composer.json structure | `ergebnis/composer-normalize` | `composer normalize --dry-run` | `composer require --dev ergebnis/composer-normalize` |
| **composer-unused** | Identifies unused dependencies | `composer-unused/composer-unused` | `./vendor/bin/composer-unused` | `composer require --dev composer-unused/composer-unused` |
| **parallel-lint** | Fast syntax checker across PHP versions | `php-parallel-lint/php-parallel-lint` | `./vendor/bin/parallel-lint src tests` | `composer require --dev php-parallel-lint/php-parallel-lint` |
| **PHP Insights** | Quality, complexity, architecture overview | `nunomaduro/phpinsights` | `./vendor/bin/phpinsights` | `composer require --dev nunomaduro/phpinsights` |
| **composer-require-checker** | Verifies declared package dependencies | `maglnet/composer-require-checker` | `./vendor/bin/composer-require-checker check` | `composer require --dev maglnet/composer-require-checker` |
| **CaptainHook** | Git hooks manager for pre-commit checks | `captainhook/captainhook` | `./vendor/bin/captainhook run` | `composer require --dev captainhook/captainhook` |
