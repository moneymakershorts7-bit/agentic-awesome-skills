# php-master Diagnostic & Troubleshooting Playbook

This playbook provides actionable, step-by-step diagnostic and self-healing procedures for common failure modes encountered in modern enterprise PHP systems.

---

## 1. Runbook: Worker Memory Leaks (FrankenPHP / RoadRunner)

### Symptom
Worker processes gradually consume system memory until they are terminated by the kernel OOM killer or exceed the maximum allowed process memory limit.

### Root Cause Analysis
1. **Doctrine ORM Identity Map Retention**: The Entity Manager keeps all managed entities in its internal identity map until cleared.
2. **Static Property Accumulation**: Static properties or singletons append objects per request.
3. **Circular Reference Cycles**: Two objects pointing to each other prevent reference counts from hitting 0 immediately, accumulating until `gc_collect_cycles()` runs.
4. **Unregistered Event Listeners**: Closure listeners bound to long-lived event dispatchers capture the request scope.

### Diagnostic Recipes
- Run `gc_status()` and `memory_get_usage(true)` at request begin and end.
- Verify that the worker teardown hook executes:
  ```php
  // In worker loop termination / finally block:
  $entityManager->clear();
  $eventDispatcher->reset();
  gc_collect_cycles();
  ```
- Replace static caches with WeakMap or request-scoped services:
  ```php
  // Instead of private static array $cache = [];
  /** @var WeakMap<object, mixed> */
  private WeakMap $cache;
  ```

---

## 2. Runbook: PHPStan Level Max Type Narrowing Issues

### Symptom
PHPStan reports `Parameter #1 expects TypeA, TypeA|null given` or `Cannot call method on mixed`.

### Root Cause Analysis
PHPStan Level Max/9 enforces complete type safety without assuming truthy branches narrow types unless explicitly asserted or guarded.

### Diagnostic Recipes
1. **Use Type-Narrowing Guards**:
   ```php
   // BAD:
   if ($user) { $user->getName(); }

   // GOOD:
   if ($user instanceof User) {
       $user->getName();
   }
   ```
2. **Replace Mixed Arrays with Generics PHPDoc**:
   ```php
   /**
    * @param list<UserRecord> $users
    * @return array<string, UserRecord>
    */
   public function indexById(array $users): array
   ```
3. **Assert Non-Null Boundaries**:
   ```php
   assert($entity !== null, 'Entity must be resolved prior to dispatch.');
   ```
4. **Never Use Unjustified Suppressions**:
   Do NOT use `@phpstan-ignore` without a mandatory inline ticket justification (`ticket: SEC-101`).

---

## 3. Runbook: Infection PHP Mutation Survivors (MSI < 80%)

### Symptom
Infection reports: `Mutation Score Indicator (MSI) is 74.2%, which is below the required 80.0% threshold. 6 mutants escaped.`

### Root Cause Analysis
1. **Untested Boundary Conditions**: Tests check `< 10` but no test checks exact boundary values `10` and `9`.
2. **Missing Negative / Zero Tests**: Mutators flip `+` to `-` or `true` to `false` and tests still pass because assertions are too broad or only test the happy path.
3. **Dummy Assertions**: Tests use `$this->assertTrue(true)` or test methods that don't assert specific state changes.

### Diagnostic Recipes
- Inspect `infection.log` for the exact lines where mutants escaped.
- Example Mutant Escaped:
  ```diff
  - return $amount->cents > 0;
  + return $amount->cents >= 0;
  ```
- **Remediation**: Add explicit test cases for boundary edge cases:
  ```php
  public function testRejectsZeroAmount(): void
  {
      $this->expectException(DomainException::class);
      $processor->process(new Money(0, 'USD'));
  }
  ```

---

## 4. Runbook: Deptrac Architectural Layer Breaches

### Symptom
Deptrac reports: `Domain depends on Infrastructure (src/Domain/Order.php:8 imports Doctrine\ORM\Mapping)`.

### Root Cause Analysis
A class in the inner Domain or Application layer directly imported a class from an external infrastructure adapter or persistence library, violating Hexagonal Architecture.

### Diagnostic Recipes
1. **Extract Domain Port Interface**:
   Move persistence needs behind a clean interface in `src/Domain/<Context>/`:
   ```php
   namespace App\Domain\Order;

   interface OrderRepositoryInterface
   {
       public function save(Order $order): void;
       public function findById(OrderId $id): ?Order;
   }
   ```
2. **Implement in Infrastructure Layer**:
   ```php
   namespace App\Infrastructure\Persistence;

   use App\Domain\Order\Order;
   use App\Domain\Order\OrderRepositoryInterface;

   final class DoctrineOrderRepository implements OrderRepositoryInterface { ... }
   ```
3. **Re-run Deptrac**:
   ```bash
   ./vendor/bin/deptrac analyse
   ```
