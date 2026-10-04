# Guia Maestra de GitHub Actions y Workflows

GitHub Actions es la plataforma de automatizacion de CI/CD nativa de GitHub. Esta guia cubre patrones avanzados de diseno, seguridad, control de concurrencia y operacion via `gh` CLI.

---

## 1. Eventos y Disparadores (Triggers)

Un workflow (`.github/workflows/*.yml`) puede activarse por multiples eventos:

```yaml
on:
  push:
    branches: [main]
    paths-ignore:
      - '**.md'
      - 'docs/**'
  pull_request:
    branches: [main]
    types: [opened, synchronize, reopened]
  workflow_dispatch:
    inputs:
      target_env:
        description: 'Ambiente de destino'
        required: true
        default: 'staging'
        type: choice
        options: [staging, production]
      run_smoke_tests:
        description: 'Ejecutar tests de humo'
        required: false
        default: true
        type: boolean
  schedule:
    - cron: '0 4 * * 1' # Todos los lunes a las 04:00 UTC
  workflow_call:
    inputs:
      config-path:
        required: true
        type: string
    secrets:
      api-token:
        required: true
```

---

## 2. Principio de Minimo Privilegio (Permissions)

Por defecto, los workflows heredan permisos amplios o los definidos en la organizacion. Es mandatorio restringir los permisos en la raiz del workflow o a nivel de cada job:

```yaml
# Restriccion a nivel de workflow
permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  publish-comments:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write # Permiso especifico solo para este job
    steps:
      - uses: actions/checkout@v4
      - run: gh pr comment ${{ github.event.pull_request.number }} --body "Tests OK"
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## 3. Concurrencia y Cancelacion de Builds Obsoletos

Para evitar que commits sucesivos en un PR ejecuten pipelines redundantes en paralelo:

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

---

## 4. Matriz de Pruebas y Fail-Fast

Permite ejecutar el pipeline en multiples combinaciones de sistemas operativos y runtimes:

```yaml
jobs:
  matrix-test:
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false # Continua ejecutando las demas variantes si una falla
      matrix:
        os: [ubuntu-latest, macos-latest]
        node-version: [18.x, 20.x, 22.x]
        exclude:
          - os: macos-latest
            node-version: 18.x
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: 'npm'
      - run: npm ci
      - run: npm test
```

---

## 5. Endurecimiento de Seguridad en la Cadena de Suministro

1. **Fijacion de Acciones a Commit SHAs Inmutables:**
   - En lugar de tags mutables (`@v4`), fijar el hash SHA-1 de 40 caracteres:
     ```yaml
     uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
     ```
2. **Validacion de Sintaxis con Actionlint:**
   - Comprueba tipos, expresiones `${{ }}`, sintaxis YAML y permisos faltantes.
     ```bash
     actionlint .github/workflows/*.yml
     ```

---

## 6. Operacion y Depuracion Completa via `gh` CLI

La herramienta oficial `gh` permite controlar y depurar workflows sin abrir el navegador:

### Listar y Disparar Workflows
```bash
# Listar workflows disponibles
gh workflow list

# Ver detalles de un workflow especifico
gh workflow view ci.yml

# Disparar manualmente un workflow con inputs
gh workflow run deploy.yml -f target_env=staging -f run_smoke_tests=true
```

### Monitoreo e Inspeccion de Ejecuciones (Runs)
```bash
# Listar las 10 ejecuciones mas recientes
gh run list --limit 10

# Filtrar ejecuciones por workflow y rama
gh run list --workflow=ci.yml --branch=main

# Ver estado de una ejecucion especifica
gh run view <run-id>

# Ver el progreso en tiempo real
gh run watch <run-id>
```

### Depuracion de Fallos y Logs
```bash
# Ver unicamente los logs de los pasos que fallaron (ahorro masivo de tokens)
gh run view <run-id> --log-failed

# Re-ejecutar UNICAMENTE los jobs fallidos
gh run rerun <run-id> --failed

# Re-ejecutar el workflow completo con logs de depuracion activados
gh run rerun <run-id> --debug

# Cancelar una ejecucion en curso
gh run cancel <run-id>

# Descargar artefactos generados en la ejecucion
gh run download <run-id> -D ./build-artifacts
```
