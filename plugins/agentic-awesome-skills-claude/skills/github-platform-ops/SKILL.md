---
name: github-platform-ops
description: Master GitHub Wikis, Environments, Actions, and Workflows via gh CLI, Git, and GitHub REST API. Handles wiki cloning and structure, deployment environments with protection rules and secrets/vars, workflow dispatch, matrix, concurrency, and log debugging.
license: MIT
risk: safe
source: internal
date_added: '2026-10-03'
allowed-tools:
  - bash
  - read
  - grep
---

# GitHub Platform Operations: Wiki, Environments, Actions & Workflows

## When to Use
Utilizar este skill cuando se requiera operar componentes avanzados de la plataforma GitHub:
- **GitHub Wiki:** Clonar el repositorio Git del wiki, disenar estructuras de navegacion (`_Sidebar.md`, `_Footer.md`, `Home.md`), o automatizar sincronizaciones de documentacion.
- **GitHub Environments:** Crear y configurar ambientes de despliegue (`production`, `staging`), definir reglas de proteccion (aprobaciones manuales, wait timers, politicas de ramas), y gestionar variables o secretos aislados por ambiente.
- **GitHub Actions & Workflows:** Disenar o modificar pipelines YAML, configurar disparadores (`push`, `pull_request`, `workflow_dispatch`), restringir permisos bajo minimo privilegio, gestionar concurrencia, y depurar logs de fallos con `gh run view --log-failed`.

---

## 1. Gestion de GitHub Wiki

El Wiki de cualquier repositorio es un repositorio Git independiente accesible via:
`https://github.com/<owner>/<repo>.wiki.git`

### Operaciones Esenciales:
1. **Comprobar si el Wiki esta habilitado:**
   ```bash
   gh api repos/:owner/:repo --jq '.has_wiki'
   ```
2. **Clonar el repositorio de la wiki:**
   ```bash
   git clone https://github.com/<owner>/<repo>.wiki.git
   ```
3. **Estructura basica de navegacion:**
   - `Home.md`: Portada de inicio.
   - `_Sidebar.md`: Menu lateral visible en todas las paginas.
   - `_Footer.md`: Pie de pagina global.
4. **Referencias detalladas:** Consultar [references/wiki_management.md](references/wiki_management.md).

---

## 2. GitHub Environments y Reglas de Proteccion

Los Environments permiten aislar configuraciones de despliegue con aprobaciones humanas y secretos protegidos.

### Operaciones via `gh` CLI:
1. **Listar ambientes existentes:**
   ```bash
   gh api repos/:owner/:repo/environments --jq '.environments[].name'
   ```
2. **Crear o actualizar un ambiente con temporizador y revision obligatoria:**
   ```bash
   gh api --method PUT repos/:owner/:repo/environments/production \
     -f wait_timer=10 \
     -F prevent_self_review=true
   ```
3. **Restringir despliegues a ramas protegidas:**
   ```bash
   gh api --method PUT repos/:owner/:repo/environments/production \
     --input - <<< '{"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false}}'
   ```
4. **Gestionar secretos y variables del ambiente:**
   ```bash
   # Secretos (cifrados)
   gh secret set DB_PASSWORD --env production --body "$DB_PASSWORD_VAL"
   gh secret list --env production

   # Variables (valores planos)
   gh variable set DEPLOY_REGION --env production --body "us-east-1"
   gh variable list --env production
   ```
5. **Referencias detalladas:** Consultar [references/environments_guide.md](references/environments_guide.md).

---

## 3. GitHub Actions y Workflows

### Mejores Practicas de Arquitectura:
- **Minimo Privilegio (Permissions):** Declarar siempre `permissions: contents: read` en la raiz del workflow y habilitar escritura solo en los jobs que lo demanden estrictamente (`pull-requests: write`).
- **Control de Concurrencia:** Cancelar builds obsoletos en ramas activas con:
  ```yaml
  concurrency:
    group: ${{ github.workflow }}-${{ github.ref }}
    cancel-in-progress: true
  ```
- **Fijacion de Acciones Inmutables:** Utilizar hashes SHA-1 de 40 caracteres en lugar de tags mutables para proteger la cadena de suministro.

### Monitoreo y Depuracion Operativa con `gh`:
```bash
# 1. Listar las ejecuciones recientes
gh run list --limit 10

# 2. Ver unicamente los logs de los pasos fallidos (ahorro masivo de tokens)
gh run view <run-id> --log-failed

# 3. Disparar manualmente un workflow con inputs
gh workflow run deploy.yml -f target_env=staging

# 4. Re-ejecutar unicamente los jobs que fallaron
gh run rerun <run-id> --failed
```
Referencias detalladas: Consultar [references/workflows_mastery.md](references/workflows_mastery.md).

---

## Limitations

- La creacion de wikis requiere que el repositorio tenga activada la opcion en su configuracion general.
- Las reglas de proteccion avanzadas de Environments (aprobadores requeridos y wait timers) requieren repositorios publicos o planes GitHub Pro/Team/Enterprise en repositorios privados.
- La gestion de secretos mediante `gh secret set` requiere permisos de administracion (`admin:repo_hook` o rol admin/maintainer) sobre el repositorio.
