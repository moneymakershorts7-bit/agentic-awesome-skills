# Guia Maestra de GitHub Environments

Los **GitHub Environments** (Entornos de Despliegue) permiten definir destinos de ejecucion seguros (ej. `production`, `staging`, `preview`) con reglas de proteccion estrictas, revisores obligatorios, temporizadores de espera y variables/secretos aislados por ambiente.

---

## 1. Conceptos Clave de Environments

- **Reglas de Proteccion (Protection Rules):**
  - **Revisores requeridos:** Uno o mas usuarios/equipos deben aprobar manualmente el despliegue antes de que se ejecute el job.
  - **Temporizador de espera (Wait timer):** Retrasa la ejecucion del job durante un numero determinado de minutos tras activarse.
  - **Politica de ramas de despliegue:** Restringe que ramas pueden desplegar en el ambiente (ej. solo `main` o ramas protegidas).
  - **Prevencion de auto-aprobacion:** Impide que el autor del pull request apruebe su propio despliegue.
- **Secretos y Variables Aislados:** Secretos que solo estan disponibles cuando el job declara explicitamente el `environment: <nombre>`.

---

## 2. Administracion via `gh` CLI y GitHub REST API

### Listar Ambientes Existentes
```bash
gh api repos/:owner/:repo/environments --jq '.environments[].name'
```

### Consultar Detalles y Reglas de un Ambiente
```bash
gh api repos/:owner/:repo/environments/production
```

### Crear o Actualizar un Ambiente con Temporizador y Prevencion de Auto-Revision
```bash
gh api --method PUT repos/:owner/:repo/environments/production \
  -f wait_timer=10 \
  -F prevent_self_review=true
```

### Configurar Politica de Ramas de Despliegue (Solo Ramas Protegidas)
```bash
gh api --method PUT repos/:owner/:repo/environments/production \
  --input - <<< '{
    "deployment_branch_policy": {
      "protected_branches": true,
      "custom_branch_policies": false
    }
  }'
```

### Configurar Politica de Ramas Personalizadas (ej. `main` o `release/*`)
```bash
# 1. Habilitar ramas personalizadas
gh api --method PUT repos/:owner/:repo/environments/staging \
  --input - <<< '{
    "deployment_branch_policy": {
      "protected_branches": false,
      "custom_branch_policies": true
    }
  }'

# 2. Agregar regla de rama autorizada
gh api --method POST repos/:owner/:repo/environments/staging/deployment-branch-policies \
  -f name="release/*"
```

### Configurar Revisores Requeridos (Aprobacion Manual)
```bash
gh api --method PUT repos/:owner/:repo/environments/production \
  --input - <<< '{
    "reviewers": [
      {
        "type": "User",
        "id": 12345678
      }
    ]
  }'
```

### Eliminar un Ambiente
```bash
gh api --method DELETE repos/:owner/:repo/environments/temp-env
```

---

## 3. Gestion de Secretos y Variables de Ambiente

Los secretos y variables de ambiente tienen prioridad sobre los secretos a nivel de repositorio u organizacion:

### Secretos de Ambiente
```bash
# Crear o actualizar un secreto en el ambiente production
gh secret set DB_PASSWORD --env production --body "$SECRET_VALUE"

# Listar secretos del ambiente
gh secret list --env production

# Eliminar secreto de ambiente
gh secret delete DB_PASSWORD --env production
```

### Variables de Ambiente (Valores no sensibles)
```bash
# Crear o actualizar variable
gh variable set API_BASE_URL --env production --body "https://api.prod.example.com"

# Listar variables del ambiente
gh variable list --env production

# Eliminar variable de ambiente
gh variable delete API_BASE_URL --env production
```

---

## 4. Uso de Environments en GitHub Actions Workflows

Para vincular un job a un ambiente protegido y acceder a sus secretos exclusivos:

```yaml
name: Deploy Production

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://prod.example.com
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Execute deployment
        env:
          DATABASE_URL: ${{ secrets.DB_PASSWORD }}
          API_URL: ${{ vars.API_BASE_URL }}
        run: |
          echo "Desplegando en ambiente production..."
          echo "Conectando a base de datos de producción de forma segura."
```
