# Guia Maestra de Gestion de GitHub Wiki

GitHub Wiki es un sistema de documentacion colaborativo integrado en cada repositorio de GitHub. Tecnicamente, cada Wiki es un **repositorio Git independiente** con su propio historial, ramas y archivos Markdown.

---

## 1. Naturaleza y Arquitectura del Wiki

- **URL del Repositorio Git del Wiki:**
  ```text
  https://github.com/<owner>/<repo>.wiki.git
  ```
- **Rama principal:** Historicamente `master` (en algunos repositorios recientes puede configurarse como `main`).
- **Permisos:** Hereda los permisos de escritura del repositorio principal.
- **Formatos soportados:** Markdown (`.md`), MediaWiki (`.mediawiki`), Textile (`.textile`), AsciiDoc (`.asciidoc`), Org-mode (`.org`).

---

## 2. Archivos Especiales de Estructura y Navegacion

Para crear una documentacion estructurada y visualmente profesional:

| Archivo | Funcion |
| :--- | :--- |
| `Home.md` | Pagina de inicio principal que se muestra por defecto al acceder a la pestana Wiki. |
| `_Sidebar.md` | Barra lateral de navegacion fija que aparece en todas las paginas del Wiki. |
| `_Footer.md` | Pie de pagina fijo que aparece al final de cada pagina del Wiki. |

### Ejemplo de `_Sidebar.md`
```markdown
### 📖 Documentacion
- [[Home]]
- [[Arquitectura del Sistema]]
- [[Guia de Instalacion]]

### 🛠️ Operaciones
- [[Gestion de Ambientes]]
- [[Monitoreo y Alertas]]
- [[Solucion de Problemas]]
```

### Sintaxis de Enlaces Internos (Wikilinks)
- Enlace por titulo: `[[Nombre de la Pagina]]`
- Enlace con texto personalizado: `[[Texto a Mostrar|Nombre-de-la-Pagina]]`
- Enlace Markdown estandar: `[Texto](Nombre-de-la-Pagina)` (los espacios en nombres de archivos se reemplazan por guiones `-`).

---

## 3. Flujo de Trabajo Local con Git

El Wiki se gestiona como cualquier proyecto Git desde la terminal:

```bash
# 1. Clonar el repositorio del wiki
git clone https://github.com/<owner>/<repo>.wiki.git wiki-local
cd wiki-local

# 2. Crear o editar paginas
cat << 'EOF' > Home.md
# Bienvenido a la Wiki del Proyecto

Consulte la barra lateral para navegar por las secciones tecnicas.
EOF

# 3. Comitear y enviar cambios
git add .
git commit -m "docs(wiki): update landing page and navigation"
git push origin master
```

---

## 4. Comprobacion y Activacion via `gh` CLI y API

Comprobar si el wiki esta habilitado en el repositorio:
```bash
gh api repos/:owner/:repo --jq '.has_wiki'
```

Activar el wiki si se encuentra deshabilitado:
```bash
gh api -X PATCH repos/:owner/:repo -F has_wiki=true
```

---

## 5. Automatizacion: Sincronizacion de `docs/` al Wiki via GitHub Actions

Patron de flujo de trabajo para mantener la documentacion del repositorio principal y el Wiki en perfecta sincronia:

```yaml
name: Sync Docs to Wiki

on:
  push:
    branches: [main]
    paths:
      - 'docs/**'

permissions:
  contents: write

jobs:
  sync-wiki:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout main repo
        uses: actions/checkout@v4

      - name: Checkout wiki repo
        uses: actions/checkout@v4
        with:
          repository: ${{ github.repository }}.wiki
          path: wiki
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Copy docs to wiki
        run: |
          cp -r docs/* wiki/
          cd wiki
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add .
          if ! git diff --staged --quiet; then
            git commit -m "chore(wiki): sync documentation from main repository"
            git push origin master
          fi
```
