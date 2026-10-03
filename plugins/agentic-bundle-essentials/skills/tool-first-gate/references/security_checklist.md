# Protocolo y Lista de Verificacion de Seguridad Previa a la Instalacion

Antes de instalar cualquier herramienta, binario, libreria o paquete para resolver una tarea mecanica, el agente debe someter el paquete al siguiente protocolo de auditoria estricto.

---

## 1. Verificacion de Origen y Procedencia (Provenance)

El origen del paquete determina el nivel de confianza y el vector de instalacion:

### Nivel 1: Repositorios Oficiales del Sistema (Maxima Confianza)
- **Gestores:** `apt` (Ubuntu/Debian), `dnf`/`yum` (Fedora/RHEL), `apk` (Alpine).
- **Criterio:** Paquetes mantenidos y firmados criptograficamente por la distribucion.
- **Accion:** Preferir siempre sobre paquetes de terceros.
- **Comando de comprobacion:**
  ```bash
  apt-cache show <paquete>
  ```
  Verificar que `Maintainer:` corresponda a los mantenedores oficiales de la distro.

### Nivel 2: Registros de Lenguaje Oficiales (Confianza Verificada)
- **Python / PyPI:** Utilizar `uv tool install <paquete>` para aislar el entorno en lugar de instalaciones globales no aisladas.
  - Comprobar que el paquete en PyPI tiene repositorio oficial enlazado en GitHub/GitLab.
  - Verificar volumen de descargas y antiguedad (> 1 ano y > 50k descargas mensuales para herramientas utilitarias comunes).
- **JavaScript / NPM:** Utilizar `bun add -g <paquete>` o `npm install -g --ignore-scripts <paquete>`.
  - Flags mandatorios: Si se usa `npm`, pasar `--ignore-scripts` a menos que sea estrictamente necesario para compilar binarios nativos conocidos.
- **Rust / Crates.io:** Utilizar `cargo install <paquete>` o binarios precompilados de releases oficiales verificando el hash sha256.

### Nivel 3: Binarios Precompilados Directos de GitHub Releases
- Solo descargar de la organizacion o autor oficial reconocido (ej. `duckdb`, `ripgrep`).
- **Verificacion de Integridad:** Comprobar siempre el checksum `sha256sum` publicado en el release antes de ejecutar el binario.

---

## 2. Deteccion de Typosquatting y Suplantacion

Los atacantes registran nombres similares a herramientas populares para inducir al usuario o al agente a instalar malware:

| Herramienta Legitima | Ejemplos de Typosquatting Malicioso |
| :--- | :--- |
| `pandoc` | `pypandoc-malicious`, `pandoc-cli-tool`, `pandoc-py` |
| `ffmpeg` | `ffmpeg-python-bin`, `pyffmpeg-core` |
| `imagemagick` | `image-magick-tool`, `imagemagick-cli` |
| `csvkit` | `csv-kit`, `csvtools-kit` |
| `duckdb` | `duck-db`, `duckdb-core-lib` |
| `ripgrep` | `rip-grep`, `ripgrep-bin-linux` |

**Regla de comprobacion:**
- Nunca instalar un paquete cuyo nombre difiera del nombre canonico oficial documentado en `references/tool_matrix.md`.
- Si se solicita un formato no documentado, buscar primero el proyecto original en GitHub y verificar las estrellas, contribuidores y licencia antes de descargar.

---

## 3. Auditoria de Vulnerabilidades y CVEs Conocidos

Antes de instalar paquetes de registros dinamicos (PyPI, NPM):

1. **Escaneo de Base de Datos OSV / NVD:**
   Si se instala via Python:
   ```bash
   pip-audit --package <nombre_paquete>
   ```
2. **Evaluacion de Severidad:**
   - Si se detecta un CVE con severidad **CRITICAL** o **HIGH** (CVSS > 7.0), **ABORTAR** la instalacion inmediatamente y buscar una herramienta alternativa en la matriz.
   - Si existen avisos de severidad **MEDIUM** o **LOW**, revisar si el vector de ataque involucra red o inputs no sanitizados antes de proceder.

---

## 4. Principio de Minimo Privilegio y Aislamiento de Red

Las tareas mecanicas de conversion (transformar un Markdown a PDF, un WAV a MP3, o un CSV a Parquet) son intrinsecamente **locales y desconectadas**:

1. **Aislamiento de Red (Offline por Defecto):**
   - Una herramienta de conversion de archivos **NUNCA** requiere conectividad a internet para procesar un archivo local.
   - Si la herramienta intenta abrir sockets o realizar peticiones HTTP durante la conversion, clasificar el evento como anomalia o exfiltracion sospechosa.
2. **Permisos de Ejecucion:**
   - La ejecucion de la herramienta debe realizarse siempre bajo el usuario sin privilegios elevados.
   - Nunca ejecutar conversores o parsers con privilegios de root por riesgo de sobreescritura accidental o maliciosa de archivos de sistema.
3. **Limites de Recursos:**
   - Para herramientas que procesan imagenes o videos (ImageMagick, FFmpeg), establecer limites para evitar ataques de denegacion de servicio por archivos bomba:
     - ImageMagick: configurar limites de memoria (`-limit memory 512MiB -limit disk 1GiB`).
     - FFmpeg: limitar tiempo de ejecucion con flags de timeout si se procesan archivos de origen desconocido.

---

## 5. Protocolo de Descarte y Limpieza

1. **Verificacion de artefactos temporales:**
   - Las herramientas mecanicas deben escribir unicamente en la ruta de destino designada por el usuario o en el directorio temporal de trabajo.
   - Prohibido dejar archivos temporales huerfanos en directorios compartidos del sistema.
2. **Confirmacion de Integridad de Salida:**
   - Comprobar que el archivo de destino no este vacio.
   - Comprobar que el codigo de salida del proceso fue exactamente `0`.
