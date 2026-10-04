---
name: tool-first-gate
description: Mandatory pre-execution gate for mechanical tasks (file conversions, media transcoding, data restructuring, OCR, archiving). Discovers the best CLI tool, audits security, installs safely, and executes deterministically without wasting LLM reasoning tokens.
license: MIT
risk: safe
source: internal
date_added: '2026-10-03'
allowed-tools:
  - bash
  - read
  - grep
permissions:
  - shell
metadata:
  aas-category: essentials
  aas-tags: '["tooling", "security", "conversions", "deterministic", "optimization"]'
---

# Tool-First Gate: Resolucion y Seguridad para Tareas Mecanicas

## When to Use

Activar este gate **obligatoriamente** ante cualquier tarea **mecanica, algoritmica o deterministica** que **no requiera razonamiento cognitivo** del modelo.

### Tareas Mecanicas (Activar Gate)
- **Conversion de formatos de documentos:** Markdown a PDF, DOCX a PDF, HTML a Markdown, EPUB a MOBI.
- **Procesamiento multimedia:** Transcodificacion de video (MP4, MKV, WebM), compresion, extraccion de pistas de audio (MP3, WAV), recorte o cambio de tasa de cuadros.
- **Transformacion de datos estructurados:** JSON a CSV, CSV a Parquet, consultas SQL en memoria sobre datasets, filtrado tabular masivo.
- **Manipulacion de imagenes y graficos:** Redimensionamiento por lotes, optimizacion sin perdida (PNG/JPEG/WebP), rasterizacion SVG.
- **Extraccion de texto u OCR:** `pdftotext`, `tesseract`, transcripcion local con `whisper`.
- **Compresion y empaquetado:** `tar`, `zstd`, `7z`, `pigz`.

### Tareas Cognitivas (NO Activar Gate)
- Arquitectura de software, diseno de esquemas de bases de datos relacionales, depuracion de condiciones de carrera logicas, redaccion creativa de contenido, prompting o decisiones de negocio.

---

## Principio Fundamental

> **Prohibido reinventar la rueda con tokens:** El agente **nunca** debe escribir scripts caseros fragiles en Python/Bash ni manipular archivos linea por linea mediante tokens del LLM cuando existe una herramienta de linea de comandos estandar de la industria, optimizada y de alto rendimiento.

---

## Flujo Operativo en 5 Pasos

```
  [ Tarea Entrante ]
          │
          ▼
1. Clasificacion: ¿Es mecanica / deterministica?
          │  (Si: Detener generacion de tokens de codigo ad-hoc)
          ▼
2. Busqueda y Recomendacion de la Herramienta Canonica
          │  (Consultar matriz y catalogo de herramientas probadas)
          ▼
3. Auditoria Previa de Seguridad y Procedencia
          │  (APT oficial / PyPI verificado / Typosquatting / Offline)
          ▼
4. Instalacion Aislada y Prueba de Humo (--version)
          │  (apt-get / uv tool / bun sin privilegios excesivos)
          ▼
5. Ejecucion Deterministica y Registro en Memoria Procedural
```

---

## 1. Clasificacion y Deteccion

Antes de escribir una sola linea de codigo, responder:
- ¿Esta tarea transforma una entrada A en una salida B mediante una regla formal estandar?
- ¿Existe ya una utilidad CLI disenada especificamente para esto (`pandoc`, `ffmpeg`, `jq`, `duckdb`, `poppler`, etc.)?
- Si la respuesta es afirmativa, ingresar inmediatamente en el Gate Tool-First.

---

## 2. Busqueda y Seleccion de la Herramienta Canonica

Verificar si la herramienta ya esta disponible en el sistema antes de intentar instalarla:

```bash
python3 scripts/vet_and_install_tool.py recommend "convertir pdf a docx"
```

O verificar manualmente el binario con `which`:
```bash
which pandoc
```

Si la tarea requiere una herramienta especifica, consultar la guia detallada en [references/tool_matrix.md](references/tool_matrix.md).

---

## 3. Protocolo de Auditoria de Seguridad Previa

Antes de instalar cualquier paquete, ejecutar la auditoria de procedencia y seguridad:

```bash
python3 scripts/vet_and_install_tool.py audit <nombre_paquete> --manager <apt|uv|bun>
```

### Reglas de Aprobacion de Seguridad:
1. **Procedencia Oficial:**
   - Preferir siempre paquetes del repositorio oficial de la distribucion Linux.
   - Para paquetes Python: usar unicamente `uv tool install` (aislado en entorno propio).
   - Para paquetes JS: usar `bun add -g` o `npm install -g --ignore-scripts`.
2. **Defensa contra Typosquatting:**
   - Verificar contra la lista negra de nombres enganosos en [references/security_checklist.md](references/security_checklist.md).
3. **Aislamiento de Red:**
   - Tareas mecanicas locales **no deben** realizar llamadas de red. Prohibido instalar conversores que dependan de APIs propietarias de terceros cuando existe alternativa local offline.
4. **Minimo Privilegio:**
   - Ejecutar conversiones y transformaciones siempre bajo el usuario local sin elevaciones innecesarias de privilegios.

---

## 4. Instalacion Segura y Prueba de Humo

Generar el plan auditado de instalacion:

```bash
python3 scripts/vet_and_install_tool.py plan <herramienta>
```

Ejecutar la instalacion con la herramienta correspondiente:

```bash
# Gestor de paquetes de sistema
apt-get install -y --no-install-recommends <paquete>

# O entorno aislado de herramientas Python
uv tool install <paquete>
```

### Prueba de Humo Mandatoria:
```bash
<binario> --version
```
Confirmar que el codigo de salida sea `0` antes de proceder con la transformacion del archivo.

---

## 5. Ejecucion Deterministica y Persistencia

Ejecutar la herramienta sobre los archivos de entrada con directivas seguras de salida:

```bash
# Ejemplo: Conversion de documento
pandoc -s entrada.md -o salida.docx

# Ejemplo: Extraccion de texto de PDF
pdftotext -layout documento.pdf texto_extraido.txt

# Ejemplo: Compresion y normalizacion de audio
ffmpeg -i origen.wav -vn -ar 44100 -ac 2 -b:a 192k salida.mp3
```

### Persistencia en Memoria Procedural:
Una vez que una herramienta ha sido instalada y validada en el entorno, registrar su receta en la memoria procedural para que futuras sesiones la reutilicen inmediatamente sin repetir la fase de prospeccion.

---

## Recetario Rapido de Tareas Mecanicas Comunes

| Tarea Requerida | Herramienta | Comando Canonico |
| :--- | :--- | :--- |
| **DOCX a PDF** | `libreoffice` | `libreoffice --headless --convert-to pdf entrada.docx` |
| **Markdown a DOCX** | `pandoc` | `pandoc entrada.md -o salida.docx` |
| **PDF a Texto** | `pdftotext` | `pdftotext -layout entrada.pdf salida.txt` |
| **PDF a PNG** | `pdftoppm` | `pdftoppm -png -r 150 entrada.pdf pagina` |
| **Extraer Audio de Video** | `ffmpeg` | `ffmpeg -i video.mp4 -vn -acodec copy audio.m4a` |
| **Optimizar PNG** | `optipng` | `optipng -o5 imagen.png` |
| **Transformar JSON** | `jq` | `jq '.items[] | {id, name}' data.json` |
| **SQL sobre Tablas** | `duckdb` | `duckdb -c "SELECT count(*) FROM input_dataset;"` |

---

## Limitations

- Este gate esta reservado para transformaciones mecanicas y procesamiento deterministico.
- Si una tarea requiere juicio semantico (ej. corregir estilo de redaccion, resumir ejecutivamente, refactorizar logica de negocio), se debe emplear el razonamiento del LLM.
- En contenedores o sistemas con restricciones severas donde los paquetes de sistema requieran autorizacion del administrador, preferir binarios de usuario aislados (`uv tool` o binarios en `~/.local/bin/`).
