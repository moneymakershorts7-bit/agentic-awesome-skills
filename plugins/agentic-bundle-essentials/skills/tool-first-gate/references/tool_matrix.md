# Matriz de Herramientas Especializadas para Tareas Mecánicas

Esta matriz contiene las herramientas CLI canónicas, óptimas y probadas para tareas determinísticas y de procesamiento por lotes que no requieren razonamiento cognitivo por parte del LLM.

---

## 1. Documentos y Formatos

| Tarea Mecánica | Herramienta Canónica | Paquete / Gestor | Comando de Verificación | Notas de Uso y Seguridad |
| :--- | :--- | :--- | :--- | :--- |
| Markdown ↔ DOCX ↔ PDF ↔ EPUB ↔ LaTeX | `pandoc` | `apt: pandoc` | `pandoc --version` | Estándar de la industria. No requiere acceso a red. Para PDF requiere engine LaTeX o `wkhtmltopdf`/`typst`. |
| DOCX / XLSX / PPTX ➔ PDF | `libreoffice` | `apt: libreoffice-writer-nogui` | `libreoffice --version` | Ejecutar siempre en modo headless: `libreoffice --headless --convert-to pdf <archivo>`. |
| PDF ➔ Texto plano | `pdftotext` | `apt: poppler-utils` | `pdftotext -v` | Rápido, ligero y 100% offline. `pdftotext -layout input.pdf output.txt`. |
| PDF ➔ Imágenes (PNG/JPEG) | `pdftoppm` | `apt: poppler-utils` | `pdftoppm -v` | Conversión rasterizada de alta fidelidad: `pdftoppm -png -r 150 input.pdf page`. |
| Extracción de imágenes en PDF | `pdfimages` | `apt: poppler-utils` | `pdfimages -v` | Extrae imágenes embebidas sin recomprimir: `pdfimages -png input.pdf extracted/img`. |
| Fusión / Separación de PDFs | `pdfunite` / `qpdf` | `apt: poppler-utils` / `apt: qpdf` | `qpdf --version` | `qpdf --empty --pages file1.pdf file2.pdf -- output.pdf`. Preserva metadatos y enlaces. |
| Tipografía y Maquetación Moderna | `typst` | `cargo: typst-cli` / binario | `typst --version` | Alternativa moderna ultra-rápida a LaTeX para compilar documentos profesionales a PDF. |

---

## 2. Multimedia (Audio y Video)

| Tarea Mecánica | Herramienta Canónica | Paquete / Gestor | Comando de Verificación | Notas de Uso y Seguridad |
| :--- | :--- | :--- | :--- | :--- |
| Transcodificación / Corte / Compresión de Video | `ffmpeg` | `apt: ffmpeg` | `ffmpeg -version` | Herramienta universal. Para re-escalar: `ffmpeg -i in.mp4 -vf scale=1280:-1 out.mp4`. No requiere red. |
| Extracción de audio desde video | `ffmpeg` | `apt: ffmpeg` | `ffmpeg -version` | `ffmpeg -i video.mp4 -vn -acodec mp3 audio.mp3` o `-acodec copy`. |
| Procesamiento, normalización y filtrado de Audio | `sox` | `apt: sox libsox-fmt-all` | `sox --version` | La navaja suiza de audio: `sox in.wav out.mp3 norm -0.1`. |
| Descarga autorizada de stream/video | `yt-dlp` | `uv: yt-dlp` | `yt-dlp --version` | Requiere red. Ejecutar con flags de sandbox y solo sobre URLs explícitamente autorizadas por el usuario. |

---

## 3. Gráficos e Imágenes

| Tarea Mecánica | Herramienta Canónica | Paquete / Gestor | Comando de Verificación | Notas de Uso y Seguridad |
| :--- | :--- | :--- | :--- | :--- |
| Conversión de formatos de imagen, recorte, resize | `magick` / `convert` | `apt: imagemagick` | `magick --version` | Ejecutar con directivas seguras de memoria (`-limit memory 512MB`). |
| Optimización sin pérdida de PNG | `optipng` | `apt: optipng` | `optipng -v` | Reduce peso sin perder un solo píxel: `optipng -o5 imagen.png`. |
| Optimización de JPEG | `jpegoptim` | `apt: jpegoptim` | `jpegoptim --version` | `jpegoptim --strip-all -m85 imagen.jpg`. |
| Conversión a formato WebP moderno | `cwebp` / `dwebp` | `apt: webp` | `cwebp -version` | `cwebp -q 80 imagen.png -o imagen.webp`. Soporte nativo para transparencia. |
| SVG ➔ PNG / PDF / EPS | `rsvg-convert` | `apt: librsvg2-bin` | `rsvg-convert --version` | Renderizado rápido de vectores SVG a mapa de bits sin requerir un navegador headless completo. |

---

## 4. Datos Estructurados

| Tarea Mecánica | Herramienta Canónica | Paquete / Gestor | Comando de Verificación | Notas de Uso y Seguridad |
| :--- | :--- | :--- | :--- | :--- |
| Filtrado, mapeo y transformación JSON | `jq` | `apt: jq` | `jq --version` | Rápido y determinístico. No requiere Node ni runtime de scripting. |
| Filtrado y edición de YAML | `yq` | `apt: yq` / `bun: yq` | `yq --version` | Soporta conversiones directas YAML ↔ JSON ↔ XML. |
| Consultas SQL analíticas sobre CSV, JSON, Parquet | `duckdb` | binario / `uv: duckdb` | `duckdb --version` | Base de datos analítica en memoria ultra-rápida. Procesa gigabytes en segundos con SQL estándar. |
| Manipulación, corte y unión de CSV | `csvkit` / `xsv` | `uv: csvkit` / `cargo: xsv` | `csvstat --version` | `csvcut`, `csvgrep`, `csvjoin`. Ideal para inspección rápida de datasets tabulares. |
| Procesamiento tabular multilenguaje (CSV, TSV, JSON) | `mlr` (Miller) | `apt: miller` | `mlr --version` | Como awk/sed/cut pero con comprensión nativa de columnas y claves estructuradas. |

---

## 5. Extracción Web y Búsqueda de Texto

| Tarea Mecánica | Herramienta Canónica | Paquete / Gestor | Comando de Verificación | Notas de Uso y Seguridad |
| :--- | :--- | :--- | :--- | :--- |
| Extracción limpia de HTML a Markdown | `defuddle` | CLI local / `bun` | `defuddle --version` | Limpia menús, cookies y scripts, devolviendo contenido editorial legible. |
| Extracción de selectores CSS desde HTML | `htmlq` / `pup` | `cargo: htmlq` | `htmlq --version` | Equivalente a `jq` para documentos HTML en bash. |
| Búsqueda ultra-rápida de patrones en texto | `rg` (ripgrep) | `apt: ripgrep` | `rg --version` | Respeta `.gitignore`, multi-hilo, eficiente en uso de CPU y memoria. |
| Búsqueda de archivos en árbol de directorios | `fd` | `apt: fd-find` | `fdfind --version` | Reemplazo rápido de `find` con regex y coloreado. |

---

## 6. OCR y Reconocimiento Local

| Tarea Mecánica | Herramienta Canónica | Paquete / Gestor | Comando de Verificación | Notas de Uso y Seguridad |
| :--- | :--- | :--- | :--- | :--- |
| Extracción de texto desde imágenes/escaneos (OCR) | `tesseract` | `apt: tesseract-ocr` | `tesseract --version` | Soporte multilingüe (`tesseract-ocr-spa`, `tesseract-ocr-eng`). `tesseract input.png output -l spa`. |
| Transcripción de audio a texto | `whisper-cpp` | binario / `uv tool` | `whisper --version` | Modelos compactos (`base`, `small`) ejecutados 100% offline en CPU local. |

---

## 7. Compresión y Archivos

| Tarea Mecánica | Herramienta Canónica | Paquete / Gestor | Comando de Verificación | Notas de Uso y Seguridad |
| :--- | :--- | :--- | :--- | :--- |
| Compresión ultra-rápida y de alto ratio | `zstd` | `apt: zstd` | `zstd --version` | `zstd -T0 -19 archivo` para compresión multi-hilo máxima. |
| Descompresión multiformato (7z, rar, zip, tar) | `7z` | `apt: p7zip-full` | `7z` | Robusto para archivos comprimidos complejos o partidos. |
| Gzip acelerado multi-núcleo | `pigz` | `apt: pigz` | `pigz --version` | Drop-in replacement para `gzip` utilizando todos los cores de CPU. |
