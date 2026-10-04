# Tipografía Editorial y Pares Tipográficos para Libros

La selección tipográfica es la base estructural del diseño editorial. Un libro bien diseñado no solo es legible, sino que evoca la atmósfera, época y dignidad del contenido.

---

## 1. Pares Tipográficos Canónicos

### A. Sagrada Historia / Bestseller Teológico / Antigüedad
* **Títulos (H1, H2):** `Cinzel` (Google Fonts, 600/700) o `Cormorant Garamond` (700).
  * *Inspiración:* Inscripciones monumentales de la Columna de Trajano y códices clásicos.
  * *Propiedades:* Serif clásica, versalitas (*small caps*), proporción romana imperial, excelente kerning.
* **Subtítulos y Secciones (H3, H4):** `Cormorant Garamond` o `Cinzel`.
* **Cuerpo de Texto (Body / Párrafos):** `EB Garamond` (Google Fonts, 400 normal, 400 itálica, 600 semibold).
  * *Inspiración:* El canon de Claude Garamond del siglo XVI, considerado el epítome de la legibilidad en libros impresos.
  * *Propiedades:* Ojo medio, remates suaves, excelente contraste en bloques densos de texto.
* **Citas y Notas al Pie:** `EB Garamond` en cursiva con reducción proporcional de escala a 9.5pt.

### B. Académico / Crítica Histórica / Monografía Oxford
* **Títulos (H1, H2):** `Playfair Display` (700) o `Libre Baskerville` (700).
  * *Propiedades:* Alto contraste de trazos gruesos y finos, elegancia formal del siglo XVIII.
* **Cuerpo de Texto:** `Source Serif 4` o `Merriweather` (400, 600).
  * *Propiedades:* Tipografía robusta, gran altura de la x, diseñada específicamente para pantallas de alta resolución y páginas impresas nítidas.

### C. Editorial Minimalista / Filosofía / Ensayo Moderno
* **Títulos:** `Inter` o `Montserrat` (Mayúsculas con espaciado amplio `letter-spacing: 0.15em`).
* **Cuerpo de Texto:** `Lora` (400/500).
  * *Propiedades:* Calidez contemporánea con raíces caligráficas.

### D. Renacimiento / Biografías / Clásicos
* **Títulos:** `Cormorant Garamond`.
* **Cuerpo de Texto:** `Cormorant Infant` o `EB Garamond`.

---

## 2. Escala Tipográfica Modular (Proporción Áurea y Cuarta Justa)

Para mantener una jerarquía armónica entre los niveles de encabezados, se aplica la escala de Cuarta Justa (Ratio 1.333):

| Elemento | Tamaño (pt) | Tamaño (rem) | Interlineado (`line-height`) | Espaciado (`letter-spacing`) |
| :--- | :---: | :---: | :---: | :---: |
| **H1 (Título de Capítulo)** | 26pt – 28pt | 2.4rem | 1.15 | 0.05em |
| **H2 (Subtítulo de Capítulo)** | 18pt – 20pt | 1.7rem | 1.25 | 0.02em |
| **H3 (Sección / Período)** | 14pt – 15pt | 1.3rem | 1.30 | 0.01em |
| **H4 (Subsección)** | 11.5pt – 12pt | 1.05rem | 1.35 | 0 |
| **Cuerpo de Texto (Párrafo)** | 10.5pt – 11pt | 1.0rem | 1.60 – 1.65 | 0 |
| **Citas en Bloque (Callouts)** | 9.5pt – 10pt | 0.9rem | 1.50 | 0 |
| **Pies de Figura (Captions)** | 8.5pt – 9pt | 0.8rem | 1.40 | 0.01em |
| **Encabezados / Pies de Página** | 8pt – 8.5pt | 0.75rem | 1.0 | 0.04em |

---

## 3. Microtipografía y Reglas de Imprenta

1. **Justificación e Hipenación:**
   * En libros impresos, los párrafos principales deben estar justificados (`text-align: justify;`).
   * Para evitar huecos de espaciado ("ríos de blanco"), se activa la hipenación automática del navegador (`hyphens: auto; -webkit-hyphens: auto;`) con atributo de idioma español (`lang="es"`).
2. **Control de Viudas y Huérfanas:**
   * Prohibir líneas sueltas al inicio o final de página:
     ```css
     p {
       orphans: 3;
       widows: 3;
     }
     ```
3. **Letras Capitulares (*Drop Caps*):**
   * El primer párrafo que sigue a un título de capítulo puede llevar una letra capitular ornamental:
     ```css
     .chapter-content > p:first-of-type::first-letter {
       float: left;
       font-family: 'Cinzel', serif;
       font-size: 3.4em;
       line-height: 0.8;
       padding-right: 0.15em;
       padding-top: 0.05em;
       color: var(--primary-accent);
     }
     ```
4. **Espaciado y Sangría:**
   * En prosa tradicional, se utiliza sangría de primera línea (`text-indent: 1.5em;`) en párrafos subsecuentes, sin espacio vertical entre ellos.
   * En comentarios exegéticos con listas y citas, se prefiere margen inferior suave (`margin-bottom: 0.8em;`) sin sangría para máxima claridad de lectura.
