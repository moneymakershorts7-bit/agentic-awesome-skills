# Paletas Cromáticas Editoriales y Armonía de Color para Libros

En el diseño editorial de libros, el color no es mero adorno; cumple una función jerárquica, orientadora y atmosférica. Las paletas editoriales deben respetar altos estándares de legibilidad, contraste y elegancia para impresión y lectura digital.

---

## 1. Paletas Canónicas por Género y Temática

### A. Sagrada Historia y Oro Imperial (`sacred-history`)
Ideal para comentarios bíblicos, tratados teológicos, crónicas del mundo antiguo e imperios.
* **Borgoña Imperial / Púrpura Profundo (`#6E1A24`):** Color heráldico y digno para títulos principales (`H1`, `H2`), bordes de portadas y acentos solemnes.
* **Oro Antiguo / Bronce Sacro (`#B8860B` / `#C5A059`):** Acento secundario para líneas decorativas, bordes de cajas de texto sagrado (`> 📖`), viñetas y fechas.
* **Carbón Profundo (`#222222`):** Texto principal. Suaviza el impacto frente al negro puro (`#000000`) reduciendo la fatiga visual.
* **Marfil Antiguo / Papel Pergamino (`#FDFCF7`):** Fondo general del libro. Aporta la calidez táctil del papel bibliófilo de alto gramaje.
* **Fondo de Cita Bíblica (`#FBF8F1`):** Tinte dorado muy sutil con borde izquierdo en oro antiguo.
* **Fondo de Verificación Histórica (`#F4F6F8`):** Tinte neutro con borde sutil para datos de fact-checking y referencias académicas.

```css
:root {
  --theme-primary: #6E1A24;
  --theme-secondary: #C5A059;
  --theme-accent: #9C7A28;
  --theme-text: #222222;
  --theme-muted: #666666;
  --theme-bg: #FDFCF7;
  --theme-card-bg: #FBF8F1;
  --theme-border: #E8DFCE;
}
```

---

### B. Azul Oxford y Pizarra Académica (`academic-oxford`)
Diseñado para monografías universitarias, historia crítica, filosofía y ensayos.
* **Azul Marino Oxford (`#0A2540`):** Autoridad, serenidad y rigor académico en títulos.
* **Pizarra Profunda (`#205493`):** Subtítulos y cabeceras de tablas.
* **Carmesí Universitario (`#9E2A2B`):** Acentos en viñetas y enlaces.
* **Negro Tinta (`#1F2421`):** Texto principal de máxima legibilidad.
* **Blanco Natural (`#FFFFFF`):** Fondo limpio, nítido y moderno.

```css
:root {
  --theme-primary: #0A2540;
  --theme-secondary: #205493;
  --theme-accent: #9E2A2B;
  --theme-text: #1F2421;
  --theme-muted: #555555;
  --theme-bg: #FFFFFF;
  --theme-card-bg: #F5F7FA;
  --theme-border: #DDE2E5;
}
```

---

### C. Editorial Monocromático Cálido (`editorial-minimalist`)
Diseñado para publicaciones contemporáneas, literatura moderna y manuales ejecutivos.
* **Negro Carbón (`#111111`):** Tipografía de alto contraste.
* **Grafito Medio (`#555555`):** Subtítulos y elementos secundarios.
* **Ocre Tostado (`#C07D38`):** Toque único de color para acentos puntuales.
* **Gris Niebla (`#F8F8F8`):** Cajas y tablas con bordes ultra-finos (`0.5pt solid #E0E0E0`).

---

### D. Renacimiento y Tierra Toscana (`renaissance-earth`)
Adecuado para biografías, ensayos literarios y humanidades.
* **Terracota / Siena Tostada (`#882D17`):** Títulos principales cálidos y literarios.
* **Nogal Profundo (`#4A2E1B`):** Subtítulos y llamadas de atención.
* **Verde Salvia (`#2E4A3D`):** Acentos botánicos/clásicos en divisores.
* **Crema Lino (`#FAF7F2`):** Fondo orgánico.

---

## 2. Pautas de Aplicación y Contraste WCAG AAA

1. **Relación de Contraste:** Todo texto sobre su fondo debe superar la relación de contraste **7:1** (Nivel AAA para texto normal) y **4.5:1** para encabezados en negrita mayores a 18pt.
2. **Cajas de Cita (`Blockquotes / Callouts`):**
   * El color de fondo debe tener una opacidad o tinte suave (luminosidad superior al 95%) para que la lectura del texto en su interior mantenga el 100% de nitidez.
   * La barra vertical de la izquierda debe tener un grosor entre `3px` y `4px`, funcionando como ancla visual rápida al escanear la página.
3. **Tablas Editoriales:**
   * La fila de encabezado (`thead th`) utiliza el color primario de fondo con texto en contraste claro, o una barra inferior gruesa de `1.5pt solid var(--theme-primary)`.
   * El rayado de cebra (*zebra striping*) utiliza alternancia con un 2% a 3% de saturación para no recargar visualmente la página.
