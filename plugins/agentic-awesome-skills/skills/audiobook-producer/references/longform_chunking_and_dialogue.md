# Segmentación de Libros Extensos y Extracción de Diálogos

La síntesis de audiolibros completos (de 10.000 a 100.000 palabras) requiere una estrategia rigurosa de segmentación y limpieza para evitar desconexiones de red, pérdida de memoria en modelos locales o artefactos vocales.

---

## 1. Reglas de Limpieza de Texto (Sanitización Auditiva)

Al convertir un libro escrito o digital (Markdown / PDF / DOCX) a voz hablada, se deben aplicar las siguientes reglas automáticas:

1. **Citas y notas al pie:**
   - Eliminar marcadores numéricos como `[1]`, `[14]`, `[^2]`. En lectura hablada suenan como números inconexos.
   - En libros académicos, si una nota es crítica, integrarla como inciso conversacional: *"Como señala el autor en sus notas complementarias..."*.
2. **Tablas y listas densas:**
   - No leer tablas celda por celda. Convertirlas en un resumen narrativo de los datos clave.
3. **Enlaces y URLs:**
   - Suprimir cadenas `http://...` o `[título](enlace)`. Conservar únicamente el texto descriptivo.
4. **Acotaciones entre paréntesis:**
   - Los paréntesis técnicos `(1844 d.C.)` deben leerse como *"en el año mil ochocientos cuarenta y cuatro de nuestra era"*.

---

## 2. Heurística de Detección de Diálogo

Un bloque de texto se clasifica como diálogo si cumple cualquiera de las siguientes condiciones:
- Comienza o termina con comillas tipográficas (`"..."`, `«...»`, `“...”`).
- Comienza con raya de diálogo (`—`).
- Contiene marcadores de atribución (`—dijo él`, `—exclamó ella`).

### Inyección de Contraste Prosódico:
- **Narrador:** Velocidad moderada, cadencia regular, timbre base.
- **Diálogo Masculino Secundario:** Modulación de tono -2Hz a -4Hz.
- **Diálogo Femenino Secundario:** Modulación de tono +3Hz a +5Hz o cambio a voz alternativa (`es-ES-ElviraNeural`, `en-US-JennyNeural`).
- **Pausa de cambio de hablante:** 400ms a 600ms antes y después de cada turno conversacional.
