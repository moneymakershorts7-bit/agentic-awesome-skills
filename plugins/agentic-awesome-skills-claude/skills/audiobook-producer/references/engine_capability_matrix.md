# Matriz de Capacidades por Modelo y Motor TTS

Esta matriz detalla cómo cada motor procesa audiolibros, sus límites máximos de fragmentación segura y sus mecanismos óptimos de inyección emocional.

---

## Comparativa Técnica para Producción de Audiolibros

| Motor / Modelo | Tipo | Límite por Chunk | Control de Emoción | Manejo de Diálogos | Coste x 100k palabras (~10h) |
|---|---|---|---|---|---|
| **Microsoft Edge-TTS** | Gratuito / Cloud | ~1.800 caracteres | SSML W3C `<mstts:express-as style="...">`, prosody rate/pitch | Etiquetas `<voice name="...">` alternadas por personaje | **$0.00** |
| **Kokoro-82M** | Gratuito / Local (CPU) | ~1.500 caracteres | Puntuación expandida (`...`), elipses prosódicas | Mezcla de voces locales por segmento | **$0.00** |
| **ChatTTS** | Gratuito / Local | ~1.000 caracteres | Tokens de risa `[laugh]`, pausas `[break_4]`, respiración `[oral_2]` | Tokens de estilo conversacional espontáneo | **$0.00** |
| **ElevenLabs Turbo/Multi** | De Pago / Hosted | ~3.000 caracteres | Control de *Stability* (0.35 diálogo / 0.65 narrador), `<break time="..."/>` | Mapeo de Voice IDs por personaje (Voice Design) | **~$20 - $35 USD** |
| **OpenAI TTS (tts-1-hd)** | De Pago / Hosted | ~2.000 caracteres | Inferencia semántica por contexto y signos `!`, `?`, `...` | Asignación de voces (`onyx`, `nova`, `fable`) | **~$20 USD** |

---

## Estrategia de Adaptación Dinámica

1. **Cuando el objetivo es Edge-TTS (Gratuito):**
   - El script se empaqueta en formato XML/SSML estándar con pausas de 300ms entre oraciones y 1200ms tras los títulos.
   - Alterna voces como `es-ES-AlvaroNeural` para narración general y `es-ES-ElviraNeural` para personajes femeninos o reflexiones líricas.

2. **Cuando el objetivo es Kokoro-82M (Open Source Local):**
   - El script normaliza números ordinales ("Capítulo V" a "Capítulo Cinco").
   - Las frases se espacian con comas y elipses para permitir que el vocoder respire de forma orgánica.

3. **Cuando el objetivo es ElevenLabs (Comercial / De Pago):**
   - Se inyectan directivas de acotación dramática y etiquetas `<break time="1.5s" />` en transiciones de escena.
   - Se ajusta la estabilidad según el tipo de bloque (más baja para emociones intensas, más alta para explicaciones históricas o técnicas).
