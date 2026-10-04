# Herramientas de Voz de Pago y Comerciales (Hosted APIs)

Guía completa para utilizar motores de voz comerciales cuando se requiere clonación de voz instantánea de máxima fidelidad, personalización actoral extrema o latencia inferior a 100 milisegundos.

---

## 1. ElevenLabs (Turbo v2.5 / Multilingual v2 / v3)

El estándar de oro de la industria para narraciones audibles, doblaje cinematográfico y clonación de voz ultrarrealista.

### Precios y Modelos:
- **Modelos:**
  - `eleven_multilingual_v2`: Máxima fidelidad expresiva en más de 29 idiomas.
  - `eleven_turbo_v2_5`: Latencia ultra-baja (~250ms) con alta calidad.
- **Coste:** Aprox. $0.30 - $0.50 USD por cada 10.000 caracteres (según plan).

### Parámetros Clave para Emoción Humana:
1. **Stability (Estabilidad):**
   - Rango: `0.0` a `1.0`
   - *Valores recomendados:* `0.30 - 0.45` para interpretaciones emotivas, dinámicas o conversacionales. `0.70 - 0.85` para tono informativo, formal o noticias.
2. **Similarity Boost (Fidelidad de Voz):**
   - Rango: `0.0` a `1.0`
   - *Valores recomendados:* `0.75 - 0.85`. Un valor demasiado alto (>0.90) puede reintroducir artefactos del audio original.
3. **Style Exaggeration (Exageración de Estilo):**
   - Rango: `0.0` a `1.0`
   - Amplifica los rasgos dramáticos del hablante original. Recomendado en `0.10 - 0.25` para podcasts enérgicos.

### Trucos de Guion para ElevenLabs:
- **Pausas explícitas:** Soporta etiquetas `<break time="1.5s" />`.
- **Intención tonal:** Si deseas susurros, coloca el texto entre paréntesis o redacta la acotación antes de la frase: `(susurrando) No hagas ruido...`.
- **Mayúsculas para énfasis:** Escribir palabras completas en mayúsculas (`INCREÍBLE`) aumenta la intensidad vocal.

---

## 2. Cartesia Sonic

Motor basado en arquitecturas SSM (State Space Models / Mamba) diseñado específicamente para agentes en tiempo real.

- **Latencia:** Primera palabra en ~90ms a 130ms (la más rápida del mercado).
- **Precio:** ~$0.05 a $0.08 por cada 1.000 caracteres.
- **Uso ideal:** Llamadas telefónicas, asistentes interactivos con interrupción en vivo.
- **Control emocional:** Permite inyectar vectores emocionales (alegría, enfado, tristeza) en el payload JSON.

---

## 3. OpenAI TTS (`tts-1`, `tts-1-hd`, `gpt-4o-audio`)

Motor integrado en la plataforma de OpenAI con 6 voces predeterminadas: `alloy`, `echo`, `fable`, `onyx`, `nova`, `shimmer`.

- **Latencia:** Media (~300-500ms).
- **Precio:**
  - `tts-1`: $0.015 / 1.000 caracteres.
  - `tts-1-hd`: $0.030 / 1.000 caracteres.
- **Peculiaridad:** No admite SSML granular ni sliders de estabilidad. La emoción se guía íntegramente por:
  - Signos de puntuación (`!`, `?`, `...`).
  - Contexto semántico del párrafo.
  - Elección de voz (`nova` y `shimmer` tienden a ser más enérgicas/expresivas; `onyx` y `echo` más graves y sobrias).

---

## 4. Deepgram Aura

Motor de TTS de alto rendimiento diseñado para integrarse con el reconocedor de voz Deepgram Nova.

- **Precio:** $0.015 / 1.000 caracteres.
- **Enfoque:** Conversacional y fluido. Excelente para manejar interrupciones en pipelines con LiveKit o Pipecat.

---

## 5. PlayHT 2.0 (PlayDialog)

- **Precio:** ~$0.08 / 1.000 palabras.
- **Enfoque:** Diálogo entre múltiples personajes, control explícito de emociones mediante presets (`happy`, `sad`, `fear`, `anger`, `whisper`).
