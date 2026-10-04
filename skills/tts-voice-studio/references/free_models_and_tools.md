# Herramientas y Modelos de Voz Gratuitos y Open Source

Esta guía detalla los motores de Text-to-Speech (TTS) gratuitos y de código abierto más avanzados disponibles, con instrucciones de instalación, uso y cómo extraer la máxima emotividad.

---

## 1. Microsoft Edge TTS (`edge-tts`) [100% Gratuito - Recomendado Nivel 1]

Accede a las voces neuronales de Azure Speech utilizadas por el lector inmersivo de Edge sin costo, sin clave de API y sin límites restrictivos.

- **Tipo:** API en la nube pública directa (Fair use).
- **Calidad:** Grado comercial de producción (24kHz / 48kHz neural).
- **Voces:** Más de 400 voces en más de 100 idiomas y dialectos.
- **Instalación:**
  ```bash
  uv tool install edge-tts
  # O con pip:
  pip install edge-tts
  ```
- **Comandos canónicos:**
  ```bash
  # Sintetizar texto con voz española masculina profunda:
  edge-tts --voice es-ES-AlvaroNeural --text "Hola mundo" --write-media audio.mp3

  # Modificar velocidad y tono:
  edge-tts --voice es-MX-DaliaNeural --rate="+10%" --pitch="+4Hz" --text "¡Bienvenidos al podcast!" --write-media intro.mp3

  # Listar todas las voces disponibles:
  edge-tts --list-voices
  ```
- **Voces destacadas recomendadas:**
  - **Español:** `es-ES-AlvaroNeural` (narrador documental), `es-ES-ElviraNeural` (cálida, audiolibros), `es-MX-DaliaNeural` (dinámica, comercial), `es-MX-JorgeNeural` (autoritario corporativo).
  - **Inglés:** `en-US-JennyNeural` (altamente expresiva), `en-US-GuyNeural` (noticias / narración clásica), `en-US-AriaNeural` (dinámica y conversacional), `en-GB-RyanNeural` (británico accesible).

---

## 2. Kokoro-82M [SOTA Local Open Source - Recomendado Nivel 2]

El modelo open source más ligero y de mayor calidad del ecosistema actual (82 millones de parámetros, licencia Apache 2.0).

- **Puntos clave:**
  - Corre en tiempo real incluso en CPU convencional (sin requerir GPU dedicada).
  - Fidelidad vocal y cadencia que compiten directamente con modelos comerciales de más de 1.000 millones de parámetros.
  - Soporte multilingüe (inglés, español, francés, japonés, chino).
- **Instalación rápida en Python:**
  ```bash
  pip install kokoro soundfile onnxruntime
  ```
- **Uso en Python:**
  ```python
  from kokoro import KPipeline
  import soundfile as sf

  pipeline = KPipeline(lang_code='e') # 'e' para español, 'a' para inglés americano
  text = "La inteligencia artificial ya no suena como un robot... Suena como nosotros."
  generator = pipeline(text, voice='em_alex', speed=1.0)
  for i, (gs, ps, audio) in enumerate(generator):
      sf.write(f'kokoro_output_{i}.wav', audio, 24000)
  ```

---

## 3. ChatTTS [Conversacional Especializado con Risa y Pausas]

Modelo open source diseñado específicamente para diálogos naturales, podcasts y agentes conversacionales.

- **Capacidades únicas:**
  - Soporta inserción de risas espontáneas mediante el token `[laugh]`.
  - Inserción de respiraciones y pausas de vacilación oral (`[oral_1]`, `[oral_2]`, `[break_4]`).
  - Control de velocidad dinámico en mitad de la frase (`[speed_5]`).
- **Instalación:**
  ```bash
  pip install ChatTTS torch
  ```
- **Ejemplo con Marcadores Emocionales:**
  ```python
  import ChatTTS
  import torch

  chat = ChatTTS.Chat()
  chat.load(compile=False) # Cargar pesos

  text = "Oye [laugh] ¿de verdad pensaste que eso iba a funcionar? [break_4] Bueno, al final... todo salió bien."
  wavs = chat.infer(text)
  ```

---

## 4. Piper TTS [Ultra Ligero para Sistemas Embebidos / Raspberry Pi]

Motor local desarrollado en C++ y ONNX por Nabu Casa (Home Assistant).

- **Velocidad:** Genera audio 10x más rápido que el tiempo real en CPUs modestas.
- **Consumo de memoria:** Menos de 50 MB de RAM.
- **Uso ideal:** Robótica, domótica, sistemas offline sin conexión a internet.
- **CLI de uso:**
  ```bash
  echo "Luces de la sala encendidas." | piper --model es_ES-davefx-medium.onnx --output_file alerta.wav
  ```

---

## 5. Bark (Suno) y Parler-TTS [Actuación Dramática y Efectos]

Modelos basados en transformers y difusión acústica capaces de generar ruidos no verbales extremos (llanto, suspiros, risas, música de fondo).

- **Bark:** Permite prompts enriquecidos con `[sighs]`, `[gasps]`, `[laughs]`, `[screams]`.
- **Parler-TTS:** Permite condicionar la voz con un prompt en lenguaje natural, por ejemplo:
  > *"A male speaker speaks with an excited, high-pitched tone in a small resonant room with crisp sound."*
