# Cheat Sheet: SSML, Brackets y Marcadores de Emoción TTS

Este documento resume las etiquetas y marcas de control sintáctico para los principales motores de síntesis de voz.

---

## 1. W3C & Microsoft Azure / Edge-TTS SSML

Soportado por Edge-TTS, Azure Speech Service, Amazon Polly y Google Cloud TTS.

```xml
<speak version="1.0" xmlns="http://www.w3.org/2001/10/synthesis"
       xmlns:mstts="https://www.w3.org/2001/mstts" xml:lang="es-ES">
  
  <!-- Selección de Voz -->
  <voice name="es-ES-ElviraNeural">
    
    <!-- Estilo Emocional (Azure/Edge TTS) -->
    <mstts:express-as style="cheerful" styledegree="1.5">
      ¡Qué gran noticia tenemos el día de hoy!
    </mstts:express-as>

    <!-- Pausa de respiración (Break) -->
    <break time="500ms" />

    <!-- Modulación de Prosodia (Velocidad, Tono, Volumen) -->
    <prosody rate="-10%" pitch="+3Hz" volume="+10%">
      Ahora escucha con atención los siguientes detalles.
    </prosody>

    <!-- Énfasis de palabra o frase -->
    <emphasis level="strong">Esto es fundamental.</emphasis>

    <!-- Fonética personalizada / Pronunciación exacta -->
    <phoneme alphabet="ipa" ph="ˈbaɪ.təs">Bytes</phoneme>

    <!-- Susurros -->
    <mstts:express-as style="whispering">
      Nadie más debe enterarse de esto...
    </mstts:express-as>

  </voice>
</speak>
```

### Estilos Emocionales en Azure / Edge Neural (`mstts:express-as`):
- `cheerful`: Alegre, optimista, brillante.
- `empathetic`: Empático, cálido, comprensivo.
- `calm`: Calmado, reflexivo, sereno.
- `whispering`: Susurrado, confidencial.
- `serious`: Serio, formal, solemne.
- `excited`: Emocionado, rápido, exaltado.
- `angry`: Tenso, cortante, enérgico.
- `sad`: Melancólico, pausado, débil.

---

## 2. Marcadores para ChatTTS (Conversational Brackets)

ChatTTS interpreta tokens en corchetes directamente en la cadena de texto:

| Token | Efecto Sonoro |
|---|---|
| `[laugh]` | Inserta una risa natural o risilla en ese punto del discurso |
| `[oral_0]` a `[oral_9]` | Nivel de vocalización coloquial, sonidos de garganta y carraspeo |
| `[break_0]` a `[break_7]` | Duración de la pausa (de micro-pausa rápida a silencio prolongado) |
| `[speed_0]` a `[speed_9]` | Aceleración o desaceleración puntual del habla |

**Ejemplo:**
```text
Hola a todos [laugh], no me van a creer lo que pasó hoy. [break_4] Llegué a la oficina y [oral_2] nadie sabía qué hacer.
```

---

## 3. Marcadores para Bark (Suno)

Bark utiliza anotaciones sencillas en texto:

| Marcador | Efecto |
|---|---|
| `[laughs]` / `[laughter]` | Risa o carcajada |
| `[sighs]` | Suspiro audible |
| `[gasps]` | Jadeo o sorpresa al inhalar |
| `[whispers]` | Transición a tono susurrado |
| `[clears throat]` | Aclarado de garganta / carraspeo |
| `...` | Pausa reflexiva |
| `MAYÚSCULAS` | Énfasis vocal / aumento de volumen e intensidad |
| `♪ música ♪` | Entonación musical o silbido |

---

## 4. Marcadores para ElevenLabs

ElevenLabs responde primariamente a la puntuación expresiva:

- `...` (3 puntos): Pausa vacilante de ~0.5 segundos con caída suave de tono.
- `—` (guion largo): Corte seco en la frase para introducir un matiz.
- `<break time="1.5s" />`: Silencio absoluto controlado (especialmente en Turbo v2 y v2.5).
- `(acotaciones)`: Por ejemplo `(riendo levemente)` o `(en voz baja)` condiciona el contexto semántico del generador autoregresivo.
