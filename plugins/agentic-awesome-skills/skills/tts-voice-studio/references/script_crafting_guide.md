# Guía Maestra de Guionizado para Síntesis de Voz Humana y Emotiva

## 1. El Principio de Oralidad vs. Texto Escrito

Los motores de Text-to-Speech (TTS), incluso los más avanzados basados en difusión o autoregresión (ElevenLabs, Kokoro, Edge-TTS), tienden a sonar monótonos o acartonados si reciben texto escrito con formato literario o formal. 

Para dotar a la voz sintética de naturalidad humana y emoción real, el texto debe transformarse en una **partitura de dicción**:

### Reglas de Oro de Oralidad:
1. **Oraciones cortas y respirables:** Los humanos no hablan en párrafos de 60 palabras sin respirar. Divide oraciones compuestas en ideas de 10 a 18 palabras.
2. **Puntuación elocuente:**
   - La coma (`,`) introduce una micro-pausa leve (~150ms).
   - Los puntos suspensivos (`...`) simulan pensamiento, reflexión o vacilación (~400-600ms).
   - El guion largo (`—`) o raya crea una ruptura abrupta de ritmo o suspenso (~350ms).
   - El punto y aparte obliga al motor a reiniciar la cadencia prosódica, evitando el tono plano continuo.
3. **Contracciones y partículas conversacionales:**
   - En lugar de *"No es posible que esto suceda"*, usa *"Es que... no hay manera de que esto pase"*.
   - Añade muletillas controladas (*"bueno"*, *"mira"*, *"la verdad"*, *"fíjate"*).
4. **Aliteraciones y palabras difíciles:** Sustituye trabalenguas técnicos o siglas por su versión fonética explícita (ej. en vez de *"API RESTful"*, redactar *"A-P-I Restful"* o usar etiquetas fonéticas).

---

## 2. Inyección Emocional por Arquetipo

| Arquetipo Emocional | Ritmo (Rate) | Tono (Pitch) | Puntuación Clave | Disparadores Vocales |
|---|---|---|---|---|
| **Cálido / Empático** | -5% a -10% | Ligeramente grave (-2Hz) | Puntos suspensivos, comas suaves | Sonrisas al inicio, vocales ligeramente prolongadas |
| **Dramático / Solemne** | -12% a -18% | Grave (-4Hz a -6Hz) | Guiones largos (`—`), pausas de 1s | Énfasis en sustantivos clave, silencios prolongados |
| **Entusiasta / Dinámico** | +10% a +18% | Agudo (+4Hz a +8Hz) | Signos de exclamación `!`, oraciones breves | Ataque rápido, articulación nítida |
| **Misterio / Suspenso** | -15% | Susurrado o medio-tono | `...` constantes, pausas tensas | Descenso de volumen, aire audible en fonación |
| **Autoritario / Corporativo** | 0% a -2% | Neutro-grave | Puntos seguidos, frases asertivas | Cierre tonal descendente, sin dudas |

---

## 3. Ejemplo Antes y Después (Transformación)

### Texto Crudo Original:
> *"La inteligencia artificial generativa ha transformado sustancialmente el panorama del desarrollo de software permitiendo a los ingenieros programar a velocidades sin precedentes y optimizar sus flujos de trabajo."*

### Guión Humanizado (Estilo Conversacional y Enérgico):
> *"Miren esto... La inteligencia artificial generativa ha cambiado las reglas del juego. Y no lo digo a la ligera. Hoy en día, cualquier ingeniero puede programar a un ritmo que hace dos años parecía pura ciencia ficción. ¿El resultado? Flujos de trabajo limpios, rápidos y sin fricción."*

### Guión Humanizado (Estilo Íntimo / Podcast Empático):
> *"Piénsalo por un momento... Todo lo que sabíamos sobre crear software... está cambiando ante nuestros ojos. Ya no se trata solo de escribir código... se trata de conectar ideas a una velocidad casi humana."*
