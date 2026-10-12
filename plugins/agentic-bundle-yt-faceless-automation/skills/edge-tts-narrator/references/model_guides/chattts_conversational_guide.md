# ChatTTS: Conversational Disfluency & Natural Speech Guide 🎙️🗣️

**ChatTTS** is an open-source neural generative speech model designed specifically for conversational dialogue. Unlike traditional TTS models that aim for clean, sterile broadcast delivery, ChatTTS natively synthesizes **laughter, sighs, interjections, hesitations, and breath pauses**.

---

## 1. Conversational Token Syntax

ChatTTS parses specialized bracket tokens inline to control conversational prosody:

| Token | Type | Acoustic Effect |
| :--- | :--- | :--- |
| `[laugh]` / `[laugh_0]` ... `[laugh_2]` | Laughter | Injects spontaneous laughter into speech |
| `[oral_0]` ... `[oral_9]` | Disfluency | Natural conversational throat pauses, filler sounds, lip smacks |
| `[break_0]` ... `[break_7]` | Silence Gap | Micro-pause scaling from 100ms (`[break_0]`) to 1200ms (`[break_7]`) |

### Example Conversational Prompt:
```text
"So we ran the benchmark [laugh_1] and you won't believe what happened. [break_2] The GPU temperature dropped by fifteen degrees! [oral_2] Absolutely wild."
```

---

## 2. Speaker Seed Locking & Timbre Consistency

Because ChatTTS is fully generative, running inference without an explicit speaker vector results in a different random voice on every call.

```python
import ChatTTS
import torch

chat = ChatTTS.Chat()
chat.load_models()

# Lock deterministic speaker timbre using an integer seed
torch.manual_seed(4281)
speaker_rand_spk = chat.sample_random_speaker()

# Configure inference parameters
params_infer_code = {
    'spk_emb': speaker_rand_spk,
    'temperature': 0.3, # Lower temperature = higher stability and fewer stuttering artifacts
    'top_P': 0.7,
    'top_K': 20
}

params_refine_text = {
    'prompt': '[oral_2][laugh_0][break_4]'
}

text = "Hello! [laugh_1] Welcome back to the laboratory. Today we test quantum entanglement."
wavs = chat.infer([text], params_refine_text=params_refine_text, params_infer_code=params_infer_code)
```

---

## 3. Best Practices & Pitfalls

- **Temperature Tuning:** Keep `temperature` between `0.2` and `0.4` for coherent narration. Temperatures above `0.6` cause phoneme collapse and excessive slurring.
- **Text Normalization:** ChatTTS performs better with clean ASCII/UTF-8 and spelled-out numerals.
- **Audio Post-Processing:** ChatTTS emits 24 kHz audio with occasional low-frequency rumble; always apply a high-pass filter at 80 Hz and EBU R128 loudness normalization.
