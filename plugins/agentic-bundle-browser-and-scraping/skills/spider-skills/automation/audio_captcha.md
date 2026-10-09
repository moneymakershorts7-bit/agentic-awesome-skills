Strategy for audio CAPTCHA challenges:

1. **Detect the audio CAPTCHA element** using Evaluate:
   ```js
   document.title = JSON.stringify({
     audioBtn: !!document.querySelector('[class*=audio], button[aria-label*=audio], [id*=audio]'),
     audioEl: !!document.querySelector('audio, [class*=player]'),
     inputEl: !!document.querySelector('input[type=text], input[id*=response]')
   })
   ```
2. **Click the audio/accessibility button** to switch from visual to audio mode if not already active
3. **Play the audio** by clicking the play button. The audio typically reads digits or words
4. **Listen and transcribe**: The agent cannot hear audio directly. Use Evaluate to check if the audio source URL is accessible, or look for a text fallback
5. **If no text fallback exists**, try the visual CAPTCHA instead, or look for an accessibility link
6. **Enter the transcribed text** and submit:
   ```js
   document.title = 'AUDIO_STATE:' + JSON.stringify({
     src: document.querySelector('audio')?.src?.slice(-50),
     input: document.querySelector('input[type=text]')?.value
   })
   ```

Key pitfalls:
- The agent cannot process audio directly. Prefer visual CAPTCHA when available.
- Audio CAPTCHAs often have background noise to prevent automated transcription.
- Some audio CAPTCHAs require pressing a "replay" button to hear again.
- Look for a download link to the audio file as a fallback.
