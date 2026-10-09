Strategy for reCAPTCHA audio fallback challenges:

1. **Switch to audio mode** by clicking the headphone/audio icon in the reCAPTCHA widget
2. **Detect the audio challenge state** using Evaluate:
   ```js
   document.title = JSON.stringify({
     audioButton: !!document.querySelector('#recaptcha-audio-button, [class*=rc-audiochallenge]'),
     audioSrc: document.querySelector('audio')?.src?.slice(-60),
     downloadLink: document.querySelector('a[class*=rc-audiochallenge-tdownload]')?.href?.slice(-60),
     responseInput: document.querySelector('#audio-response, input[class*=response]')?.value,
     verifyBtn: !!document.querySelector('#recaptcha-verify-button')
   })
   ```
3. **The audio plays spoken digits or words**. Since the agent cannot hear audio, try alternative approaches
4. **Check if a download link exists** for the audio file. The audio URL may be extractable
5. **If audio approach fails**: Switch back to the image challenge mode by clicking the image icon
6. **Enter any transcription attempt** and click Verify. The challenge will provide a new audio if wrong

Key pitfalls:
- The agent cannot directly process audio. This is a significant limitation for audio CAPTCHAs.
- Audio challenges are generally harder than image challenges. Prefer the image mode when possible.
- Multiple failed attempts on audio may trigger a harder challenge or temporary lockout.
- The audio typically says a sequence of digits. Common digits: 1-9.
