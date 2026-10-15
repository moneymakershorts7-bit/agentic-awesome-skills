Strategy for browser fingerprint challenge detection:

1. **Detect fingerprinting scripts** using Evaluate:
   ```js
   document.title = JSON.stringify({
     canvas: !!HTMLCanvasElement.prototype.toDataURL,
     webgl: !!document.createElement('canvas').getContext('webgl'),
     audioContext: !!window.AudioContext || !!window.webkitAudioContext,
     fonts: !!document.fonts,
     plugins: navigator.plugins?.length,
     languages: navigator.languages,
     platform: navigator.platform,
     hardwareConcurrency: navigator.hardwareConcurrency,
     deviceMemory: navigator.deviceMemory,
     touchPoints: navigator.maxTouchPoints,
     fpScripts: [...document.querySelectorAll('script[src]')].map(s => s.src).filter(s =>
       /fingerprintjs|fpjs|clientjs/i.test(s)
     )
   })
   ```
2. **Fingerprint challenges verify browser consistency**. Do not modify browser properties between pages
3. **If a challenge page appears**: Wait for it to complete its fingerprint collection automatically
4. **Do not block or modify** canvas, WebGL, or AudioContext APIs - this makes the fingerprint suspicious
5. **Maintain consistent behavior**: Same user agent, same viewport size, same timezone throughout
6. **If stuck on a fingerprint challenge**: Reload the page and wait for automatic verification

Key pitfalls:
- Fingerprint inconsistencies (mismatched platform and user agent) trigger blocks.
- Some fingerprint challenges run silently and redirect on completion.
- Canvas fingerprinting, WebGL rendering, and font enumeration are common techniques.
- Blocking fingerprint collection scripts often causes the challenge to fail permanently.
