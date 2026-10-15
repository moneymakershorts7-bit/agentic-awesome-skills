Strategy for Arkose Labs / FunCaptcha challenges:

1. **Detect Arkose/FunCaptcha** using Evaluate:
   ```js
   document.title = JSON.stringify({
     iframe: !!document.querySelector('iframe[src*=arkoselabs], iframe[src*=funcaptcha]'),
     container: !!document.querySelector('[id*=arkose], [id*=funcaptcha], [class*=arkose]'),
     enforcement: !!document.querySelector('[data-callback]')
   })
   ```
2. **Identify the challenge type**: FunCaptcha uses various game-like challenges:
   - Image rotation: Rotate the image to make it upright
   - Image matching: Select the image that matches a description
   - 3D object rotation: Rotate 3D objects to match a target
   - Tile matching: Select tiles with the same object
3. **For rotation challenges**: Click arrow buttons to rotate the image until it appears upright
4. **For matching challenges**: Read the instruction text and click the correct image
5. **Submit each round**: Click the Submit/Verify button after your selection
6. **Expect multiple rounds**: FunCaptcha typically requires 3-5 correct answers in sequence

Key pitfalls:
- FunCaptcha runs inside deeply nested iframes making DOM inspection difficult.
- Challenge images may be distorted or 3D-rendered, making visual analysis harder.
- Each round has a time limit - do not spend too long analyzing.
- Wrong answers reset the challenge counter. Accuracy matters more than speed.
- Look at the instruction text carefully each round as the task type may change.
