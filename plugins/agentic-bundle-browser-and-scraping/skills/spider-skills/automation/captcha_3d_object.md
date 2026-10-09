Strategy for 3D object CAPTCHA challenges (rotate 3D object, identify angle):

1. **Detect the 3D challenge** using Evaluate:
   ```js
   document.title = JSON.stringify({
     canvas: document.querySelector('canvas')?.getBoundingClientRect(),
     webgl: !!document.querySelector('canvas')?.getContext('webgl'),
     controls: [...document.querySelectorAll('button, [class*=arrow], [class*=rotate]')].map(el => ({
       text: el.textContent?.trim() || el.title, cls: el.className?.slice(0,30), rect: el.getBoundingClientRect()
     })),
     instruction: document.querySelector('[class*=instruction], [class*=prompt]')?.textContent?.trim(),
     options: [...document.querySelectorAll('[class*=option], [class*=choice]')].map(el => el.textContent?.trim())
   })
   ```
2. **Read the instruction**: "Rotate to match the target", "What is this object?", "Select the matching view"
3. **For rotation challenges**: Use arrow buttons or drag on the canvas to rotate the 3D object
4. **For identification**: Analyze the 3D rendering from the screenshot to identify the object
5. **For matching**: Compare the 3D view to provided options and select the correct match
6. **Submit** after achieving the target orientation or making the selection

Key pitfalls:
- 3D objects render on canvas/WebGL. No DOM elements represent the object itself.
- Rotation may use mouse drag on the canvas (click and drag to orbit).
- 3D renders may look different from 2D images. Consider perspective and shading.
- Multiple correct orientations may exist. Match the specific target angle shown.
