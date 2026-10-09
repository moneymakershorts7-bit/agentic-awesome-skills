Strategy for object counting challenges (count items in an image):

1. **Detect the counting challenge** using Evaluate:
   ```js
   document.title = JSON.stringify({
     prompt: document.querySelector('[class*=question], [class*=prompt], [class*=instruction]')?.textContent?.trim(),
     image: document.querySelector('[class*=challenge] img, [class*=count] img')?.getBoundingClientRect(),
     input: document.querySelector('input[type=number], input[type=text]')?.name,
     options: [...document.querySelectorAll('[class*=option], [class*=choice], button')].map(el => el.textContent?.trim())
   })
   ```
2. **Read the prompt**: "How many triangles?", "Count the dogs", "How many red objects?"
3. **Analyze the image carefully** from the screenshot. Count the target objects systematically
4. **Use a grid approach**: Mentally divide the image into quadrants and count in each section
5. **Enter the count** in the input field or select from multiple-choice options
6. **Double-check** by counting again from a different starting point before submitting

Key pitfalls:
- Objects may overlap or be partially hidden. Count carefully.
- The prompt may ask for a specific subset (only "red" apples, not all apples).
- Trick images may include objects that look similar but are not the target (dogs vs cats).
- Very small or partially hidden objects are easy to miss. Scan the entire image.
