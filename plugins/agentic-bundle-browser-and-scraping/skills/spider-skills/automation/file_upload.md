Strategy for file upload dialog challenges:

1. **Detect the file upload element** using Evaluate:
   ```js
   document.title = JSON.stringify({
     fileInput: document.querySelector('input[type=file]')?.outerHTML?.slice(0,100),
     accept: document.querySelector('input[type=file]')?.accept,
     multiple: document.querySelector('input[type=file]')?.multiple,
     dropzone: !!document.querySelector('[class*=dropzone], [class*=drop-area], [class*=upload-area]'),
     button: document.querySelector('[class*=upload] button, button[class*=upload]')?.textContent?.trim()
   })
   ```
2. **For standard file inputs**: The agent can use the Upload action to attach files if available
3. **For drag-and-drop zones**: Look for the underlying file input element which is often hidden
4. **Trigger the file input programmatically** via Evaluate if needed:
   ```js
   const input = document.querySelector('input[type=file]');
   // Cannot programmatically set files for security reasons, but can trigger click
   input.click();
   ```
5. **Check accepted file types** from the accept attribute before attempting upload
6. **After upload, verify** the file appears in the upload preview/list

Key pitfalls:
- Browsers prevent programmatic file setting on input[type=file] for security.
- The actual file input may be hidden (opacity:0, position:absolute) behind a styled button.
- Drag-and-drop uploads may require dispatching DragEvent sequences.
- File size limits may reject large files silently. Check for max-size attributes.
