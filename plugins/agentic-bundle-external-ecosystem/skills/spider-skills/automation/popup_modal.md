Strategy for popup / modal dialog handling:

1. **Detect modals and popups** using Evaluate:
   ```js
   document.title = JSON.stringify({
     modals: [...document.querySelectorAll('[class*=modal], [role=dialog], [class*=overlay], [class*=popup]')].filter(el => {
       const s = getComputedStyle(el); return s.display !== 'none' && s.visibility !== 'hidden'
     }).map(el => ({
       cls: el.className?.slice(0,50), text: el.textContent?.trim()?.slice(0,80),
       close: !!el.querySelector('[class*=close], button[aria-label=close], [class*=dismiss]')
     })),
     backdrop: !!document.querySelector('[class*=backdrop], [class*=overlay]')
   })
   ```
2. **Read the modal content** to understand what it wants (newsletter signup, cookie consent, alert)
3. **Dismiss unwanted modals**: Click the close button (X), dismiss button, or press Escape
4. **For required modals** (accept terms, age gate): Complete the required action (click Accept, enter info)
5. **If close button is hidden**: Try clicking the backdrop/overlay, or use Evaluate to close:
   ```js
   document.querySelector('[class*=modal], [role=dialog]').style.display = 'none';
   document.querySelector('[class*=backdrop], [class*=overlay]').style.display = 'none';
   ```
6. **After dismissing**, verify the modal is gone and the page beneath is interactive

Key pitfalls:
- Modals may block interaction with the page behind them. Dismiss before proceeding.
- Some modals reappear after scrolling or time delay. Check for re-triggering.
- Clicking the backdrop may or may not close the modal depending on implementation.
- Escape key may not work if the modal captures keyboard events.
