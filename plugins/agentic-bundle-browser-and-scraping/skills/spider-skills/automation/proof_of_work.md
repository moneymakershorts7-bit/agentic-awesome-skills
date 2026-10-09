Strategy for proof-of-work challenge pages:

1. **Detect proof-of-work challenges** using Evaluate:
   ```js
   document.title = JSON.stringify({
     pow: !!document.querySelector('[class*=pow], [class*=challenge], [id*=challenge]'),
     computing: !!document.querySelector('[class*=computing], [class*=solving], [class*=processing]'),
     progress: document.querySelector('[class*=progress], progress')?.value,
     script: [...document.querySelectorAll('script')].some(s => s.textContent?.includes('hashcash') || s.textContent?.includes('proof')),
     status: document.querySelector('[class*=status], [class*=message]')?.textContent?.trim(),
     waiting: !!document.querySelector('[class*=spinner], [class*=loading]')
   })
   ```
2. **Proof-of-work runs automatically** in the browser via JavaScript. Let it complete.
3. **Wait patiently**: PoW challenges may take 5-30 seconds of CPU computation
4. **Monitor progress** if a progress bar is shown. Do not navigate away during computation
5. **After completion**: The page should auto-redirect or show a success message
6. **If it fails or takes too long**: Reload the page to get a fresh challenge

Key pitfalls:
- Do not navigate away or refresh during PoW computation. This restarts the process.
- PoW challenges consume CPU. The browser may become sluggish during computation.
- Some PoW systems increase difficulty after repeated requests. Let them complete naturally.
- The challenge token is time-limited. If computation takes too long, you may need to restart.
