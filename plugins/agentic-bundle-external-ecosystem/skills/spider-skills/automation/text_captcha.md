Strategy for distorted text / CAPTCHA challenges:

**After 2 failed attempts, STOP guessing and click the refresh button to get new text.**

1. Read the text from the screenshot. Common confusions: O↔D↔0, S↔5, I↔1↔L, Z↔2, B↔8, G↔6
2. Fill the input and submit. Track attempts in memory: `{"op":"set","key":"captcha_attempts","value":1}`
3. If wrong, try ONE alternative reading (swap most ambiguous character). Increment attempts.
4. If 2+ attempts fail, refresh the CAPTCHA:
   ```js
   const r = document.querySelector('[class*=refresh], [class*=reload], button svg');
   if (r) r.click(); else document.querySelectorAll('button').forEach(el => { if (el.innerHTML.includes('refresh') || el.innerHTML.includes('↻')) el.click(); });
   document.title = 'REFRESHED';
   ```
   Or click the ↻ icon near the CAPTCHA image via ClickPoint. Then read the NEW text fresh.
5. Never submit the same text twice.
