Strategy for OTP (One-Time Password) input challenges:

1. **Detect OTP input fields** using Evaluate:
   ```js
   document.title = JSON.stringify({
     inputs: [...document.querySelectorAll('input[class*=otp], input[class*=code], input[class*=pin], input[name*=otp]')].map((el,i) => ({
       i, name: el.name, maxLength: el.maxLength, value: el.value, type: el.type,
       autoComplete: el.autocomplete, rect: el.getBoundingClientRect()
     })),
     singleInput: !!document.querySelector('input[maxlength="6"], input[maxlength="4"]'),
     splitInputs: document.querySelectorAll('input[maxlength="1"][class*=otp], input[maxlength="1"][class*=code]').length,
     resend: document.querySelector('button[class*=resend], a[class*=resend]')?.textContent?.trim(),
     timer: document.querySelector('[class*=timer], [class*=countdown]')?.textContent?.trim()
   })
   ```
2. **For single input field**: Type all digits at once (e.g., "123456")
3. **For split inputs** (one digit per box): Click each box and type one digit, or type in first box and let auto-advance handle the rest
4. **Auto-advance**: Most OTP UIs move focus to the next input after typing a digit
5. **If pasting is supported**: Paste the full code into the first input
6. **Handle backspace**: If you need to correct a digit, press Backspace to clear and re-enter

Key pitfalls:
- Split OTP inputs auto-advance focus. Type each digit individually in the focused input.
- Some OTP UIs prevent pasting. Type digits one at a time instead.
- OTP codes expire quickly (30-120 seconds). Enter promptly.
- Resend buttons may have cooldown timers. Wait for the timer to expire before resending.
