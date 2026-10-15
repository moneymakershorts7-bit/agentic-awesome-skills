Strategy for device verification / trusted device challenges:

1. **Detect device verification prompts** using Evaluate:
   ```js
   document.title = JSON.stringify({
     prompt: document.querySelector('[class*=verify], [class*=device], [class*=trust]')?.textContent?.trim()?.slice(0,100),
     codeInput: !!document.querySelector('input[name*=code], input[class*=otp], input[class*=verification]'),
     methods: [...document.querySelectorAll('[class*=method], [class*=option]')].map(el => el.textContent?.trim()),
     email: document.querySelector('[class*=email], [class*=masked]')?.textContent?.trim(),
     phone: document.querySelector('[class*=phone], [class*=sms]')?.textContent?.trim(),
     resend: !!document.querySelector('button[class*=resend], a[class*=resend]')
   })
   ```
2. **Identify the verification method**: Email code, SMS code, authenticator app, push notification
3. **If a code input is shown**: Enter the verification code when available
4. **For "Trust this device" checkbox**: Check it to avoid future verifications
5. **Click "Send Code" or "Resend"** if no code has been sent yet
6. **If unable to verify**: Look for alternative methods (backup codes, security questions)

Key pitfalls:
- The agent cannot receive SMS or email codes externally. These require external input.
- OTP inputs may be split into individual digit fields. Fill each field separately.
- Verification codes typically expire after 5-10 minutes.
- "Trust this device" settings are cookie-based and cleared with cookie deletion.
