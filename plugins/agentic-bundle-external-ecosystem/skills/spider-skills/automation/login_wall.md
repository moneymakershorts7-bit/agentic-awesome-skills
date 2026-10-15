Strategy for login wall / authentication gate challenges:

1. **Detect the login wall** using Evaluate:
   ```js
   document.title = JSON.stringify({
     form: !!document.querySelector('form[class*=login], form[action*=login], form[action*=signin]'),
     fields: [...document.querySelectorAll('input')].filter(el => el.offsetParent).map(el => ({
       name: el.name, type: el.type, placeholder: el.placeholder, autocomplete: el.autocomplete
     })),
     social: [...document.querySelectorAll('button[class*=google], button[class*=facebook], a[class*=oauth]')].map(el => el.textContent?.trim()),
     signup: !!document.querySelector('a[href*=register], a[href*=signup]'),
     guest: !!document.querySelector('a[class*=guest], button[class*=skip], [class*=continue-without]')
   })
   ```
2. **Look for a "Continue as Guest" or "Skip" option** first - this avoids needing credentials
3. **If credentials are required**: Fill the username/email and password fields, then submit
4. **For social login**: Click the appropriate OAuth button (Google, Facebook, etc.)
5. **Handle 2FA/MFA**: If a second factor is requested, look for a code input field
6. **Detect success**: Check if the URL changed or the login form disappeared after submission

Key pitfalls:
- Login walls block access to content behind them. No way around without valid credentials.
- Social login buttons open popups that need separate handling.
- Some login forms use AJAX and don't navigate - check for success/error messages in place.
- Rate limiting may lock out after multiple failed attempts.
