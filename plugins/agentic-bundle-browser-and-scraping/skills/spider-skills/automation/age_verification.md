Strategy for age verification gate challenges:

1. **Detect age gate elements** using Evaluate:
   ```js
   document.title = JSON.stringify({
     gate: !!document.querySelector('[class*=age], [class*=verify], [id*=age-gate]'),
     type: document.querySelector('input[type=date], input[name*=year], select[name*=year]') ? 'date_entry' :
           document.querySelector('button, a')?.textContent?.match(/yes|enter|21|18/i) ? 'button_click' : 'unknown',
     inputs: [...document.querySelectorAll('input, select')].filter(el => el.offsetParent).map(el => ({
       name: el.name, type: el.type, placeholder: el.placeholder
     })),
     buttons: [...document.querySelectorAll('button, a[class*=btn]')].map(el => el.textContent?.trim()?.slice(0,30))
   })
   ```
2. **For button-based gates**: Click "Yes, I am 21+" or "Enter" (not "No" or "Exit")
3. **For date entry gates**: Enter a valid date that makes the user old enough (e.g., 1990-01-01)
4. **For dropdown-based**: Select valid month, day, and year values indicating age 21+
5. **Click the Submit/Enter button** after entering the date
6. **Verify the gate is dismissed** and content is accessible

Key pitfalls:
- Age gates typically require the user to be 18 or 21 depending on the content type.
- Entering a date too recent will fail. Use a birth year at least 25 years ago.
- Some gates remember the choice via cookies. Clearing cookies resets the gate.
- The "No/Exit" button may redirect to another site entirely. Always click the affirmative option.
