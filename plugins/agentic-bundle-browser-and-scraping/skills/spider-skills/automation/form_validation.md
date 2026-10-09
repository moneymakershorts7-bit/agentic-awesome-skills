Strategy for form validation handling:

1. **Detect validation errors** using Evaluate:
   ```js
   document.title = JSON.stringify({
     errors: [...document.querySelectorAll('[class*=error], [class*=invalid], [role=alert], .field-error')].map(el => ({
       text: el.textContent?.trim(), field: el.closest('[class*=field], [class*=group]')?.querySelector('input,select')?.name
     })),
     invalidFields: [...document.querySelectorAll(':invalid, [aria-invalid=true], [class*=invalid]')].map(el => ({
       name: el.name, type: el.type, value: el.value?.slice(0,20), msg: el.validationMessage
     })),
     required: [...document.querySelectorAll('[required], [aria-required=true]')].filter(el => !el.value).map(el => el.name)
   })
   ```
2. **Read each error message** to understand what needs to be fixed
3. **Fix validation errors** one at a time:
   - Required fields: Fill in missing values
   - Format errors: Correct email, phone, URL formats
   - Length errors: Adjust text to meet min/max length
4. **Clear the field before re-entering**: Some validation caches old values
5. **Re-submit the form** after fixing all errors
6. **Check for JavaScript validation** that prevents submission without proper field states

Key pitfalls:
- Validation may be client-side (instant) or server-side (after submit). Handle both.
- Error messages may appear as tooltips, inline text, or at the top of the form.
- Fixing one error may reveal new ones that were previously hidden.
- Some forms validate on blur (leaving a field), others only on submit.
