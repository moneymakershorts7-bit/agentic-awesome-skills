Strategy for web form auto-fill challenges:

1. **Map all form fields** using Evaluate:
   ```js
   document.title = JSON.stringify({
     forms: [...document.querySelectorAll('form')].map(f => ({
       action: f.action?.slice(-50), method: f.method,
       fields: [...f.querySelectorAll('input:not([type=hidden]), select, textarea')].map(el => ({
         name: el.name, type: el.type, autocomplete: el.autocomplete,
         label: el.labels?.[0]?.textContent?.trim(), required: el.required,
         placeholder: el.placeholder, value: el.value?.slice(0,20)
       }))
     }))
   })
   ```
2. **Use autocomplete attributes** to understand field purposes: name, email, tel, street-address, etc.
3. **Fill fields systematically**: Start from top, fill each field with appropriate data
4. **For dropdowns and selects**: Choose the first valid option or the one matching requirements
5. **Handle interdependent fields**: Fill parent fields first (country before state)
6. **Submit when all required fields are filled** - check for remaining validation errors

Key pitfalls:
- Browser auto-fill may conflict with programmatic filling. Clear fields before filling.
- Some fields validate in real-time and show errors immediately. Address errors as they appear.
- Hidden fields (type=hidden) contain form tokens. Do not modify them.
- Multi-page forms require filling and submitting each page sequentially.
