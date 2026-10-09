Strategy for address form completion challenges:

1. **Map all address fields** using Evaluate:
   ```js
   document.title = JSON.stringify({
     fields: [...document.querySelectorAll('input, select, textarea')].filter(el => el.offsetParent).map(el => ({
       name: el.name, id: el.id, type: el.type, label: el.labels?.[0]?.textContent?.trim(),
       placeholder: el.placeholder, required: el.required, autocomplete: el.autocomplete,
       options: el.tagName === 'SELECT' ? [...el.options].map(o => o.text).slice(0,5) : undefined
     }))
   })
   ```
2. **Identify field roles** by name, id, autocomplete attribute, or label:
   - street/address1, address2/apt, city, state/province, zip/postal, country
3. **Fill fields in order**: Start with country/state (they may trigger dependent dropdowns)
4. **For country/state dropdowns**: Select the value, then wait for dependent fields to update
5. **Handle address autocomplete**: If a Google Places or similar widget appears, select a suggestion
6. **Validate and submit**: Check for error messages before submitting

Key pitfalls:
- State/province dropdowns may only populate after country is selected. Fill country first.
- Zip/postal code format depends on country (US: 5 digits, UK: alphanumeric, etc.).
- Address autocomplete widgets may override manual input. Select from suggestions when they appear.
- Some forms split address into multiple lines (Address Line 1, Address Line 2).
