Strategy for multi-step form wizard challenges:

1. **Detect the form wizard state** using Evaluate:
   ```js
   document.title = JSON.stringify({
     steps: [...document.querySelectorAll('[class*=step], [class*=progress] > *, [role=tablist] > *')].map((el,i) => ({
       i, text: el.textContent?.trim()?.slice(0,20), active: el.classList.contains('active') || el.getAttribute('aria-selected')==='true'
     })),
     currentFields: [...document.querySelectorAll('input:not([type=hidden]), select, textarea')].filter(el => el.offsetParent !== null).map(el => ({
       name: el.name, type: el.type, required: el.required, value: el.value, label: el.labels?.[0]?.textContent?.trim()
     })),
     nextBtn: document.querySelector('[class*=next], button[type=submit], [class*=continue]')?.textContent?.trim()
   })
   ```
2. **Fill all required fields** on the current step before clicking Next
3. **Validate each step** - watch for error messages appearing after clicking Next
4. **Track progress** through the step indicators. Store completed steps in memory
5. **Handle back navigation** - if you need to correct a previous step, use the Back button
6. **On the final step**, review the summary (if shown) before clicking Submit

Key pitfalls:
- Clicking Next without filling required fields may show validation errors without advancing.
- Some wizards lose data if you navigate away. Complete each step fully.
- Hidden fields on inactive steps are not visible. Only fill fields on the current step.
- Progress indicators may be clickable for direct step navigation.
