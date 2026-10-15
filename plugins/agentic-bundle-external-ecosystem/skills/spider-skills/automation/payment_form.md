Strategy for payment form challenges:

1. **Identify payment form fields** using Evaluate:
   ```js
   document.title = JSON.stringify({
     fields: [...document.querySelectorAll('input, select')].filter(el => el.offsetParent).map(el => ({
       name: el.name, id: el.id, type: el.type, placeholder: el.placeholder,
       autocomplete: el.autocomplete, iframe: false, maxLength: el.maxLength
     })),
     iframes: [...document.querySelectorAll('iframe')].map(el => ({
       name: el.name, src: el.src?.slice(0,60), title: el.title, cls: el.className
     })),
     stripeEl: !!document.querySelector('[class*=StripeElement], [class*=stripe]')
   })
   ```
2. **Detect payment processor**: Stripe, Braintree, PayPal, Square embed fields in iframes
3. **For iframe-embedded fields** (Stripe Elements): Fields are inside separate iframes. Click inside the iframe area and type
4. **Standard fields**: Card number, expiry (MM/YY), CVV/CVC, cardholder name
5. **Format card number** with spaces every 4 digits if the field expects them
6. **After filling all fields**, click the Pay/Submit button

Key pitfalls:
- Stripe/Braintree card fields are inside iframes. Direct Fill won't work on them. Click and Type instead.
- Card number fields may auto-format with spaces. Type digits only and let the field format.
- Expiry field may be one field (MM/YY) or two separate fields (month and year dropdowns).
- CVV is 3 digits for most cards, 4 for Amex. Check the expected length.
