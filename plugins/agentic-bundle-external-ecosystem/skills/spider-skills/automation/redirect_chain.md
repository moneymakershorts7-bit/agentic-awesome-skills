Strategy for redirect chain handling:

1. **Detect redirect behavior** using Evaluate:
   ```js
   document.title = JSON.stringify({
     url: window.location.href,
     metaRefresh: document.querySelector('meta[http-equiv=refresh]')?.content,
     jsRedirect: document.body?.innerHTML?.includes('window.location') || document.body?.innerHTML?.includes('document.location'),
     countdown: document.querySelector('[class*=countdown], [class*=timer], [class*=redirect]')?.textContent?.trim(),
     continueLink: document.querySelector('a[class*=continue], a[class*=proceed], a[class*=skip]')?.href
   })
   ```
2. **If a "Continue" or "Skip" link exists**, click it to bypass the redirect wait
3. **For timed redirects**: Wait for the countdown, or use Evaluate to trigger immediately:
   ```js
   const meta = document.querySelector('meta[http-equiv=refresh]');
   if (meta) { const url = meta.content.match(/url=(.+)/i)?.[1]; if (url) window.location.href = url; }
   ```
4. **Track the redirect chain** in memory to detect loops (same URL appearing twice)
5. **For JavaScript-based redirects**: Let them execute naturally, or extract the target URL
6. **If stuck in a redirect loop**: Navigate directly to the target URL if known

Key pitfalls:
- Redirect loops can waste infinite rounds. Track visited URLs and break loops after 3 visits.
- Some redirects are through URL shorteners or tracking links. Follow the chain patiently.
- Meta refresh redirects may have long delays (5-30 seconds). Skip the wait if a direct link exists.
- JavaScript redirects may fail if execution is blocked. Use Navigate to go to the target directly.
