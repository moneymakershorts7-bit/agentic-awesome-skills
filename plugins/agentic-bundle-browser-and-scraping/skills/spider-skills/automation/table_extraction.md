Strategy for structured table data extraction:

1. **Detect and map the table** using Evaluate:
   ```js
   document.title = JSON.stringify({
     tables: [...document.querySelectorAll('table')].map((t,i) => ({
       i, rows: t.rows.length, cols: t.rows[0]?.cells.length,
       headers: [...(t.querySelector('thead tr')?.cells || [])].map(c => c.textContent?.trim()),
       caption: t.querySelector('caption')?.textContent?.trim()
     })),
     divTables: document.querySelectorAll('[role=table], [class*=table], [class*=grid]').length
   })
   ```
2. **Extract headers** from the first row or thead element
3. **Extract all row data** using Evaluate:
   ```js
   const table = document.querySelector('table');
   const rows = [...table.querySelectorAll('tbody tr, tr')].map(tr =>
     [...tr.querySelectorAll('td, th')].map(td => td.textContent?.trim())
   );
   document.title = 'DATA:' + JSON.stringify(rows.slice(0, 20));
   ```
4. **Handle pagination**: If the table is paginated, extract data from each page
5. **Handle sorting/filtering**: Apply any needed sort/filter before extraction
6. **For div-based tables**: Use role=row, role=cell selectors instead of tr/td

Key pitfalls:
- Large tables may exceed document.title length limits. Extract in batches (20-50 rows at a time).
- Merged cells (colspan/rowspan) complicate extraction. Check for these attributes.
- Some tables use div-based layouts with CSS grid. These won't have tr/td elements.
- Hidden columns or expandable rows may contain additional data.
