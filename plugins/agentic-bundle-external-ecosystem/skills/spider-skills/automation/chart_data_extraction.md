Strategy for chart/graph data extraction challenges:

1. **Detect the chart library and type** using Evaluate:
   ```js
   document.title = JSON.stringify({
     chartjs: !!document.querySelector('canvas')?.getContext && !!window.Chart,
     svg: document.querySelectorAll('svg [class*=bar], svg rect, svg circle, svg path[class*=line]').length,
     highcharts: !!document.querySelector('[class*=highcharts]'),
     d3: !!document.querySelector('svg [class*=d3]'),
     tooltip: document.querySelector('[class*=tooltip]')?.textContent?.trim(),
     labels: [...document.querySelectorAll('[class*=label], [class*=tick] text, text')].map(el => el.textContent?.trim()).filter(t => t).slice(0,20),
     legend: [...document.querySelectorAll('[class*=legend] *, [class*=legend-item]')].map(el => el.textContent?.trim()).slice(0,10)
   })
   ```
2. **For SVG-based charts**: Extract data directly from SVG element attributes (rect height, circle cx/cy)
3. **For canvas charts**: Hover over data points to trigger tooltips, then read tooltip text
4. **Extract axis labels and values** from text elements near the axes
5. **Hover systematically** over each data point to read exact values from tooltips
6. **Compile extracted data** into a structured format

Key pitfalls:
- Canvas-rendered charts (Chart.js) have no DOM elements for data points. Hover for tooltips.
- SVG charts have data encoded in element attributes but may use transforms for positioning.
- Tooltip text may appear briefly. Read it from the DOM immediately after hover.
- Chart scales may be logarithmic or inverted. Read axis labels carefully.
