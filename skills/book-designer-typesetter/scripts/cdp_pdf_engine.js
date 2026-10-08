#!/usr/bin/env bun
/**
 * CDP PDF Engine for Book Designer & Typesetter (cdp_pdf_engine.js)
 * Uses Chrome DevTools Protocol (CDP) to print publication-quality vector PDFs
 * with strict control over headers, footers, zero-URL display.
 */

const fs = require("fs");
const path = require("path");

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    input: null,
    output: null,
    title: "Editorial Book",
    author: "",
    size: "A4",
    isCover: false
  };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--input" && args[i + 1]) options.input = path.resolve(args[++i]);
    else if (args[i] === "--output" && args[i + 1]) options.output = path.resolve(args[++i]);
    else if (args[i] === "--title" && args[i + 1]) options.title = args[++i];
    else if (args[i] === "--author" && args[i + 1]) options.author = args[++i];
    else if (args[i] === "--size" && args[i + 1]) options.size = args[++i];
    else if (args[i] === "--is-cover") options.isCover = true;
  }

  if (!options.input || !options.output) {
    console.error("Usage: bun cdp_pdf_engine.js --input <file.html> --output <file.pdf> [--title <title>] [--author <author>] [--size <A4|trade-6x9|letter>] [--is-cover]");
    process.exit(1);
  }

  return options;
}

const PAGE_DIMENSIONS = {
  "A4": { width: 8.27, height: 11.69, css: "210mm 297mm" },
  "trade-6x9": { width: 6.0, height: 9.0, css: "6in 9in" },
  "letter": { width: 8.5, height: 11.0, css: "8.5in 11in" }
};

async function main() {
  const opts = parseArgs();
  const bravePath = "/opt/brave.com/brave/brave-browser";

  if (!fs.existsSync(bravePath)) {
    throw new Error(`Brave executable not found at: ${bravePath}`);
  }

  const tempProfile = path.join("/tmp", `brave_book_cdp_${Date.now()}_${Math.random().toString(36).substring(7)}`);
  fs.mkdirSync(tempProfile, { recursive: true });

  const proc = Bun.spawn([
    bravePath,
    "--headless",
    "--no-sandbox",
    "--disable-gpu",
    "--remote-debugging-port=0",
    `--user-data-dir=${tempProfile}`,
    "about:blank"
  ], {
    stdout: "ignore",
    stderr: "ignore",
    stdin: "ignore"
  });

  let port = null;
  const portFile = path.join(tempProfile, "DevToolsActivePort");

  for (let i = 0; i < 60; i++) {
    if (fs.existsSync(portFile)) {
      const lines = fs.readFileSync(portFile, "utf-8").trim().split("\n");
      port = lines[0];
      break;
    }
    await new Promise(r => setTimeout(r, 100));
  }

  if (!port) {
    proc.kill();
    fs.rmSync(tempProfile, { recursive: true, force: true });
    throw new Error("Failed to discover Chrome DevTools port.");
  }

  const verRes = await fetch(`http://127.0.0.1:${port}/json/version`);
  const ver = await verRes.json();
  const ws = new WebSocket(ver.webSocketDebuggerUrl);

  function sendCmd(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = Math.floor(Math.random() * 1000000);
      const handler = (evt) => {
        const data = JSON.parse(evt.data);
        if (data.id === id) {
          ws.removeEventListener("message", handler);
          if (data.error) reject(data.error);
          else resolve(data.result);
        }
      };
      ws.addEventListener("message", handler);
      ws.send(JSON.stringify({ id, method, params }));
    });
  }

  await new Promise(r => ws.onopen = r);

  const inputPath = path.resolve(opts.input);
  if (!fs.existsSync(inputPath)) {
    throw new Error(`Input HTML file not found: ${inputPath}`);
  }
  const target = await sendCmd("Target.createTarget", { url: `file://${inputPath}` });
  const sanitizedTargetId = encodeURIComponent(String(target.targetId).replace(/[^a-zA-Z0-9_-]/g, ""));
  const pageWs = new WebSocket(`ws://127.0.0.1:${port}/devtools/page/${sanitizedTargetId}`);
  await new Promise(r => pageWs.onopen = r);

  function sendPageCmd(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = Math.floor(Math.random() * 1000000);
      const handler = (evt) => {
        const data = JSON.parse(evt.data);
        if (data.id === id) {
          pageWs.removeEventListener("message", handler);
          if (data.error) reject(data.error);
          else resolve(data.result);
        }
      };
      pageWs.addEventListener("message", handler);
      pageWs.send(JSON.stringify({ id, method, params }));
    });
  }

  await sendPageCmd("Page.enable");
  // Wait for rendering and layout
  await new Promise(r => setTimeout(r, opts.isCover ? 600 : 2000));

  let pdfResult;
  if (opts.isCover) {
    pdfResult = await sendPageCmd("Page.printToPDF", {
      printBackground: true,
      displayHeaderFooter: false,
      preferCSSPageSize: true,
      paperWidth: dim.width,
      paperHeight: dim.height,
      marginTop: 0,
      marginBottom: 0,
      marginLeft: 0,
      marginRight: 0
    });
  } else {
    const headerTemplate = `<div style="font-size: 7.5pt; font-family: 'Cinzel', Georgia, serif; width: 100%; text-align: center; color: #8c8275; border-bottom: 0.5pt solid #d9d2c7; padding-bottom: 3px; margin: 0 18mm; letter-spacing: 0.08em; text-transform: uppercase;">
  <span>${opts.title}</span>
</div>`;

    const footerTemplate = `<div style="font-size: 8pt; font-family: 'EB Garamond', Georgia, serif; width: 100%; text-align: center; color: #8c8275; border-top: 0.5pt solid #d9d2c7; padding-top: 3px; margin: 0 18mm;">
  — <span class="pageNumber"></span> —
</div>`;

    pdfResult = await sendPageCmd("Page.printToPDF", {
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate: headerTemplate,
      footerTemplate: footerTemplate,
      preferCSSPageSize: true,
      paperWidth: dim.width,
      paperHeight: dim.height,
      marginTop: 0.8,
      marginBottom: 0.8,
      marginLeft: 0.6,
      marginRight: 0.6
    });
  }

  fs.writeFileSync(opts.output, Buffer.from(pdfResult.data, "base64"));
  pageWs.close();

  // Teardown
  ws.close();
  proc.kill();
  fs.rmSync(tempProfile, { recursive: true, force: true });
  console.log(`[*] PDF rendered successfully at: ${opts.output}`);
}

main().catch(err => {
  console.error("FATAL ERROR in CDP PDF Engine:", err);
  process.exit(1);
});
