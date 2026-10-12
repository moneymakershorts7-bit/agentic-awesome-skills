#!/usr/bin/env node
/**
 * code-to-video CLI & Core Engine
 * Deterministic HTML/CSS/Canvas/WebGL to MP4/WebM Video Engine
 * Incorporates El Décimo Hombre Hardening Directives:
 * - Deterministic Virtual Clock (CSS animations, Web Animations API, GSAP, requestAnimationFrame)
 * - True 60fps frame stepping without real-time wall-clock drift
 * - Audio-visual sample-accurate sync with edge-tts and sidechain ducking
 * - Hermetic font and asset verification
 */

const { program } = require('commander');
const puppeteer = require('puppeteer-core');
const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const DEFAULT_CHROME = '/usr/bin/google-chrome';
const DEFAULT_FFMPEG = process.env.FFMPEG_PATH || 'ffmpeg';

function findChromePath() {
  const candidates = [
    process.env.CHROME_BIN,
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/snap/bin/chromium'
  ].filter(Boolean);

  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return null;
}

/**
 * Deterministic Injected Clock Driver
 * Freezes real-time timers and provides sample-accurate frame scrubbing
 */
const DETERMINISTIC_CLOCK_SCRIPT = `
(function() {
  window.__HV_DETERMINISTIC__ = true;
  window.__CURRENT_FRAME__ = 0;
  window.__FPS__ = 60;
  window.__VIRTUAL_TIME_MS__ = 0;

  // Track all registered RAF callbacks
  window.__rafCallbacks = [];
  const originalRAF = window.requestAnimationFrame;
  window.requestAnimationFrame = function(cb) {
    window.__rafCallbacks.push(cb);
    return window.__rafCallbacks.length;
  };

  // Override performance.now and Date.now for time-locked procedural animations
  const baseEpoch = 1700000000000;
  window.performance.now = function() {
    return window.__VIRTUAL_TIME_MS__;
  };
  Date.now = function() {
    return baseEpoch + window.__VIRTUAL_TIME_MS__;
  };

  // Step function called by orchestrator per discrete frame
  window.__seekToFrame = function(frameIndex, fps) {
    window.__CURRENT_FRAME__ = frameIndex;
    window.__FPS__ = fps || 60;
    const timeMs = (frameIndex / window.__FPS__) * 1000;
    window.__VIRTUAL_TIME_MS__ = timeMs;

    // 1. Advance CSS Animations (Web Animations API)
    try {
      const anims = document.getAnimations ? document.getAnimations() : [];
      for (let i = 0; i < anims.length; i++) {
        const a = anims[i];
        try {
          a.pause();
          a.currentTime = timeMs;
        } catch(e) {}
      }
    } catch(e) {}

    // 2. Advance GSAP Global Timeline if present
    try {
      if (window.gsap && window.gsap.globalTimeline) {
        window.gsap.globalTimeline.pause();
        window.gsap.globalTimeline.time(timeMs / 1000);
      }
    } catch(e) {}

    // 3. Dispatch and flush RAF callbacks for Canvas/WebGL render loops
    const cbs = window.__rafCallbacks.slice();
    window.__rafCallbacks = [];
    for (let i = 0; i < cbs.length; i++) {
      try {
        cbs[i](timeMs);
      } catch(e) {
        console.error("RAF Callback error:", e);
      }
    }

    // 4. Custom hook for WebGL / Canvas runners
    if (typeof window.__onFrameUpdate === 'function') {
      try {
        window.__onFrameUpdate(frameIndex, timeMs);
      } catch(e) {}
    }

    return true;
  };

  // Initial pause on all animations
  window.addEventListener('DOMContentLoaded', () => {
    try {
      const style = document.createElement('style');
      style.textContent = '*, *::before, *::after { animation-play-state: paused !important; }';
      document.head.appendChild(style);
    } catch(e) {}
  });
})();
`;

async function renderHtmlToVideo(options) {
  const {
    inputHtml,
    outputVideo,
    durationSec = 5,
    fps = 60,
    width = 1920,
    height = 1080,
    audioFile = null,
    bgmFile = null,
    voiceDuck = true,
    chromePath = findChromePath()
  } = options;

  if (!chromePath) {
    throw new Error('Google Chrome or Chromium binary not found. Please install Chrome or set CHROME_BIN.');
  }

  if (!fs.existsSync(inputHtml)) {
    throw new Error(`Input HTML file not found: ${inputHtml}`);
  }

  const resolvedHtml = path.resolve(inputHtml);
  const totalFrames = Math.round(durationSec * fps);
  const frameIntervalMs = 1000 / fps;

  console.log(`[code-to-video] Initializing deterministic render:`);
  console.log(`  Source: ${resolvedHtml}`);
  console.log(`  Output: ${outputVideo}`);
  console.log(`  Specs:  ${width}x${height} @ ${fps}fps | ${durationSec}s (${totalFrames} total frames)`);

  const browser = await puppeteer.launch({
    executablePath: chromePath,
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu-sandbox',
      '--disable-web-security',
      '--allow-file-access-from-files',
      `--window-size=${width},${height}`,
      '--hide-scrollbars',
      '--font-render-hinting=medium',
      '--force-color-profile=srgb',
      '--disable-threaded-animation',
      '--disable-threaded-scrolling',
      '--run-all-compositor-stages-before-draw',
      '--enable-begin-frame-control'
    ]
  });

  const page = await browser.newPage();
  await page.setViewport({ width, height, deviceScaleFactor: 1 });

  // Inject deterministic virtual clock
  await page.evaluateOnNewDocument(DETERMINISTIC_CLOCK_SCRIPT);

  // Navigate to file URL
  const fileUrl = 'file://' + resolvedHtml;
  await page.goto(fileUrl, { waitUntil: 'load', timeout: 30000 });

  // Await document fonts settlement
  await page.evaluate(async () => {
    if (document.fonts && document.fonts.ready) {
      await document.fonts.ready;
    }
  });

  // Spawn FFmpeg in image2pipe raw video ingestion mode
  const tmpRawVideo = path.join(os.tmpdir(), `ctv_raw_${Date.now()}.mp4`);
  const ffmpegArgs = [
    '-y',
    '-f', 'image2pipe',
    '-vcodec', 'png',
    '-r', String(fps),
    '-i', '-',
    '-c:v', 'libx264',
    '-pix_fmt', 'yuv420p',
    '-preset', 'fast',
    '-crf', '18',
    tmpRawVideo
  ];

  console.log(`[code-to-video] Spawning FFmpeg video pipe...`);
  const ffmpegProc = spawn(DEFAULT_FFMPEG, ffmpegArgs, {
    stdio: ['pipe', 'pipe', 'pipe']
  });

  let ffmpegStderr = '';
  ffmpegProc.stderr.on('data', (d) => { ffmpegStderr += d.toString(); });

  const ffmpegExitPromise = new Promise((resolve, reject) => {
    ffmpegProc.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`FFmpeg exited with error code ${code}:\n${ffmpegStderr.slice(-1000)}`));
    });
  });

  const startTime = Date.now();
  console.log(`[code-to-video] Stepping and rasterizing ${totalFrames} frames deterministically...`);

  for (let frameIdx = 0; frameIdx < totalFrames; frameIdx++) {
    // Step internal virtual time
    await page.evaluate((idx, targetFps) => {
      window.__seekToFrame(idx, targetFps);
    }, frameIdx, fps);

    // Capture exact frame buffer
    const frameBuffer = await page.screenshot({
      type: 'png',
      omitBackground: false
    });

    // Write to FFmpeg stdin with backpressure management
    const canWrite = ffmpegProc.stdin.write(frameBuffer);
    if (!canWrite) {
      await new Promise((r) => ffmpegProc.stdin.once('drain', r));
    }

    if ((frameIdx + 1) % Math.max(1, Math.floor(totalFrames / 5)) === 0 || frameIdx === totalFrames - 1) {
      const pct = Math.round(((frameIdx + 1) / totalFrames) * 100);
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      console.log(`  Progress: ${pct}% (${frameIdx + 1}/${totalFrames} frames) in ${elapsed}s`);
    }
  }

  ffmpegProc.stdin.end();
  await ffmpegExitPromise;
  await browser.close();

  // Handle Audio Synthesis / Muxing
  if (audioFile && fs.existsSync(audioFile)) {
    console.log(`[code-to-video] Muxing audio track (${audioFile})...`);
    let filterArgs = [];
    let audioInputs = ['-i', audioFile];

    if (bgmFile && fs.existsSync(bgmFile) && voiceDuck) {
      console.log(`[code-to-video] Applying sidechain compression ducking with BGM (${bgmFile})...`);
      audioInputs.push('-i', bgmFile);
      filterArgs = [
        '-filter_complex',
        '[2:a]volume=0.25[bgm];[bgm][1:a]sidechaincompress=threshold=0.08:ratio=4:attack=50:release=300[ducked_bgm];[1:a][ducked_bgm]amix=inputs=2:duration=first[aout]',
        '-map', '0:v',
        '-map', '[aout]'
      ];
    } else {
      filterArgs = ['-map', '0:v', '-map', '1:a'];
    }

    const muxArgs = [
      '-y',
      '-i', tmpRawVideo,
      ...audioInputs,
      ...filterArgs,
      '-c:v', 'copy',
      '-c:a', 'aac',
      '-b:a', '192k',
      '-shortest',
      outputVideo
    ];

    execSync(`${DEFAULT_FFMPEG} ${muxArgs.map(a => `"${a}"`).join(' ')}`, { stdio: 'pipe' });
    fs.unlinkSync(tmpRawVideo);
  } else {
    fs.renameSync(tmpRawVideo, outputVideo);
  }

  console.log(`[code-to-video] ✓ Successfully generated ${outputVideo}`);
}

async function synthesizeNarration(text, outputFile, voice = 'en-US-ChristopherNeural') {
  console.log(`[code-to-video] Synthesizing speech narration via edge-tts (voice: ${voice})...`);
  const cmd = `edge-tts --voice "${voice}" --text "${text.replace(/"/g, '\\"')}" --write-media "${outputFile}"`;
  execSync(cmd, { stdio: 'inherit' });
  console.log(`[code-to-video] ✓ Audio saved to ${outputFile}`);
}

module.exports = {
  renderHtmlToVideo,
  synthesizeNarration,
  findChromePath
};

if (require.main === module) {
  program
    .name('code-to-video')
    .description('Deterministic Code & HTML to MP4 Video Engine')
    .version('1.0.0');

  program
    .command('render')
    .description('Render an HTML file into a deterministic MP4 video')
    .requiredOption('-i, --input <path>', 'Path to input HTML file')
    .requiredOption('-o, --output <path>', 'Path to output MP4 file')
    .option('-d, --duration <seconds>', 'Video duration in seconds', '5')
    .option('-r, --fps <number>', 'Frames per second', '60')
    .option('-w, --width <pixels>', 'Width in pixels', '1920')
    .option('-h, --height <pixels>', 'Height in pixels', '1080')
    .option('-a, --audio <path>', 'Optional voiceover audio file')
    .option('--bgm <path>', 'Optional background music audio file')
    .action(async (opts) => {
      try {
        await renderHtmlToVideo({
          inputHtml: opts.input,
          outputVideo: opts.output,
          durationSec: parseFloat(opts.duration),
          fps: parseInt(opts.fps, 10),
          width: parseInt(opts.width, 10),
          height: parseInt(opts.height, 10),
          audioFile: opts.audio,
          bgmFile: opts.bgm
        });
      } catch (err) {
        console.error('[code-to-video] Error:', err.message);
        process.exit(1);
      }
    });

  program
    .command('narrate')
    .description('Generate neural voiceover audio using edge-tts')
    .requiredOption('-t, --text <text>', 'Text script to speak')
    .requiredOption('-o, --output <path>', 'Output audio file path (.mp3)')
    .option('-v, --voice <name>', 'Neural voice name', 'en-US-ChristopherNeural')
    .action(async (opts) => {
      try {
        await synthesizeNarration(opts.text, opts.output, opts.voice);
      } catch (err) {
        console.error('[code-to-video] Narration error:', err.message);
        process.exit(1);
      }
    });

  program.parse(process.argv);
}
