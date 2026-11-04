// Record the README demo (docs/videos/builder-demo.mp4 and docs/images/builder-demo.gif): the builder's wizard,
// copying the command, then the sample report of six compromised npm releases (site/samples/compromised-npm,
// from a real run of the same command by examples/compromised-npm/build.sh). Not part of the test suite.
//
//   npm install --no-save playwright && npx playwright install chromium   # once
//   node scripts/record_demo.js site
//   ffmpeg -ss 0.4 -i raw/demo.webm -vf fps=30,format=yuv420p -c:v libx264 -crf 22 -preset slow \
//     -movflags +faststart -an docs/videos/builder-demo.mp4
//   ffmpeg -i docs/videos/builder-demo.mp4 -vf "fps=8,scale=800:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=64:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" docs/images/builder-demo.gif
//
// The pointer and captions are drawn over the page for the film only; the page itself is not changed.
const { chromium } = require('playwright');
const http = require('http'), fs = require('fs'), path = require('path');
const SITE = process.argv[2];
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png' };
const srv = http.createServer((q, r) => {
  const p = path.join(SITE, decodeURIComponent(q.url.split('?')[0].split('#')[0]).replace(/\/$/, '/index.html'));
  fs.readFile(p, (e, d) => { if (e) { r.writeHead(404); r.end(); return; } r.writeHead(200, { 'content-type': types[path.extname(p)] || 'text/plain' }); r.end(d); });
}).listen(8131);
const W = 1280, H = 800;
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// An overlay drawn on top of the page for the film: a pointer and a caption bar. Added with page.evaluate (the
// page's own code is untouched; DOM and CSSOM changes are allowed by its Content Security Policy).
async function overlay(page) {
  await page.evaluate(() => {
    if (document.getElementById('film-cursor')) return;
    const c = document.createElement('div'); c.id = 'film-cursor';
    Object.assign(c.style, { position: 'fixed', left: '640px', top: '420px', width: '22px', height: '22px', borderRadius: '50%',
      background: 'rgba(44,90,160,.35)', border: '2px solid #2c5aa0', zIndex: 99999, pointerEvents: 'none', transform: 'translate(-50%,-50%)' });
    const bar = document.createElement('div'); bar.id = 'film-caption';
    Object.assign(bar.style, { position: 'fixed', right: '24px', bottom: '24px', maxWidth: '560px',
      background: 'rgba(20,28,62,.94)', color: '#fff', font: '600 21px/1.35 system-ui,sans-serif', padding: '14px 22px', borderRadius: '14px',
      zIndex: 99999, pointerEvents: 'none', opacity: '0', transition: 'opacity .35s', boxShadow: '0 6px 24px rgba(0,0,0,.25)', textAlign: 'left' });
    document.body.append(c, bar);
  });
}
async function caption(page, text, sub = '') {
  await page.evaluate(([t, s]) => {
    const bar = document.getElementById('film-caption');
    bar.replaceChildren(document.createTextNode(t));
    if (s) { const small = document.createElement('div'); small.textContent = s; Object.assign(small.style, { font: '400 15px/1.4 system-ui,sans-serif', opacity: '.85', marginTop: '4px' }); bar.append(small); }
    bar.style.opacity = t ? '1' : '0';
  }, [text, sub]);
}
async function pointAt(page, selector, ms = 700) {
  const box = await page.locator(selector).first().boundingBox();
  const x = box.x + Math.min(box.width / 2, 60), y = box.y + box.height / 2;
  await page.evaluate(([x, y, ms]) => {
    const c = document.getElementById('film-cursor');
    const from = [parseFloat(c.style.left), parseFloat(c.style.top)];
    c.animate([{ left: `${from[0]}px`, top: `${from[1]}px` }, { left: `${x}px`, top: `${y}px` }], { duration: ms, easing: 'ease-in-out', fill: 'forwards' });
    c.style.left = `${x}px`; c.style.top = `${y}px`;
  }, [x, y, ms]);
  await wait(ms + 80);
}
async function click(page, selector) {
  await pointAt(page, selector);
  await page.evaluate(() => document.getElementById('film-cursor').animate([{ transform: 'translate(-50%,-50%) scale(1)' }, { transform: 'translate(-50%,-50%) scale(.6)' }, { transform: 'translate(-50%,-50%) scale(1)' }], { duration: 260 }));
  await page.locator(selector).first().click();
  await wait(350);
}

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: W, height: H }, recordVideo: { dir: 'raw', size: { width: W, height: H } },
    permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await ctx.newPage();
  await page.goto('http://localhost:8131/builder/');
  await page.waitForSelector('#targets button');
  await overlay(page);
  await caption(page, 'oss-intake command builder', 'Check a project for known-compromised packages before you use it');
  await wait(2600);
  await caption(page, '1. What are you checking?', 'A project\'s dependency list: here, an npm package-lock.json');
  await click(page, '#targets [data-focus="targets:lockfile"]');
  await wait(900);
  await click(page, '#next');
  await caption(page, '2. Point it at the lockfile', 'Only the file is read: nothing is downloaded or installed');
  await pointAt(page, '#w-path');
  await page.locator('#w-path').pressSequentially('package-lock.json', { delay: 70 });
  await wait(900);
  await click(page, '#next');
  await caption(page, '3. A pass or fail check', 'Fail if any package is known malware');
  await click(page, '#outcomes [data-focus="outcomes:gate"]');
  await wait(500);
  await click(page, '#w-gate-malicious');
  await wait(1400);
  await click(page, '#next');
  await caption(page, '4. Review what the command will do', 'What it checks, what it contacts and sends, when it fails');
  await wait(1200);
  await page.evaluate(() => window.scrollTo({ top: 0 }));
  for (let y = 0; y < 900; y += 15) { await page.evaluate((y) => window.scrollTo(0, y), y); await wait(22); }
  await wait(1200);
  for (let y = 900; y >= 0; y -= 30) { await page.evaluate((y) => window.scrollTo(0, y), y); await wait(16); }
  await wait(400);
  await caption(page, 'Copy the command', 'oss-intake --path package-lock.json --out report --fail-on malicious');
  await click(page, '#copy');
  await wait(2200);
  await caption(page, 'Run it in your terminal', 'With a malware gate, a run that finds malware exits with code 3');
  await wait(2600);
  // The report: the repo's sample, from a real run of this command on six compromised npm releases.
  await page.goto('http://localhost:8131/samples/compromised-npm/report.html');
  await overlay(page);
  await caption(page, 'The report: 6 malicious packages', 'Malware, not bugs: remove, do not patch');
  await pointAt(page, '.tile >> nth=0', 900);
  await wait(2600);
  await caption(page, 'Every compromised release, with the advisory', 'Sample report from a real run on six compromised npm releases');
  const top = await page.locator('h2:has-text("Top 9 findings")').evaluate((n) => n.getBoundingClientRect().top + scrollY - 20);
  for (let y = 0; y < top; y += 24) { await page.evaluate((y) => window.scrollTo(0, y), y); await wait(16); }
  await page.evaluate((y) => window.scrollTo(0, y), top);
  await pointAt(page, 'td:has-text("chalk")', 900);
  await wait(3800);
  await caption(page, 'ntavakol.github.io/OSS-Intake/builder', 'pip install oss-intake');
  await wait(2600);
  const video = page.video();
  await ctx.close();
  fs.renameSync(await video.path(), 'raw/demo.webm');
  await browser.close(); srv.close();
})();
