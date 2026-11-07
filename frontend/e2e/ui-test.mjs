// End-to-end UI test through Chrome DevTools Protocol: clicks real buttons, fills forms,
// navigates with the sidebar, and fails on any JS exception or blank page.
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
const BIN = process.env.CHROME_BIN || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const BASE = process.argv[2] || "http://127.0.0.1:8000";
const port = 9341;
const proc = spawn(BIN, ["--headless=new", `--remote-debugging-port=${port}`,
  `--user-data-dir=${join(tmpdir(), "logjack-e2e-" + Date.now())}`,
  "--window-size=1440,900", "about:blank"], { stdio: "ignore" });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
let targets;
for (let i = 0; i < 60; i++) { try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); break; } catch { await wait(200); } }
const ws = new WebSocket(targets.find((t) => t.type === "page").webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map(); const errors = [];
ws.onmessage = (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg.result); pending.delete(msg.id); }
  if (msg.method === "Runtime.exceptionThrown") errors.push(msg.params.exceptionDetails.exception?.description?.split("\n")[0] || msg.params.exceptionDetails.text);
  if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "error") errors.push("console.error: " + msg.params.args.map((a) => a.value ?? a.description).join(" ").slice(0, 200));
};
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (expr) => { const r = await send("Runtime.evaluate", { expression: `(async()=>{${expr}})()`, returnByValue: true, awaitPromise: true }); return r.result?.value; };
await send("Runtime.enable"); await send("Page.enable");

// helpers injected into the page
const H = `
const $$ = (s) => [...document.querySelectorAll(s)];
const byText = (sel, re) => $$(sel).find(e => re.test(e.textContent.trim()));
const click = (el) => { if (!el) throw new Error('element not found'); el.click(); return true; };
const setVal = (el, v) => { const p = el.tagName === 'SELECT' ? HTMLSelectElement.prototype : el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(p, 'value').set.call(el, v); el.dispatchEvent(new Event(el.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true })); };
const until = async (fn, ms = 15000) => { const t = Date.now(); while (Date.now() - t < ms) { try { const v = fn(); if (v) return v; } catch {} await new Promise(r => setTimeout(r, 150)); } throw new Error('timeout waiting'); };
const h1 = () => document.querySelector('h1')?.innerText || '';
const nav = (href) => click($$('nav a').find(a => a.getAttribute('href') === href));
`;
let pass = 0, fail = 0;
const step = async (name, body) => {
  let res;
  try { res = await ev(H + body); } catch (e) { res = "EXC " + e.message; }
  await wait(300);
  const len = await ev("return document.getElementById('root')?.innerText.length || 0");
  const ok = (res === true || (typeof res === "string" && !res.startsWith("EXC") && !res.startsWith("ERR"))) && errors.length === 0 && len > 50;
  ok ? pass++ : fail++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${typeof res === "string" ? "  → " + res : ""}${len <= 50 ? "  [BLANK PAGE]" : ""}${errors.length ? "\n      " + errors.splice(0).join("\n      ") : ""}`);
};
const wrap = (body) => `try { ${body} } catch (e) { return 'ERR ' + e.message; }`;

await send("Page.navigate", { url: BASE + "/" }); await wait(2000);

// 1. sidebar navigation, two full passes in different orders
const routes = ["/playground", "/datasets", "/experiments", "/defenses", "/tripwires", "/findings", "/"];
const titles = { "/": "Overview", "/playground": "SOC Playground", "/datasets": "Dataset Explorer", "/experiments": "Experiments", "/defenses": "Defense Comparison", "/tripwires": "Tripwire Events", "/findings": "Research Findings & Exports" };
for (const r of [...routes, ...[...routes].reverse()])
  await step(`sidebar → ${r}`, wrap(`nav('${r}'); await until(() => h1() === ${JSON.stringify(titles[r])}); return true;`));

// 2. playground: load case, analyze, compare
await step("playground: load case LJ-SSH-011 (modified)", wrap(`nav('/playground'); await until(() => h1()==='SOC Playground');
  const sel = await until(() => $$('select').find(s => [...s.options].some(o => o.value === 'LJ-SSH-011')));
  setVal(sel, 'LJ-SSH-011'); await until(() => document.querySelector('textarea').value.includes('sshd')); return 'log loaded';`));
await step("playground: Analyze (baseline)", wrap(`click(byText('button', /^Analyze$/)); await until(() => /Tool requests/.test(document.body.innerText) && /Model response/.test(document.body.innerText));
  return 'verdict shown: ' + (document.body.innerText.match(/(Benign|Suspicious|Malicious)/)||[])[0];`));
await step("playground: prompt tabs", wrap(`click(byText('button', /^System prompt$/)); await until(() => /LogJack SOC Analyst Profile v1/.test(document.body.innerText));
  click(byText('button', /^User prompt$/)); return true;`));
await step("playground: Compare all 4 defenses", wrap(`click(byText('button', /Compare all 4 defenses/)); await until(() => /Defense comparison \\(same input\\)/.test(document.body.innerText));
  return 'rows: ' + $$('table tbody tr').length;`));
await step("playground: paste own log + combined defense", wrap(`const ta = document.querySelector('textarea'); setVal(ta, '203.0.113.7 - - [02/Mar/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.4.0"');
  const def = $$('select').find(s => [...s.options].some(o => o.value === 'combined')); setVal(def, 'combined');
  click(byText('button', /^Analyze$/)); await until(() => /Canary tripwire armed|Tripwire fired/.test(document.body.innerText)); return true;`));

// 3. datasets: filter, paginate, open case, analyze from case
await step("datasets: filter ssh + next page", wrap(`nav('/datasets'); await until(() => h1()==='Dataset Explorer' && $$('tbody tr').length > 0);
  const sel = $$('select').find(s => [...s.options].some(o => o.value === 'ssh')); setVal(sel, 'ssh');
  await until(() => /of 50/.test(document.body.innerText)); click($$('button[aria-label="Next page"]')[0]); await until(() => /26–50 of 50/.test(document.body.innerText)); return true;`));
await step("datasets: search box", wrap(`setVal(document.querySelector('input[placeholder^="Search"]'), 'LJ-SSH-011'); await until(() => /1–1 of 1/.test(document.body.innerText)); return true;`));
await step("datasets: open case modal (clean vs modified, highlight)", wrap(`click($$('tbody tr')[0]); await until(() => document.querySelector('[role=dialog]') && /Modified log/i.test(document.body.innerText));
  return 'highlight marks: ' + document.querySelectorAll('mark.inj').length;`));
await step("datasets: Analyze from case → playground", wrap(`const btns = $$('[role=dialog] button').filter(b => /Analyze/.test(b.textContent)); click(btns[1]);
  await until(() => h1()==='SOC Playground' && document.querySelector('textarea').value.includes('sshd')); return true;`));
await step("datasets: import modal opens/closes", wrap(`nav('/datasets'); await until(() => h1()==='Dataset Explorer'); click(byText('button', /Import/));
  await until(() => /Prompt-injection benchmark/.test(document.body.innerText)); click(document.querySelector('[aria-label=Close]')); await until(() => !document.querySelector('[role=dialog]')); return true;`));

// 4. experiments: create via form, watch progress, view, results modal, pause/resume, delete
await step("experiments: create via form (limit 30, 2 mock models × 4 defenses)", wrap(`nav('/experiments'); await until(() => h1()==='Experiments');
  setVal(document.querySelector('input[placeholder^="e.g. Baseline"]'), 'UI e2e test run');
  setVal(document.querySelector('input[placeholder="all"]'), '30');
  click(byText('button', /Start experiment/)); await until(() => /^\\/experiments\\/[0-9a-f]+$/.test(location.pathname)); return location.pathname;`));
await step("experiment detail: progress reaches 100% (live polling)", wrap(`await until(() => /completed/.test(document.body.innerText) && /480/.test(document.body.innerText), 30000); return true;`));
await step("experiment detail: metrics table + results table", wrap(`await until(() => $$('table').length >= 2); return 'metric rows: ' + $$('table')[0].querySelectorAll('tbody tr').length + ', result rows: ' + $$('table')[1].querySelectorAll('tbody tr').length;`));
await step("experiment detail: filter results + open result modal", wrap(`const sel = $$('select').find(s => [...s.options].some(o => o.value === 'attack_success')); setVal(sel, 'attack_success');
  await until(() => $$('table')[1].querySelectorAll('tbody tr').length > 0); click($$('table')[1].querySelector('tbody tr'));
  await until(() => /Result #\\d+/.test(document.body.innerText) && /Final output \\(after enforcement\\)/i.test(document.body.innerText)); click(document.querySelector('[aria-label=Close]')); return true;`));
await step("experiment detail: Charts link → defense comparison", wrap(`click(byText('a', /Charts/)); await until(() => h1()==='Defense Comparison' && document.querySelectorAll('.recharts-bar-rectangle').length > 10); return 'bars: ' + document.querySelectorAll('.recharts-bar-rectangle').length;`));
await step("defenses: switch model + Real/Mock tabs", wrap(`const m = $$('select').find(s => [...s.options].some(o => o.value === 'mock:naive')); setVal(m, 'mock:naive');
  click(byText('button', /^Real LLM$/)); await until(() => /No real-LLM experiment results yet/.test(document.body.innerText));
  click(byText('button', /^Simulated \\(mock\\)$/)); await until(() => document.querySelectorAll('.recharts-bar-rectangle').length > 10); return true;`));
await step("experiments: new run then Pause → Resume → completes", wrap(`nav('/experiments'); await until(() => h1()==='Experiments');
  setVal(document.querySelector('input[placeholder^="e.g. Baseline"]'), 'UI pause test'); setVal(document.querySelector('input[placeholder="all"]'), '');
  const par = $$('input').find(i => i.value === '4'); setVal(par, '1');
  click(byText('button', /Start experiment/)); await until(() => /^\\/experiments\\/[0-9a-f]+$/.test(location.pathname));
  await until(() => byText('button', /Pause/)); click(byText('button', /Pause/)); await until(() => /\\bpaused\\b/.test(document.body.innerText), 20000);
  click(byText('button', /Resume/)); await until(() => /\\bcompleted\\b/.test(document.body.innerText), 60000); return true;`));
await step("experiments: list shows runs; delete test run", wrap(`nav('/experiments'); const li = await until(() => h1()==='Experiments' && $$('li').find(l => /UI pause test/.test(l.textContent) && l.querySelector('button[aria-label="Delete experiment"]')));
  window.confirm = () => true; click(li.querySelector('button[aria-label="Delete experiment"]'));
  await until(() => !/UI pause test/.test(document.body.innerText)); return true;`));

// 5. tripwires + findings + overview
await step("tripwires: table + open result modal", wrap(`nav('/tripwires'); await until(() => h1()==='Tripwire Events' && $$('tbody tr').length > 0); click($$('tbody tr')[0]);
  await until(() => /Result #\\d+/.test(document.body.innerText)); click(document.querySelector('[aria-label=Close]')); return 'events: ' + $$('table')[0].querySelectorAll('tbody tr').length;`));
await step("tripwires: scope filter", wrap(`const s = $$('select')[0]; setVal(s, 'real'); await until(() => /No tripwire events/.test(document.body.innerText)); setVal(s, ''); return true;`));
await step("findings: real (no data) and mock statements", wrap(`nav('/findings'); await until(() => /No completed real LLM experiments/.test(document.body.innerText));
  click(byText('button', /^Simulated \\(mock\\)$/)); await until(() => /model-level attack success/.test(document.body.innerText)); return 'exports: ' + $$('a[href*="/export"]').length;`));
await step("findings: export links download (HTTP 200)", wrap(`const urls = [...new Set($$('a[href*="/export"]').map(a => a.href))];
  const codes = await Promise.all(urls.map(u => fetch(u).then(r => r.status))); return codes.every(c => c === 200) ? 'all ' + codes.length + ' OK' : 'ERR ' + codes;`));
await step("overview: KPIs + charts", wrap(`nav('/'); await until(() => h1()==='Overview' && document.querySelectorAll('.recharts-bar-rectangle').length > 0); return true;`));
await step("browser back/forward", wrap(`history.back(); await until(() => h1()==='Research Findings & Exports'); history.forward(); await until(() => h1()==='Overview'); return true;`));

console.log(`\n${pass} passed, ${fail} failed`);
ws.close(); proc.kill();
process.exit(fail ? 1 : 0);
