import { chromium, webkit, firefox } from "@playwright/test";
import fs from "node:fs";
const psbt = fs.readFileSync(process.argv[2], "utf8").trim();
const big = (psbt + psbt).repeat(5); // ~20 KB
const only = process.argv[3];
const H = process.env.HOME + "/.cache/ms-playwright/";
const engines = [
  ["chromium", chromium, H + "chromium-1208/chrome-linux64/chrome"],
  ["webkit", webkit, undefined],
  ["firefox", firefox, undefined],
].filter(([n]) => !only || n === only);
const log = (...a) => console.log(...a);

for (const [name, bt, exe] of engines) {
  let b;
  try {
    b = await bt.launch({ executablePath: exe, timeout: 20000 });
    const ctx = await b.newContext(name === "chromium" ? { permissions: ["clipboard-read", "clipboard-write"] } : {});
    const p = await ctx.newPage();
    p.setDefaultTimeout(8000);
    await p.goto("http://localhost:18777/");
    const fh = await (await p.$("#f")).contentFrame();
    const g = await fh.evaluate(() => (typeof window.__state === "function" ? window.__state() : { html: document.documentElement.outerHTML.slice(-200) }));
    log(name, b.version(), "guard:", JSON.stringify({ ok: g.guard, origin: g.origin, clipboardApi: g.clipboardApi, refused: g.refused, html: g.html }));
    for (const [label, text] of [["psbt", psbt], ["20KB", big]]) {
      await p.fill("#src", text);
      await p.focus("#src");
      await p.keyboard.press("ControlOrMeta+A");
      await p.keyboard.press("ControlOrMeta+C");
      await fh.fill("#in", "");
      await fh.click("#in");
      await p.keyboard.press("ControlOrMeta+V");
      const st = await fh.evaluate(() => window.__state());
      log(name, `paste-in ${label}:`, JSON.stringify({ want: text.length, got: st.inLen, pasteEventSaw: st.ev.filter((e) => e.type === "paste").at(-1)?.len }));
    }
    await fh.fill("#out", psbt);
    await fh.click("#out");
    await p.keyboard.press("ControlOrMeta+A");
    await p.keyboard.press("ControlOrMeta+C");
    await p.fill("#back", "");
    await p.click("#back");
    await p.keyboard.press("ControlOrMeta+V");
    log(name, "copy-out:", JSON.stringify({ want: psbt.length, got: (await p.inputValue("#back")).length }));
  } catch (e) {
    log(name, "ERR", e.message.split("\n")[0]);
  } finally {
    if (b) await b.close();
  }
}
