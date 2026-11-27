/**
 * The built Multisig (dist/index.html) in real browsers, for the Playwright specs. Adapted from Ghostly Chess's harness.
 *
 * Each page gets a test broker as `window.ghostly`, injected by addInitScript before the page's script runs. Frames
 * between the two sides go through Node (exposeBinding), so a test can close and reopen a side.
 *
 * Two ways to load the page:
 * - "top": the page itself, served at http://multisig.test/.
 * - "frame": inside <iframe sandbox="allow-scripts"> with a <meta> CSP like the web runner's, so what the runner's
 *   sandbox forbids fails here too. Every CSP violation is recorded (window.__violations in the frame).
 *
 * Nothing leaves the machine: every URL is answered by page.route.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Browser, BrowserContext, BrowserContextOptions, Frame, Page } from "@playwright/test";

export const ORIGIN = "http://multisig.test";
const dist = join(import.meta.dirname, "../../dist/index.html");

/** The runner's CSP (WISP 1200): inline script and style only, no network. */
export const RUNNER_CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; connect-src 'none'";

export type Mode = "top" | "frame";

/** The built page, read when a test starts (build first: npm run build). */
export function builtPage(): string {
  return readFileSync(dist, "utf8");
}

function framedHost(html: string): string {
  const inner = html.replace("<head>", `<head>\n    <meta http-equiv="Content-Security-Policy" content="${RUNNER_CSP}" />`);
  // The host writes the frame with srcdoc, as a string the host's script holds: no second URL to serve.
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>html,body{margin:0;height:100%}iframe{border:0;width:100%;height:100%;display:block}</style></head>
<body><iframe sandbox="allow-scripts" title="Multisig"></iframe><script>
document.querySelector("iframe").srcdoc = ${JSON.stringify(inner).replace(/<\//g, "<\\/")};
</script></body></html>`;
}

interface BrokerOptions {
  name: string;
  version: string;
  inChat: boolean;
  /** The client's locale, as context() gives it. */
  locale: string;
  /** Install the broker only in the sandboxed child frame. */
  childOnly: boolean;
  /** The person's display name, as context() gives it with the `name` permission. */
  displayName?: string;
}

/** Runs in the page (or the frame) before the app: the test broker. */
function installBroker(options: BrokerOptions): void {
  const w = window as unknown as Record<string, unknown> & Window;
  w.__violations = [] as string[];
  document.addEventListener("securitypolicyviolation", (e) => (w.__violations as string[]).push(`${e.violatedDirective} ${e.blockedURI}`));
  if (options.childOnly && window === window.top) return;
  const store = new Map<string, string>();
  const listeners = { message: new Set<(d: unknown) => void>(), peer: new Set<(d: unknown) => void>() };
  let peer: { version: string } | null = null;
  const call = (name: string, ...args: unknown[]) => (w[name] as (...a: unknown[]) => Promise<unknown>)(...args);
  w.__deliver = (data: unknown) => listeners.message.forEach((l) => l(data));
  w.__peerEvent = (event: { open: boolean; version?: string }) => {
    peer = event.open ? { version: event.version ?? "" } : null;
    listeners.peer.forEach((l) => l(event));
  };
  w.__setPeer = (version: string | null) => (peer = version === null ? null : { version });
  w.ghostly = {
    context: async () => ({ version: options.version, inChat: options.inChat, peer, theme: "light", locale: options.locale, ...(options.displayName === undefined ? {} : { name: options.displayName }) }),
    file: async () => new ArrayBuffer(0),
    storage: {
      get: async (key: string) => (store.has(key) ? JSON.parse(store.get(key)!) : undefined),
      set: async (key: string, value: unknown) => void store.set(key, JSON.stringify(value)),
      delete: async (key: string) => void store.delete(key),
      keys: async () => [...store.keys()],
    },
    chat: {
      send: async (value: unknown) => {
        const ok = await call("__msSend", JSON.parse(JSON.stringify(value)));
        if (!ok) throw new Error("the peer does not have the app open");
      },
      on: (event: "message" | "peer", listener: (d: unknown) => void) => {
        listeners[event].add(listener);
        return () => listeners[event].delete(listener);
      },
    },
    close: async () => {},
  };
  void call("__msHello");
}

/** One side: its page and the frame the app runs in. */
export interface Side {
  name: string;
  /** The app version this side's client reports. */
  version: string;
  page: Page;
  context: BrowserContext;
  /** The frame the app runs in, once its broker said hello. */
  frame: Frame;
}

export interface Relay {
  /** Milliseconds each frame waits before it is handed over. */
  latency: number;
  /** Return true to drop a frame. */
  drop?: (from: string, data: unknown) => boolean;
}

/** Opens one side. In a chat, `other` is the side already open, if any. */
export async function openSide(
  browser: Browser,
  options: {
    name: string;
    mode?: Mode;
    inChat?: boolean;
    contextOptions?: BrowserContextOptions;
    relay?: Relay;
    sides?: Map<string, Side>;
    /** Scripts to run in every frame before the page's own (a probe that watches a browser API). */
    init?: (() => void)[];
    /** The client's locale (default "en"). */
    locale?: string;
    /** The app version the client reports for this side (default "0.1.0"). */
    version?: string;
    /** The page to load instead of the build. */
    html?: string;
    /** The person's display name in context() (the `name` permission); none by default. */
    displayName?: string;
  },
): Promise<Side> {
  const { name, mode = "top", inChat = true, version = "0.1.0" } = options;
  const sides = options.sides ?? new Map<string, Side>();
  const relay = options.relay ?? { latency: 0 };
  const context = await browser.newContext(options.contextOptions);
  const page = await context.newPage();
  const html = options.html ?? builtPage();
  await page.route(`${ORIGIN}/**`, (route) =>
    route.fulfill({ contentType: "text/html", body: mode === "frame" ? framedHost(html) : html }),
  );
  let resolveFrame!: (frame: Frame) => void;
  const ready = new Promise<Frame>((resolve) => (resolveFrame = resolve));
  const side = { name, version, page, context } as Side;
  await page.exposeBinding("__msHello", async ({ frame }) => {
    side.frame = frame;
    // The other side is open: this one learns it from context(), the other from a peer event.
    const other = [...sides.values()].find((s) => s !== side && s.frame);
    if (other) {
      await frame.evaluate((v) => (window as unknown as { __peerEvent: (e: unknown) => void }).__peerEvent({ open: true, version: v }), other.version);
      await other.frame.evaluate((v) => (window as unknown as { __peerEvent: (e: unknown) => void }).__peerEvent({ open: true, version: v }), version);
    }
    resolveFrame(frame);
  });
  await page.exposeBinding("__msSend", async (_source, data: unknown) => {
    const other = [...sides.values()].find((s) => s !== side && s.frame);
    if (!other) return false;
    if (relay.drop?.(name, data)) return true;
    setTimeout(() => {
      void other.frame.evaluate((d) => (window as unknown as { __deliver: (d: unknown) => void }).__deliver(d), data).catch(() => {});
    }, relay.latency);
    return true;
  });
  await page.addInitScript(installBroker, { name, version, inChat, locale: options.locale ?? "en", childOnly: mode === "frame", displayName: options.displayName } satisfies BrokerOptions);
  for (const script of options.init ?? []) await page.addInitScript(script);
  sides.set(name, side);
  await page.goto(`${ORIGIN}/index.html`);
  side.frame = await ready;
  return side;
}

/** Two sides of one chat, both open. */
export async function chatPair(browser: Browser, mode: Mode = "top", contextOptions?: BrowserContextOptions): Promise<[Side, Side]> {
  const sides = new Map<string, Side>();
  const ana = await openSide(browser, { name: "ana", mode, sides, contextOptions });
  const bob = await openSide(browser, { name: "bob", mode, sides, contextOptions });
  return [ana, bob];
}
