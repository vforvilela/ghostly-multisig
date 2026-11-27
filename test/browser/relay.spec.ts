// Two co-signers in real browsers, inside the runner's sandbox and CSP: a PSBT passed, signed by the second, merged,
// and finalised; a different transaction stopped; the layout at phone width.
import { expect, test, type Frame } from "@playwright/test";
import { readFileSync } from "node:fs";
import { chatPair, type Side } from "./harness.ts";

const fixture = (f: string) => readFileSync(new URL(`../fixtures/${f}`, import.meta.url), "utf8").trim();
const DESCRIPTOR = fixture("descriptor.txt");

async function setWallet(side: Side): Promise<void> {
  const f = side.frame;
  await f.getByRole("textbox", { name: "Output descriptor" }).fill(DESCRIPTOR);
  await f.getByLabel("Network").selectOption("regtest");
  await f.getByRole("button", { name: "Use this wallet" }).click();
  await expect(f.locator(".wallet-line")).toContainText("2 of 3");
}

async function paste(f: Frame, box: string, text: string): Promise<void> {
  await f.getByRole("textbox", { name: box, exact: true }).fill(text);
  await f.getByRole("button", { name: box === "PSBT to read" ? "Read" : "Paste a signed copy" }).click();
}

const violations = (f: Frame) => f.evaluate(() => (window as unknown as { __violations: string[] }).__violations);

test("passes a PSBT between co-signers until it is fully signed", async ({ browser }) => {
  const [ana, bob] = await chatPair(browser, "frame");
  await setWallet(ana);
  await setWallet(bob);
  await expect(ana.frame.locator(".peer")).toContainText("Same wallet as yours");

  await paste(ana.frame, "PSBT to read", fixture("1-alice.psbt"));
  await expect(ana.frame.getByText("1 of 2 signed")).toBeVisible();
  await expect(ana.frame.locator('.outputs li[data-kind="change"]')).toHaveCount(1);
  await expect(ana.frame.locator(".outputs li").first()).toContainText("0.4999 9412 BTC");
  await expect(ana.frame.getByText(/0\.0000 0588 BTC · 2\.0 sat\/vB/)).toBeVisible();
  await ana.frame.getByRole("button", { name: "Send to contact" }).click();

  await expect(bob.frame.locator(".notice")).toContainText("Your contact sent a transaction.");
  await expect(bob.frame.getByText("1 of 2 signed")).toBeVisible();
  await expect(ana.frame.locator(".send-status")).toHaveText("Your contact has it: 1 signature(s) missing");
  // Bob signed in his wallet: he pastes his copy back.
  await paste(bob.frame, "Signed PSBT", fixture("1-bob.psbt"));
  await expect(bob.frame.getByText("Fully signed")).toBeVisible();
  await expect(bob.frame.getByRole("textbox", { name: "Signed transaction in hex" })).toHaveValue(/^02000000/);
  await bob.frame.getByRole("button", { name: "Send to contact" }).click();
  await expect(ana.frame.getByText("Fully signed")).toBeVisible();
  await expect(bob.frame.locator(".send-status")).toHaveText("Your contact has it, fully signed");

  // The copy box holds what the person copies into their wallet: select-all on focus.
  for (const side of [ana, bob]) expect(await violations(side.frame)).toEqual([]);
  for (const side of [ana, bob]) await side.context.close();
});

test("stops a different transaction and lets the person keep theirs", async ({ browser }) => {
  const [ana, bob] = await chatPair(browser, "frame");
  await setWallet(ana);
  await setWallet(bob);
  await paste(ana.frame, "PSBT to read", fixture("0-unsigned.psbt"));
  await paste(bob.frame, "PSBT to read", fixture("x-tampered-same-inputs.psbt"));
  await bob.frame.getByRole("button", { name: "Send to contact" }).click();
  const dialog = ana.frame.getByRole("alertdialog");
  await expect(dialog).toContainText("Your contact sent a transaction that is not the one you hold.");
  await dialog.getByRole("button", { name: "Keep mine" }).click();
  await expect(dialog).toHaveCount(0);
  await expect(ana.frame.locator(".txid")).toHaveText(/^dae56771bd3b/);
  for (const side of [ana, bob]) await side.context.close();
});

test("fits a phone without sideways scrolling", async ({ browser }) => {
  const [ana, bob] = await chatPair(browser, "top", { viewport: { width: 360, height: 700 } });
  await setWallet(ana);
  await paste(ana.frame, "PSBT to read", fixture("0-unsigned.psbt"));
  await expect(ana.frame.locator('.outputs li[data-kind="change"]')).toHaveCount(1);
  const width = await ana.page.evaluate(() => [document.documentElement.scrollWidth, window.innerWidth]);
  expect(width[0]).toBeLessThanOrEqual(width[1]);
  for (const side of [ana, bob]) await side.context.close();
});
