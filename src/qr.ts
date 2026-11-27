/**
 * Animated QR codes for air-gapped signers: a UR's parts, one after another, until the panel leaves the page.
 *
 * The UR text goes in upper case, so the QR uses its alphanumeric mode (about 30% smaller than bytes); every UR reader
 * takes either case. Dark modules on white with a 4-module quiet zone, whatever the theme: cameras need the contrast.
 */
import { encode } from "uqr";
import { urEncoder, type UrType } from "./ur.ts";

const SVG = "http://www.w3.org/2000/svg";
/** Parts a second. Passport and Keystone read 4-8 comfortably. */
const FPS = 5;
/** Bytes a part: QR version ~13 at level L, easy for a phone-grade camera at arm's length. */
export const FRAGMENT = 200;

/** One QR code as an SVG: a single path of dark modules. */
export function qrSvg(text: string, label: string): SVGSVGElement {
  const { data, size } = encode(text, { ecc: "L", border: 4 });
  let d = "";
  data.forEach((row, y) => row.forEach((dark, x) => dark && (d += `M${x} ${y}h1v1h-1z`)));
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", `0 0 ${size} ${size}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", label);
  svg.setAttribute("shape-rendering", "crispEdges");
  const bg = document.createElementNS(SVG, "rect");
  bg.setAttribute("width", String(size));
  bg.setAttribute("height", String(size));
  bg.setAttribute("fill", "#fff");
  const path = document.createElementNS(SVG, "path");
  path.setAttribute("d", d);
  path.setAttribute("fill", "#000");
  svg.append(bg, path);
  return svg;
}

/**
 * A panel kept across redraws: `show` restarts the animation only when the data changed. The timer stops itself once
 * the panel is no longer in the page, and starts again when `show` is next called.
 */
export class QrPanel {
  readonly el: HTMLElement;
  private readonly frame: HTMLElement;
  private readonly caption: HTMLElement;
  private key = "";
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly label: string,
    private readonly partOf: (n: number, count: number) => string,
  ) {
    this.frame = document.createElement("div");
    this.frame.className = "qr-frame";
    this.caption = document.createElement("p");
    this.caption.className = "muted small qr-caption";
    this.el = document.createElement("div");
    this.el.className = "qr";
    this.el.append(this.frame, this.caption);
  }

  show(type: UrType, data: Uint8Array): HTMLElement {
    const key = `${type}:${data.length}:${Array.from(data.subarray(0, 64)).join()}:${Array.from(data.subarray(-64)).join()}`;
    if (key === this.key && this.timer) return this.el;
    this.stop();
    this.key = key;
    const enc = urEncoder(type, data, FRAGMENT);
    let seq = 1;
    const draw = () => {
      if (seq > 1 && !this.el.isConnected) return this.stop();
      this.frame.replaceChildren(qrSvg(enc.part(seq).toUpperCase(), this.label));
      this.caption.textContent = enc.count > 1 ? this.partOf(((seq - 1) % enc.count) + 1, enc.count) : "";
      this.el.dataset.part = String(seq);
      seq++;
    };
    draw();
    if (enc.count > 1) this.timer = setInterval(draw, 1000 / FPS);
    return this.el;
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.key = "";
  }
}
