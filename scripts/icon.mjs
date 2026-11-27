// Draws Multisig's icon by code: a transaction sheet and three signature marks, two of them filled (two of three
// signed), on a square of 64 units, painted at 512 x 512 into assets/icon.png. Adapted from Ghostly Chess's icon
// script (MIT): no image library, shapes filled with anti-aliased edges and the PNG written here (zlib from Node). Only
// + - * / and Math.sqrt touch the numbers, so every machine paints the same pixels; test/icon.test.ts checks the
// committed file is this script's picture.
//
//   npm run gen:icon            writes assets/icon.png
import { deflateSync } from "node:zlib";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

/** The drawing's units on a side, and the PNG's pixels on a side. */
export const UNITS = 64;
export const SIZE = 512;
const K = 0.5522847498307936; // a quarter circle as a cubic curve
const SUB = 16; // sub-rows sampled per row of pixels
const STEPS = 24; // segments per cubic curve

/** A colour from "#rrggbb". */
const hex = (h) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];

const COLOURS = { night: hex("#0f1720"), sheet: hex("#e8edf5"), ink: hex("#94a3b8"), orange: hex("#f7931a") };

/** Closed outlines made of points, in drawing units. Every shape here runs clockwise, so overlaps add up. */
class Path {
  constructor() {
    this.contours = [];
    this.cur = null;
  }
  move(x, y) {
    this.cur = [[x, y]];
    this.contours.push(this.cur);
    return this;
  }
  line(x, y) {
    this.cur.push([x, y]);
    return this;
  }
  cubic(x1, y1, x2, y2, x, y) {
    const [x0, y0] = this.cur[this.cur.length - 1];
    for (let i = 1; i <= STEPS; i++) {
      const t = i / STEPS;
      const u = 1 - t;
      const a = u * u * u;
      const b = 3 * u * u * t;
      const c = 3 * u * t * t;
      const d = t * t * t;
      this.cur.push([a * x0 + b * x1 + c * x2 + d * x, a * y0 + b * y1 + c * y2 + d * y]);
    }
    return this;
  }
  close() {
    this.cur = null;
    return this;
  }
  /** An ellipse; counter-clockwise (ccw) cuts a hole in what is drawn with it. */
  ellipse(cx, cy, rx, ry, ccw = false) {
    const kx = rx * K;
    const ky = ry * K;
    const s = ccw ? -1 : 1;
    this.move(cx + rx, cy);
    this.cubic(cx + rx, cy + s * ky, cx + kx, cy + s * ry, cx, cy + s * ry);
    this.cubic(cx - kx, cy + s * ry, cx - rx, cy + s * ky, cx - rx, cy);
    this.cubic(cx - rx, cy - s * ky, cx - kx, cy - s * ry, cx, cy - s * ry);
    this.cubic(cx + kx, cy - s * ry, cx + rx, cy - s * ky, cx + rx, cy);
    return this.close();
  }
  circle(cx, cy, r, ccw = false) {
    return this.ellipse(cx, cy, r, r, ccw);
  }
  /** A rectangle, its corners rounded by r. */
  rect(x, y, w, h, r = 0) {
    const k = r * (1 - K);
    this.move(x + r, y).line(x + w - r, y).cubic(x + w - k, y, x + w, y + k, x + w, y + r);
    this.line(x + w, y + h - r).cubic(x + w, y + h - k, x + w - k, y + h, x + w - r, y + h);
    this.line(x + r, y + h).cubic(x + k, y + h, x, y + h - k, x, y + h - r);
    this.line(x, y + r).cubic(x, y + k, x + k, y, x + r, y);
    return this.close();
  }
  poly(points) {
    this.move(...points[0]);
    for (const p of points.slice(1)) this.line(...p);
    return this.close();
  }
  /** A line from (x0, y0) to (x1, y1), `width` thick, with round ends. */
  stroke(x0, y0, x1, y1, width) {
    const len = Math.sqrt((x1 - x0) * (x1 - x0) + (y1 - y0) * (y1 - y0));
    const r = width / 2;
    const [ux, uy] = [((x1 - x0) / len) * r, ((y1 - y0) / len) * r];
    const [nx, ny] = [-uy, ux];
    this.move(x0 - nx, y0 - ny).line(x1 - nx, y1 - ny);
    this.cubic(x1 - nx + ux * K, y1 - ny + uy * K, x1 + ux - nx * K, y1 + uy - ny * K, x1 + ux, y1 + uy);
    this.cubic(x1 + ux + nx * K, y1 + uy + ny * K, x1 + nx + ux * K, y1 + ny + uy * K, x1 + nx, y1 + ny);
    this.line(x0 + nx, y0 + ny);
    this.cubic(x0 + nx - ux * K, y0 + ny - uy * K, x0 - ux + nx * K, y0 - uy + ny * K, x0 - ux, y0 - uy);
    this.cubic(x0 - ux - nx * K, y0 - uy - ny * K, x0 - nx - ux * K, y0 - ny - uy * K, x0 - nx, y0 - ny);
    return this.close();
  }
  /** A copy scaled by s and moved by (dx, dy). */
  placed(s, dx, dy) {
    const out = new Path();
    out.contours = this.contours.map((c) => c.map(([x, y]) => [x * s + dx, y * s + dy]));
    return out;
  }
}

/** SIZE x SIZE pixels of RGB, painted shape over shape with anti-aliased edges. */
class Canvas {
  constructor(background) {
    this.px = new Float64Array(SIZE * SIZE * 3);
    for (let i = 0; i < SIZE * SIZE; i++) this.px.set(background, i * 3);
  }

  /** Paints a path in a colour (inside: a nonzero winding), at an opacity. */
  fill(path, color, opacity = 1) {
    const s = SIZE / UNITS;
    const edges = [];
    let [top, bottom] = [SIZE, 0];
    for (const c of path.contours) {
      for (let k = 0; k < c.length; k++) {
        const [ax, ay] = c[k];
        const [bx, by] = c[(k + 1) % c.length];
        if (ay === by) continue;
        const e = ay < by ? { x0: ax * s, y0: ay * s, x1: bx * s, y1: by * s, w: 1 } : { x0: bx * s, y0: by * s, x1: ax * s, y1: ay * s, w: -1 };
        edges.push(e);
        top = Math.min(top, e.y0);
        bottom = Math.max(bottom, e.y1);
      }
    }
    // Each row of pixels: how much of each pixel the path covers, from SUB lines across it, the spans on each line
    // measured exactly.
    const cover = new Float64Array(SIZE + 1);
    for (let py = Math.max(0, Math.floor(top)); py <= Math.min(SIZE - 1, Math.ceil(bottom)); py++) {
      cover.fill(0);
      for (let k = 0; k < SUB; k++) {
        const sy = py + (k + 0.5) / SUB;
        const hits = [];
        for (const e of edges) if (sy >= e.y0 && sy < e.y1) hits.push([e.x0 + ((sy - e.y0) * (e.x1 - e.x0)) / (e.y1 - e.y0), e.w]);
        hits.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
        let wind = 0;
        for (let h = 0; h < hits.length - 1; h++) {
          wind += hits[h][1];
          if (wind === 0) continue;
          const a = Math.max(0, hits[h][0]);
          const b = Math.min(SIZE, hits[h + 1][0]);
          if (b <= a) continue;
          const [ia, ib] = [Math.floor(a), Math.floor(b)];
          if (ia === ib) cover[ia] += (b - a) / SUB;
          else {
            cover[ia] += (ia + 1 - a) / SUB;
            for (let x = ia + 1; x < ib; x++) cover[x] += 1 / SUB;
            cover[ib] += (b - ib) / SUB;
          }
        }
      }
      for (let x = 0; x < SIZE; x++) {
        const alpha = Math.min(1, cover[x]) * opacity;
        if (alpha <= 0) continue;
        const i = (py * SIZE + x) * 3;
        for (let ch = 0; ch < 3; ch++) this.px[i + ch] += (color[ch] - this.px[i + ch]) * alpha;
      }
    }
    return this;
  }
}

/** Multisig's picture: a sheet with lines of text (the PSBT) and, under it, three marks: two filled, one a ring. */
export function drawIcon() {
  const canvas = new Canvas(COLOURS.night);
  canvas.fill(new Path().rect(14, 7, 36, 34, 4), COLOURS.sheet);
  const lines = new Path();
  for (const [y, w] of [[14, 22], [20, 26], [26, 18], [32, 24]]) lines.rect(20, y, w, 2.6, 1.3);
  canvas.fill(lines, COLOURS.ink);
  canvas.fill(new Path().circle(17, 51, 6).circle(32, 51, 6), COLOURS.orange);
  canvas.fill(new Path().circle(47, 51, 6).circle(47, 51, 4, true), COLOURS.orange);
  return canvas;
}

/** The picture as PNG scanlines: each row a filter byte (0, none) and SIZE pixels of RGB, 8 bits each. */
export function pixels() {
  const { px } = drawIcon();
  const raw = Buffer.alloc(SIZE * (1 + SIZE * 3));
  for (let y = 0; y < SIZE; y++) {
    const at = y * (1 + SIZE * 3);
    for (let x = 0; x < SIZE * 3; x++) raw[at + 1 + x] = Math.max(0, Math.min(255, Math.round(px[y * SIZE * 3 + x])));
  }
  return raw;
}

const CRC = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
function crc32(bytes) {
  let c = -1;
  for (const b of bytes) c = CRC[(c ^ b) & 255] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}
function chunk(type, data) {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(type, 4, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])));
  return Buffer.concat([head, data, crc]);
}

/** The icon as PNG bytes: RGB, 8 bits, SIZE on a side. */
export function iconPng() {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(SIZE, 0);
  ihdr.writeUInt32BE(SIZE, 4);
  ihdr.set([8, 2, 0, 0, 0], 8);
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(pixels(), { level: 9 })), chunk("IEND", Buffer.alloc(0))]);
}

export const ICON = resolve(fileURLToPath(new URL("..", import.meta.url)), "assets/icon.png");

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const png = iconPng();
  writeFileSync(ICON, png);
  console.log(`assets/icon.png ${png.length} bytes, ${SIZE} x ${SIZE}`);
}
