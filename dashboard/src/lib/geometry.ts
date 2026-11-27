// Floor-plan math. Interpolated coverage is a visualization only: points beyond the
// distance limit from any measured anchor are returned as null ("no measurement").

export type Pt = [number, number];

export interface Anchor {
  x: number;
  y: number;
  value: number;
}

export function pointInPolygon(p: Pt, poly: Pt[]): boolean {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const a = poly[i];
    const b = poly[j];
    if (!a || !b) continue;
    const cross = a[1] > p[1] !== b[1] > p[1] && p[0] < ((b[0] - a[0]) * (p[1] - a[1])) / (b[1] - a[1]) + a[0];
    if (cross) inside = !inside;
  }
  return inside;
}

export function centroid(poly: Pt[]): Pt {
  if (poly.length === 0) return [0, 0];
  const sx = poly.reduce((s, p) => s + p[0], 0);
  const sy = poly.reduce((s, p) => s + p[1], 0);
  return [sx / poly.length, sy / poly.length];
}

/** Inverse-distance weighting with a hard distance limit. Returns null when no anchor is near. */
export function idw(p: Pt, anchors: Anchor[], maxDist: number, power = 2): { value: number; nearest: number } | null {
  let num = 0;
  let den = 0;
  let nearest = Infinity;
  for (const a of anchors) {
    const d = Math.hypot(a.x - p[0], a.y - p[1]);
    nearest = Math.min(nearest, d);
    if (d < 1e-6) return { value: a.value, nearest: 0 };
    if (d > maxDist) continue;
    const w = 1 / d ** power;
    num += w * a.value;
    den += w;
  }
  if (den === 0) return null;
  return { value: num / den, nearest };
}

export function bounds(polys: Pt[][]): { minX: number; minY: number; maxX: number; maxY: number } {
  const pts = polys.flat();
  if (pts.length === 0) return { minX: 0, minY: 0, maxX: 10, maxY: 10 };
  return {
    minX: Math.min(...pts.map((p) => p[0])),
    minY: Math.min(...pts.map((p) => p[1])),
    maxX: Math.max(...pts.map((p) => p[0])),
    maxY: Math.max(...pts.map((p) => p[1])),
  };
}
