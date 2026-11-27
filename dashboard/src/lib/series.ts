// Chart helpers. Gaps are preserved: consecutive points further apart than
// 1.5x the series resolution start a new line segment instead of being bridged.

export interface Point {
  t: number;
  samples: number;
  eligible: number;
  loss_pct: number | null;
  p50_ms: number | null;
  p95_ms: number | null;
  max_ms: number | null;
  dns_bad: number;
}

export interface Series {
  target_id: string;
  vantage: string;
  resolution_s: number;
  points: Point[];
}

export function segments(points: Point[], resolutionS: number, pick: (p: Point) => number | null): Array<Array<[number, number]>> {
  const out: Array<Array<[number, number]>> = [];
  let cur: Array<[number, number]> = [];
  let prevT: number | null = null;
  for (const p of points) {
    const v = pick(p);
    const gap = prevT !== null && p.t - prevT > resolutionS * 1500;
    if (v === null || !Number.isFinite(v) || gap) {
      if (cur.length) out.push(cur);
      cur = [];
    }
    if (v !== null && Number.isFinite(v)) cur.push([p.t, v]);
    prevT = p.t;
  }
  if (cur.length) out.push(cur);
  return out;
}

/** Low-confidence flag: percentiles from fewer than `min` samples are marked. */
export function lowConfidence(p: Point, min = 20): boolean {
  return p.samples < min;
}
