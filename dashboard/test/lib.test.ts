import { describe, expect, it } from "vitest";
import { age, dbm, ms, pct, tone, UNKNOWN, utc } from "../src/lib/format";
import { bounds, centroid, idw, pointInPolygon } from "../src/lib/geometry";
import { lowConfidence, segments, type Point } from "../src/lib/series";
import { route } from "../src/App";

describe("format: unknown is never zero", () => {
  it("renders missing values as unknown", () => {
    expect(ms(null)).toBe(UNKNOWN);
    expect(ms(undefined)).toBe(UNKNOWN);
    expect(ms(Number.NaN)).toBe(UNKNOWN);
    expect(pct(null)).toBe(UNKNOWN);
    expect(dbm(null)).toBe(UNKNOWN);
    expect(utc(null)).toBe(UNKNOWN);
    expect(ms(0)).toBe("0.0 ms");
  });
  it("formats ages and UTC", () => {
    expect(age(null)).toBe("never");
    expect(age(1000, 6000)).toBe("5s ago");
    expect(age(0, 7_200_000)).toBe("2h ago");
    expect(utc(0)).toBe("1970-01-01 00:00:00Z");
  });
  it("maps states to tones, unknown by default", () => {
    expect(tone("healthy")).toBe("good");
    expect(tone("failed")).toBe("bad");
    expect(tone("missing")).toBe("bad");
    expect(tone("stale")).toBe("warn");
    expect(tone("whatever")).toBe("unknown");
    expect(tone(null)).toBe("unknown");
  });
});

const pt = (t: number, v: number | null): Point => ({ t, samples: 30, eligible: 30, loss_pct: 0, p50_ms: v, p95_ms: v, max_ms: v, dns_bad: 0 });

describe("series: gaps are preserved", () => {
  it("splits on time gaps and nulls", () => {
    const s = segments([pt(0, 1), pt(60_000, 2), pt(600_000, 3), pt(660_000, null), pt(720_000, 4)], 60, (p) => p.p95_ms);
    expect(s).toEqual([[[0, 1], [60_000, 2]], [[600_000, 3]], [[720_000, 4]]]);
  });
  it("flags low-confidence buckets", () => {
    expect(lowConfidence({ ...pt(0, 1), samples: 5 })).toBe(true);
    expect(lowConfidence(pt(0, 1))).toBe(false);
  });
});

describe("geometry", () => {
  const sq: Array<[number, number]> = [[0, 0], [4, 0], [4, 4], [0, 4]];
  it("point in polygon / centroid / bounds", () => {
    expect(pointInPolygon([2, 2], sq)).toBe(true);
    expect(pointInPolygon([5, 2], sq)).toBe(false);
    expect(centroid(sq)).toEqual([2, 2]);
    expect(bounds([sq])).toEqual({ minX: 0, minY: 0, maxX: 4, maxY: 4 });
  });
  it("IDW never extrapolates beyond the distance limit", () => {
    const anchors = [{ x: 0, y: 0, value: -50 }, { x: 4, y: 0, value: -70 }];
    expect(idw([0, 0], anchors, 3)?.value).toBe(-50);
    const mid = idw([2, 0], anchors, 3);
    expect(mid?.value).toBeCloseTo(-60);
    expect(idw([20, 20], anchors, 3)).toBeNull();
  });
});

describe("routing", () => {
  it("parses hash routes", () => {
    expect(route("#/incidents/inc-000001")).toEqual({ view: "incidents", id: "inc-000001" });
    expect(route("")).toEqual({ view: "", id: undefined });
    expect(route("#/nodes/node%2D01")).toEqual({ view: "nodes", id: "node-01" });
  });
});
