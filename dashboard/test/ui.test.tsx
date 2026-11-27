import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Badge, Stat } from "../src/components";
import { App } from "../src/App";
import { Overview } from "../src/views/Overview";

afterEach(() => {
  cleanup();
  sessionStorage.clear();
  vi.restoreAllMocks();
});

describe("accessible state rendering", () => {
  it("badges carry text, not just colour", () => {
    render(<Badge state="failed" />);
    expect(screen.getByRole("status").textContent).toContain("failed");
  });
  it("unknown stats are labeled unknown", () => {
    render(<Stat label="p95" value="unknown" />);
    expect(screen.getByText("unknown")).toBeTruthy();
  });
});

describe("app", () => {
  it("asks for a token before showing data", () => {
    render(<App />);
    expect(screen.getByText(/API token/)).toBeTruthy();
  });

  it("overview shows stale/unknown states explicitly", async () => {
    const status = {
      site_id: "home",
      now: "2026-01-01T00:00:00Z",
      generated_at: "2026-01-01T00:00:00Z",
      uptime_s: 10,
      ingestion_ok: true,
      mqtt_connected: true,
      nodes: [{ id: "node-01", liveness: "missing", room: null, rssi_dbm: -60, last_seen: null }],
      targets: [],
      active_incidents: [],
      score: { version: 1, value: null, coverage: 0, worst_vantage: null, components: [] },
      ingest: {},
      storage: null,
      desired_revision: 1,
    };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(status), { headers: { "content-type": "application/json" } }));
    render(<Overview />);
    expect(await screen.findByText("missing")).toBeTruthy();
    // RSSI of a missing node is not presented as current.
    expect(screen.queryByText("-60 dBm")).toBeNull();
    expect(screen.getAllByText("unknown").length).toBeGreaterThan(0);
  });
});
