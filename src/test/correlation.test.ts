import { describe, expect, it } from "vitest";
import { findSuspiciousCorrelations, type TimelineBlackFog, type TimelineWazuh } from "@/lib/correlation";

const bf = (time: string, endpoint = "LAPTOP-01"): TimelineBlackFog => ({
  kind: "blackfog", id: time, time, endpoint, title: "blocked",
});
const wz = (time: string, level: number, endpoint = "laptop-01"): TimelineWazuh => ({
  kind: "wazuh", id: time, time, endpoint, title: "alert", level,
});
const opts = { minLevel: 10, windowMinutes: 5 };

describe("suspicious correlation rule", () => {
  it("flags a level 10 alert 4 minutes after a BlackFog block on the same host", () => {
    const r = findSuspiciousCorrelations([bf("2026-01-01T10:00:00Z")], [wz("2026-01-01T10:04:00Z", 10)], opts);
    expect(r).toHaveLength(1);
    expect(r[0].gapSeconds).toBe(240);
  });
  it("ignores alerts below level 10", () => {
    expect(findSuspiciousCorrelations([bf("2026-01-01T10:00:00Z")], [wz("2026-01-01T10:01:00Z", 9)], opts)).toHaveLength(0);
  });
  it("ignores alerts more than 5 minutes after the block", () => {
    expect(findSuspiciousCorrelations([bf("2026-01-01T10:00:00Z")], [wz("2026-01-01T10:05:01Z", 12)], opts)).toHaveLength(0);
  });
  it("ignores alerts that happen before the block", () => {
    expect(findSuspiciousCorrelations([bf("2026-01-01T10:00:00Z")], [wz("2026-01-01T09:59:00Z", 12)], opts)).toHaveLength(0);
  });
  it("ignores alerts on a different host", () => {
    expect(findSuspiciousCorrelations([bf("2026-01-01T10:00:00Z")], [wz("2026-01-01T10:01:00Z", 12, "server-9")], opts)).toHaveLength(0);
  });
});
