// Pure correlation logic, shared by server and client and covered by tests.

export type TimelineBlackFog = {
  kind: "blackfog";
  id: string;
  time: string;
  endpoint: string;
  title: string;
  destIp?: string | null;
  process?: string | null;
  country?: string | null;
};

export type TimelineWazuh = {
  kind: "wazuh";
  id: string;
  time: string;
  endpoint: string;
  agentId?: string;
  title: string;
  level: number;
  mitre?: string[];
};

export type TimelineItem = TimelineBlackFog | TimelineWazuh;

export type SuspiciousCorrelation = {
  endpoint: string;
  blackfog: TimelineBlackFog;
  wazuh: TimelineWazuh;
  gapSeconds: number;
};

export function normalizeHost(name: string | null | undefined): string {
  return (name ?? "").trim().toLowerCase().split(".")[0];
}

/**
 * Flags a "suspicious correlation" when a BlackFog block event on an endpoint is
 * FOLLOWED by a Wazuh alert with level >= minLevel on the same endpoint within
 * windowMinutes. The BlackFog event must come first (or at the same instant);
 * alerts that happened before the block are ignored.
 *
 * Endpoints are matched by normalized hostname (lowercase, domain stripped),
 * because BlackFog reports the machine name and Wazuh reports the agent name.
 *
 * Each Wazuh alert is paired with the closest preceding BlackFog event only,
 * so one noisy alert does not produce a burst of duplicate findings.
 */
export function findSuspiciousCorrelations(
  blackfog: TimelineBlackFog[],
  wazuh: TimelineWazuh[],
  opts: { minLevel: number; windowMinutes: number },
): SuspiciousCorrelation[] {
  const windowMs = opts.windowMinutes * 60_000;
  const byHost = new Map<string, TimelineBlackFog[]>();
  for (const e of blackfog) {
    const key = normalizeHost(e.endpoint);
    const list = byHost.get(key) ?? [];
    list.push(e);
    byHost.set(key, list);
  }
  for (const list of byHost.values()) list.sort((a, b) => Date.parse(a.time) - Date.parse(b.time));

  const out: SuspiciousCorrelation[] = [];
  for (const alert of wazuh) {
    if (alert.level < opts.minLevel) continue;
    const events = byHost.get(normalizeHost(alert.endpoint));
    if (!events) continue;
    const at = Date.parse(alert.time);
    let best: TimelineBlackFog | undefined;
    for (const e of events) {
      const et = Date.parse(e.time);
      if (et > at) break;
      if (at - et <= windowMs) best = e; // keep the latest preceding event in window
    }
    if (best) {
      out.push({
        endpoint: alert.endpoint,
        blackfog: best,
        wazuh: alert,
        gapSeconds: Math.round((at - Date.parse(best.time)) / 1000),
      });
    }
  }
  return out.sort((a, b) => Date.parse(b.wazuh.time) - Date.parse(a.wazuh.time));
}

export function mergeTimeline(items: TimelineItem[]): TimelineItem[] {
  return [...items].sort((a, b) => Date.parse(b.time) - Date.parse(a.time));
}
