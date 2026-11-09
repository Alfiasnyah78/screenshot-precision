import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import {
  findSuspiciousCorrelations,
  type TimelineBlackFog,
  type TimelineWazuh,
} from "./correlation";
import {
  indexerSearch,
  mapAlertHit,
  wazuhApi,
  wazuhConfigStatus,
  WazuhConfigError,
} from "./wazuh.server";

const RANGE_HOURS = { "24h": 24, "7d": 168, "30d": 720 } as const;
type Range = keyof typeof RANGE_HOURS;

function errMsg(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

export const getStatus = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { data: roles } = await context.supabase
      .from("user_roles")
      .select("role")
      .eq("user_id", context.userId);
    const list = (roles ?? []).map((r) => r.role);
    const role = list.includes("admin") ? "admin" : list.includes("analyst") ? "analyst" : "viewer";
    return { role, config: wazuhConfigStatus(), email: (context.claims as any)?.email ?? "" };
  });

export const getOverview = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d) => z.object({ range: z.enum(["24h", "7d", "30d"]) }).parse(d))
  .handler(async ({ data, context }) => {
    const hours = RANGE_HOURS[data.range as Range];
    const since = new Date(Date.now() - hours * 3600_000);
    const startOfDay = new Date();
    startOfDay.setUTCHours(0, 0, 0, 0);
    const bucketMs = hours <= 24 ? 3600_000 : 86400_000;

    const [{ count: todayCount }, { data: events }] = await Promise.all([
      context.supabase
        .from("blackfog_events")
        .select("id", { count: "exact", head: true })
        .gte("occurred_at", startOfDay.toISOString()),
      context.supabase
        .from("blackfog_events")
        .select("occurred_at, endpoint, dest_ip, dest_country, lat, lon")
        .gte("occurred_at", since.toISOString())
        .order("occurred_at", { ascending: false })
        .limit(5000),
    ]);

    const ev = events ?? [];
    const tally = (keys: (string | null)[]) => {
      const m = new Map<string, number>();
      for (const k of keys) if (k) m.set(k, (m.get(k) ?? 0) + 1);
      return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, count]) => ({ name, count }));
    };

    // Build empty buckets so the chart has a continuous axis
    const buckets = new Map<number, { t: number; blackfog: number; wazuh: number }>();
    const start = Math.floor(since.getTime() / bucketMs) * bucketMs;
    for (let t = start; t <= Date.now(); t += bucketMs) buckets.set(t, { t, blackfog: 0, wazuh: 0 });
    for (const e of ev) {
      const k = Math.floor(Date.parse(e.occurred_at) / bucketMs) * bucketMs;
      const b = buckets.get(k);
      if (b) b.blackfog++;
    }

    const geo = new Map<string, { ip: string; country: string | null; lat: number; lon: number; count: number }>();
    for (const e of ev) {
      if (e.lat == null || e.lon == null || !e.dest_ip) continue;
      const g = geo.get(e.dest_ip) ?? { ip: e.dest_ip, country: e.dest_country, lat: e.lat, lon: e.lon, count: 0 };
      g.count++;
      geo.set(e.dest_ip, g);
    }

    let wazuhTotal: number | null = null;
    let wazuhError: string | null = null;
    let topAgents: { name: string; count: number }[] = [];
    try {
      const res = await indexerSearch({
        size: 0,
        track_total_hits: true,
        query: { range: { timestamp: { gte: since.toISOString() } } },
        aggs: {
          over_time: { date_histogram: { field: "timestamp", fixed_interval: hours <= 24 ? "1h" : "1d" } },
          agents: { terms: { field: "agent.name", size: 5 } },
        },
      });
      wazuhTotal = res.hits?.total?.value ?? 0;
      for (const b of res.aggregations?.over_time?.buckets ?? []) {
        const k = Math.floor(b.key / bucketMs) * bucketMs;
        const bucket = buckets.get(k);
        if (bucket) bucket.wazuh += b.doc_count;
      }
      topAgents = (res.aggregations?.agents?.buckets ?? []).map((b: any) => ({ name: b.key, count: b.doc_count }));
    } catch (e) {
      wazuhError = e instanceof WazuhConfigError ? "not_configured" : errMsg(e);
    }

    // Merge activity from both sources for "most active endpoints"
    const active = new Map<string, number>();
    for (const t of tally(ev.map((e) => e.endpoint)).concat(topAgents)) active.set(t.name, (active.get(t.name) ?? 0) + t.count);

    return {
      blackfogToday: todayCount ?? 0,
      blackfogInRange: ev.length,
      wazuhTotal,
      wazuhError,
      topEndpoints: [...active.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, count]) => ({ name, count })),
      topDestinations: tally(ev.map((e) => e.dest_ip)),
      series: [...buckets.values()],
      geo: [...geo.values()],
    };
  });

const alertsInput = z.object({
  hours: z.number().int().min(1).max(720).default(24),
  minLevel: z.number().int().min(0).max(16).default(0),
  agent: z.string().max(200).optional(),
  mitre: z.string().max(50).optional(),
  limit: z.number().int().min(1).max(500).default(200),
});

export const listAlerts = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d) => alertsInput.parse(d))
  .handler(async ({ data, context }) => {
    const since = new Date(Date.now() - data.hours * 3600_000).toISOString();
    const filter: any[] = [{ range: { timestamp: { gte: since } } }];
    if (data.minLevel) filter.push({ range: { "rule.level": { gte: data.minLevel } } });
    if (data.agent) filter.push({ wildcard: { "agent.name": { value: `*${data.agent}*`, case_insensitive: true } } });
    if (data.mitre) filter.push({ term: { "rule.mitre.id": data.mitre.toUpperCase() } });
    try {
      const res = await indexerSearch({
        size: data.limit,
        sort: [{ timestamp: "desc" }],
        query: { bool: { filter } },
      });
      const alerts = (res.hits?.hits ?? []).map(mapAlertHit);

      // Mark alerts whose endpoint also had BlackFog activity in the same period
      const { data: events } = await context.supabase
        .from("blackfog_events")
        .select("endpoint")
        .gte("occurred_at", since)
        .limit(5000);
      const hosts = new Set((events ?? []).map((e) => e.endpoint.toLowerCase().split(".")[0] ?? ""));
      return {
        error: null,
        alerts: alerts.map((a) => ({ ...a, hasBlackFog: hosts.has(a.agentName.toLowerCase().split(".")[0] ?? "") })),
      };
    } catch (e) {
      return { error: e instanceof WazuhConfigError ? "not_configured" : errMsg(e), alerts: [] };
    }
  });

export const listAgents = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    try {
      const res = await wazuhApi<any>("/agents?limit=500&select=id,name,ip,status,version,os.name,os.version,lastKeepAlive");
      const agents = (res.data?.affected_items ?? []).map((a: any) => ({
        id: a.id as string,
        name: a.name as string,
        ip: a.ip as string,
        status: a.status as string,
        wazuhVersion: a.version as string | undefined,
        os: [a.os?.name, a.os?.version].filter(Boolean).join(" "),
        lastSeen: a.lastKeepAlive as string | undefined,
      }));
      // BlackFog agent version is read from the latest ingested event's raw payload, if present
      const { data: events } = await context.supabase
        .from("blackfog_events")
        .select("endpoint, raw, occurred_at")
        .order("occurred_at", { ascending: false })
        .limit(2000);
      const bfVersion = new Map<string, string>();
      for (const e of events ?? []) {
        const k = e.endpoint.toLowerCase().split(".")[0] ?? "";
        const v = (e.raw as any)?.agent_version;
        if (v && !bfVersion.has(k)) bfVersion.set(k, String(v));
      }
      return {
        error: null,
        agents: agents.map((a: any) => ({ ...a, blackfogVersion: bfVersion.get(a.name.toLowerCase().split(".")[0] ?? "") ?? null })),
      };
    } catch (e) {
      return { error: e instanceof WazuhConfigError ? "not_configured" : errMsg(e), agents: [] };
    }
  });

export const getCorrelation = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d) => z.object({ hours: z.number().int().min(1).max(168) }).parse(d))
  .handler(async ({ data, context }) => {
    const since = new Date(Date.now() - data.hours * 3600_000).toISOString();
    const { data: settings } = await context.supabase.from("app_settings").select("*").eq("id", 1).maybeSingle();
    const minLevel = settings?.alert_level_threshold ?? 10;
    const windowMinutes = settings?.correlation_window_minutes ?? 5;

    const { data: events } = await context.supabase
      .from("blackfog_events")
      .select("id, occurred_at, endpoint, process_name, dest_ip, dest_country, action")
      .gte("occurred_at", since)
      .order("occurred_at", { ascending: false })
      .limit(3000);
    const blackfog: TimelineBlackFog[] = (events ?? []).map((e) => ({
      kind: "blackfog",
      id: e.id,
      time: e.occurred_at,
      endpoint: e.endpoint,
      title: `${e.action} ${e.process_name ?? "process"} → ${e.dest_ip ?? "?"}`,
      destIp: e.dest_ip,
      process: e.process_name,
      country: e.dest_country,
    }));

    let wazuh: TimelineWazuh[] = [];
    let error: string | null = null;
    try {
      const res = await indexerSearch({
        size: 2000,
        sort: [{ timestamp: "desc" }],
        query: { bool: { filter: [{ range: { timestamp: { gte: since } } }, { range: { "rule.level": { gte: 3 } } }] } },
      });
      wazuh = (res.hits?.hits ?? []).map(mapAlertHit).map((a: any) => ({
        kind: "wazuh" as const,
        id: a.id,
        time: a.timestamp,
        endpoint: a.agentName,
        agentId: a.agentId,
        title: a.description,
        level: a.level,
        mitre: a.mitre,
      }));
    } catch (e) {
      error = e instanceof WazuhConfigError ? "not_configured" : errMsg(e);
    }

    const suspicious = findSuspiciousCorrelations(blackfog, wazuh, { minLevel, windowMinutes });
    return { blackfog, wazuh, suspicious, minLevel, windowMinutes, error };
  });

// Active Response commands. Isolation and process kill require matching
// scripts on the agents (see Settings → Response setup).
const ACTIONS = {
  block_ip: { command: "!firewall-drop", label: "Block destination IP" },
  kill_process: { command: "!kill-process", label: "Kill process" },
  isolate: { command: "!host-isolate", label: "Isolate host" },
  unisolate: { command: "!host-unisolate", label: "Release host" },
  scan: { command: null, label: "Trigger scan" },
} as const;

export const runResponseAction = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d) =>
    z
      .object({
        action: z.enum(["block_ip", "kill_process", "isolate", "unisolate", "scan"]),
        agentId: z.string().regex(/^\d{3,}$/, "Invalid agent id"),
        target: z.string().max(255).optional(),
      })
      .parse(d),
  )
  .handler(async ({ data, context }) => {
    const { data: allowed } = await context.supabase.rpc("can_respond", { _user_id: context.userId });
    if (!allowed) throw new Error("Only admins and analysts can run response actions");
    if (data.action === "block_ip" && !/^[0-9a-fA-F:.]+$/.test(data.target ?? "")) throw new Error("A valid IP is required");
    if (data.action === "kill_process" && !data.target) throw new Error("A process name is required");

    const def = ACTIONS[data.action];
    let status = "success";
    let result: unknown;
    try {
      if (data.action === "scan") {
        result = await wazuhApi(`/syscheck?agents_list=${data.agentId}`, { method: "PUT" });
      } else {
        const body: any = { command: def.command, arguments: data.target ? [data.target] : [] };
        if (data.action === "block_ip") body.alert = { data: { srcip: data.target } };
        result = await wazuhApi(`/active-response?agents_list=${data.agentId}`, {
          method: "PUT",
          body: JSON.stringify(body),
        });
      }
    } catch (e) {
      status = "failed";
      result = { error: errMsg(e) };
    }

    const email = (context.claims as any)?.email ?? null;
    await Promise.all([
      context.supabase.from("response_actions").insert({
        user_id: context.userId,
        action: data.action,
        agent_id: data.agentId,
        target: data.target ?? null,
        status,
        result: result as any,
      }),
      context.supabase.from("audit_logs").insert({
        user_id: context.userId,
        user_email: email,
        action: `response.${data.action}`,
        target: `agent ${data.agentId}${data.target ? ` / ${data.target}` : ""}`,
        details: { status } as any,
      }),
    ]);
    if (status === "failed") throw new Error((result as any).error);
    return { ok: true, label: def.label };
  });

export const logAudit = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d) => z.object({ action: z.string().max(100), target: z.string().max(300).optional() }).parse(d))
  .handler(async ({ data, context }) => {
    await context.supabase.from("audit_logs").insert({
      user_id: context.userId,
      user_email: (context.claims as any)?.email ?? null,
      action: data.action,
      target: data.target ?? null,
    });
    return { ok: true };
  });
