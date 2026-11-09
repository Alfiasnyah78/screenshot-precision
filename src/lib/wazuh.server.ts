// Server-only Wazuh client. Credentials come from project secrets.
// Note: the server runtime verifies TLS certificates, so Wazuh must be reachable
// over HTTPS with a valid (publicly trusted) certificate.

export class WazuhConfigError extends Error {}

function env(name: string): string | undefined {
  const v = process.env[name];
  return v && v.trim() ? v.trim().replace(/\/+$/, "") : undefined;
}

export function wazuhConfigStatus() {
  return {
    api: Boolean(env("WAZUH_API_URL") && env("WAZUH_API_USER") && env("WAZUH_API_PASSWORD")),
    indexer: Boolean(env("WAZUH_INDEXER_URL") && env("WAZUH_INDEXER_USER") && env("WAZUH_INDEXER_PASSWORD")),
  };
}

function basic(user: string, pass: string) {
  return "Basic " + btoa(`${user}:${pass}`);
}

async function timedFetch(url: string, init: RequestInit, ms = 15000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } catch (e) {
    throw new Error(`Cannot reach ${new URL(url).host}: ${e instanceof Error ? e.message : String(e)}`);
  } finally {
    clearTimeout(t);
  }
}

async function apiToken(): Promise<{ base: string; token: string }> {
  const base = env("WAZUH_API_URL");
  const user = env("WAZUH_API_USER");
  const pass = process.env["WAZUH_API_PASSWORD"];
  if (!base || !user || !pass) throw new WazuhConfigError("Wazuh API is not configured");
  const res = await timedFetch(`${base}/security/user/authenticate?raw=true`, {
    method: "POST",
    headers: { Authorization: basic(user, pass) },
  });
  if (!res.ok) throw new Error(`Wazuh API login failed (${res.status})`);
  return { base, token: (await res.text()).trim() };
}

export async function wazuhApi<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const { base, token } = await apiToken();
  const res = await timedFetch(`${base}${path}`, {
    ...init,
    headers: { ...(init.headers ?? {}), Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Wazuh API ${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text) as T;
}

export async function indexerSearch<T = any>(body: unknown, index = "wazuh-alerts-*"): Promise<T> {
  const base = env("WAZUH_INDEXER_URL");
  const user = env("WAZUH_INDEXER_USER");
  const pass = process.env["WAZUH_INDEXER_PASSWORD"];
  if (!base || !user || !pass) throw new WazuhConfigError("Wazuh Indexer is not configured");
  const res = await timedFetch(`${base}/${index}/_search`, {
    method: "POST",
    headers: { Authorization: basic(user, pass), "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Wazuh Indexer ${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text) as T;
}

export type WazuhAlert = {
  id: string;
  timestamp: string;
  level: number;
  ruleId: string;
  description: string;
  agentId: string;
  agentName: string;
  mitre: string[];
  raw: unknown;
};

export function mapAlertHit(h: any): WazuhAlert {
  const s = h._source ?? {};
  return {
    id: h._id,
    timestamp: s.timestamp ?? s["@timestamp"],
    level: Number(s.rule?.level ?? 0),
    ruleId: String(s.rule?.id ?? ""),
    description: s.rule?.description ?? "",
    agentId: s.agent?.id ?? "",
    agentName: s.agent?.name ?? "",
    mitre: s.rule?.mitre?.id ?? [],
    raw: s,
  };
}
