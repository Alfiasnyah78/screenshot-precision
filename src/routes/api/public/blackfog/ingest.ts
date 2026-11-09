import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";

// BlackFog → BlackBeard ingest. Send events from a log forwarder (or BlackFog
// webhook/SIEM export) with header: Authorization: Bearer <BLACKFOG_INGEST_TOKEN>
const eventSchema = z.object({
  timestamp: z.string().datetime({ offset: true }).optional(),
  endpoint: z.string().min(1).max(255),
  agent_id: z.string().max(64).optional(),
  process_name: z.string().max(255).optional(),
  dest_ip: z.string().max(64).optional(),
  dest_country: z.string().max(64).optional(),
  lat: z.number().min(-90).max(90).optional(),
  lon: z.number().min(-180).max(180).optional(),
  action: z.string().max(32).optional(),
  category: z.string().max(64).optional(),
  mitre_technique: z.string().max(32).optional(),
  agent_version: z.string().max(32).optional(),
}).passthrough();

const bodySchema = z.union([eventSchema, z.array(eventSchema).max(1000)]);

function safeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export const Route = createFileRoute("/api/public/blackfog/ingest")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const expected = process.env["BLACKFOG_INGEST_TOKEN"];
        if (!expected) return Response.json({ error: "Ingest not configured" }, { status: 503 });
        const auth = request.headers.get("authorization") ?? "";
        const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
        if (!safeEqual(token, expected)) return Response.json({ error: "Unauthorized" }, { status: 401 });

        let json: unknown;
        try {
          json = await request.json();
        } catch {
          return Response.json({ error: "Invalid JSON" }, { status: 400 });
        }
        const parsed = bodySchema.safeParse(json);
        if (!parsed.success) return Response.json({ error: parsed.error.flatten() }, { status: 400 });
        const list = Array.isArray(parsed.data) ? parsed.data : [parsed.data];

        const rows = list.map((e) => ({
          occurred_at: e.timestamp ?? new Date().toISOString(),
          endpoint: e.endpoint,
          agent_id: e.agent_id ?? null,
          process_name: e.process_name ?? null,
          dest_ip: e.dest_ip ?? null,
          dest_country: e.dest_country ?? null,
          lat: e.lat ?? null,
          lon: e.lon ?? null,
          action: e.action ?? "blocked",
          category: e.category ?? null,
          mitre_technique: e.mitre_technique ?? null,
          raw: e as any,
        }));

        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const { error } = await supabaseAdmin.from("blackfog_events").insert(rows);
        if (error) {
          console.error(JSON.stringify({ level: "error", msg: "blackfog ingest failed", error: error.message }));
          return Response.json({ error: "Insert failed" }, { status: 500 });
        }
        return Response.json({ inserted: rows.length });
      },
    },
  },
});
