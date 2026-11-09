import type { ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Panel({ title, children, className }: { title?: string; children: ReactNode; className?: string }) {
  return (
    <section className={cn("rounded-lg border border-border bg-card p-5", className)}>
      {title && <h2 className="mb-4 font-mono text-xs uppercase tracking-widest text-muted-foreground">{title}</h2>}
      {children}
    </section>
  );
}

export function SourceNotice({ error }: { error: string | null | undefined }) {
  if (!error) return null;
  const msg =
    error === "not_configured"
      ? "Wazuh is not connected yet. An admin needs to add the Wazuh connection details."
      : `Wazuh could not be reached: ${error}`;
  return (
    <div className="mb-6 flex items-start gap-3 rounded-md border border-warning/40 bg-warning/10 p-4 text-sm">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
      <span>{msg}</span>
    </div>
  );
}

export function LevelBadge({ level }: { level: number }) {
  const cls =
    level >= 12
      ? "border-destructive/50 bg-destructive/15 text-destructive"
      : level >= 10
        ? "border-primary/50 bg-primary/15 text-primary"
        : level >= 7
          ? "border-warning/50 bg-warning/10 text-warning"
          : "border-border text-muted-foreground";
  return <Badge variant="outline" className={cn("font-mono", cls)}>L{level}</Badge>;
}

export function fmtTime(t: string | null | undefined) {
  if (!t) return "—";
  return new Date(t).toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function download(filename: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function toCsv(rows: Record<string, unknown>[]) {
  if (!rows.length) return "";
  const cols = Object.keys(rows[0] ?? {});
  const esc = (v: unknown) => {
    const s = v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [cols.join(","), ...rows.map((r) => cols.map((c) => esc(r[c])).join(","))].join("\n");
}
