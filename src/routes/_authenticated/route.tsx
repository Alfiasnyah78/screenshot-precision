import { createFileRoute, Link, Outlet, redirect, useRouter } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Activity, Crosshair, LayoutDashboard, LogOut, Monitor, Settings, ShieldAlert, Skull, Waves } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { statusQuery } from "@/lib/queries";
import { Badge } from "@/components/ui/badge";

export const Route = createFileRoute("/_authenticated")({
  ssr: false,
  beforeLoad: async () => {
    const { data } = await supabase.auth.getUser();
    if (!data.user) throw redirect({ to: "/auth" });
  },
  component: Shell,
});

const NAV = [
  { to: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { to: "/blackfog", label: "BlackFog Events", icon: Waves },
  { to: "/alerts", label: "Wazuh Alerts", icon: ShieldAlert },
  { to: "/correlation", label: "Correlation", icon: Crosshair },
  { to: "/endpoints", label: "Endpoints", icon: Monitor },
  { to: "/settings", label: "Settings", icon: Settings },
] as const;

function Shell() {
  const router = useRouter();
  const { data: status } = useQuery(statusQuery());
  return (
    <div className="flex min-h-screen bg-background">
      <aside className="sticky top-0 flex h-screen w-60 shrink-0 flex-col border-r border-sidebar-border bg-sidebar">
        <div className="flex items-center gap-3 px-5 py-5">
          <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary text-primary-foreground">
            <Skull className="h-5 w-5" />
          </div>
          <div>
            <div className="font-semibold tracking-tight text-sidebar-foreground">BlackBeard</div>
            <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">SOC Lite</div>
          </div>
        </div>
        <nav className="flex-1 space-y-1 px-3">
          {NAV.map((n) => (
            <Link
              key={n.to}
              to={n.to}
              className="flex items-center gap-3 rounded-md px-3 py-2 text-sm text-sidebar-foreground transition-colors hover:bg-sidebar-accent"
              activeProps={{ className: "bg-sidebar-accent text-primary" }}
            >
              <n.icon className="h-4 w-4" />
              {n.label}
            </Link>
          ))}
        </nav>
        <div className="space-y-3 border-t border-sidebar-border p-4">
          <div className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
            <Activity className={status?.config.indexer ? "h-3 w-3 text-success" : "h-3 w-3 text-destructive"} />
            Wazuh {status?.config.indexer && status?.config.api ? "linked" : "not linked"}
          </div>
          <div className="truncate text-xs text-muted-foreground">{status?.email}</div>
          <div className="flex items-center justify-between">
            <Badge variant="outline" className="font-mono uppercase">{status?.role ?? "…"}</Badge>
            <button
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
              onClick={async () => {
                await supabase.auth.signOut();
                router.navigate({ to: "/auth" });
              }}
            >
              <LogOut className="h-3 w-3" /> Sign out
            </button>
          </div>
        </div>
      </aside>
      <main className="min-w-0 flex-1 p-8">
        <Outlet />
      </main>
    </div>
  );
}
