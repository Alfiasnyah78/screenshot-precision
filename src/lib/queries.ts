import { queryOptions } from "@tanstack/react-query";
import { getCorrelation, getOverview, getStatus, listAgents, listAlerts } from "./soc.functions";

export const statusQuery = () =>
  queryOptions({ queryKey: ["status"], queryFn: () => getStatus(), staleTime: 60_000 });

export const overviewQuery = (range: "24h" | "7d" | "30d") =>
  queryOptions({ queryKey: ["overview", range], queryFn: () => getOverview({ data: { range } }), refetchInterval: 60_000 });

export type AlertFilters = { hours: number; minLevel: number; agent?: string; mitre?: string; limit: number };
export const alertsQuery = (f: AlertFilters) =>
  queryOptions({ queryKey: ["alerts", f], queryFn: () => listAlerts({ data: f }) });

export const agentsQuery = () =>
  queryOptions({ queryKey: ["agents"], queryFn: () => listAgents(), refetchInterval: 30_000 });

export const correlationQuery = (hours: number) =>
  queryOptions({ queryKey: ["correlation", hours], queryFn: () => getCorrelation({ data: { hours } }), refetchInterval: 60_000 });
