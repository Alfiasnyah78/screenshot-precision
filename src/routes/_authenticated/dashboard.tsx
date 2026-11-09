import { createFileRoute } from "@tanstack/react-router";
import { PageHeader, Panel } from "@/components/soc/common";

export const Route = createFileRoute("/_authenticated/dashboard")({
  head: () => ({ meta: [{ title: "Overview — BlackBeard" }, { name: "description", content: "Overview in BlackBeard SOC Lite." }] }),
  component: () => (
    <div>
      <PageHeader title="Overview" />
      <Panel>This page is not finished yet.</Panel>
    </div>
  ),
});
