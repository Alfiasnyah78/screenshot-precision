import { createFileRoute } from "@tanstack/react-router";
import { PageHeader, Panel } from "@/components/soc/common";

export const Route = createFileRoute("/_authenticated/correlation")({
  head: () => ({ meta: [{ title: "Correlation — BlackBeard" }, { name: "description", content: "Correlation in BlackBeard SOC Lite." }] }),
  component: () => (
    <div>
      <PageHeader title="Correlation" />
      <Panel>This page is not finished yet.</Panel>
    </div>
  ),
});
