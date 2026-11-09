import { createFileRoute } from "@tanstack/react-router";
import { PageHeader, Panel } from "@/components/soc/common";

export const Route = createFileRoute("/_authenticated/settings")({
  head: () => ({ meta: [{ title: "Settings — BlackBeard" }, { name: "description", content: "Settings in BlackBeard SOC Lite." }] }),
  component: () => (
    <div>
      <PageHeader title="Settings" />
      <Panel>This page is not finished yet.</Panel>
    </div>
  ),
});
