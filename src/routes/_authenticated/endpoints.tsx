import { createFileRoute } from "@tanstack/react-router";
import { PageHeader, Panel } from "@/components/soc/common";

export const Route = createFileRoute("/_authenticated/endpoints")({
  head: () => ({ meta: [{ title: "Endpoints — BlackBeard" }, { name: "description", content: "Endpoints in BlackBeard SOC Lite." }] }),
  component: () => (
    <div>
      <PageHeader title="Endpoints" />
      <Panel>This page is not finished yet.</Panel>
    </div>
  ),
});
