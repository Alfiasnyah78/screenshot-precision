import { createFileRoute } from "@tanstack/react-router";
import { PageHeader, Panel } from "@/components/soc/common";

export const Route = createFileRoute("/_authenticated/blackfog")({
  head: () => ({ meta: [{ title: "BlackFog Events — BlackBeard" }, { name: "description", content: "BlackFog Events in BlackBeard SOC Lite." }] }),
  component: () => (
    <div>
      <PageHeader title="BlackFog Events" />
      <Panel>This page is not finished yet.</Panel>
    </div>
  ),
});
