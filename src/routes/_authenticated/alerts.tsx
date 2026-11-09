import { createFileRoute } from "@tanstack/react-router";
import { PageHeader, Panel } from "@/components/soc/common";

export const Route = createFileRoute("/_authenticated/alerts")({
  head: () => ({ meta: [{ title: "Wazuh Alerts — BlackBeard" }, { name: "description", content: "Wazuh Alerts in BlackBeard SOC Lite." }] }),
  component: () => (
    <div>
      <PageHeader title="Wazuh Alerts" />
      <Panel>This page is not finished yet.</Panel>
    </div>
  ),
});
