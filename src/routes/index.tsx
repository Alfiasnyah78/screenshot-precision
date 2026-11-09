import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "BlackBeard SOC Lite" },
      { name: "description", content: "Unified BlackFog and Wazuh security console." },
      { property: "og:title", content: "BlackBeard SOC Lite" },
      { property: "og:description", content: "Unified BlackFog and Wazuh security console." },
    ],
  }),
  beforeLoad: () => {
    throw redirect({ to: "/dashboard" });
  },
});
