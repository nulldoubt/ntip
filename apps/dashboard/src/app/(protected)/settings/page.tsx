import type { Metadata } from "next";
import type { components } from "@ntip/contracts";
import { SettingsWorkspace } from "@/components/settings/settings-workspace";
import { apiGet, apiGetResult } from "@/lib/server-api";

export const metadata: Metadata = {
  title: "Settings | NTIP",
};

type SettingsState = components["schemas"]["SettingsState"];
type SettingsRevisionPage = components["schemas"]["SettingsRevisionPage"];
type Overview = components["schemas"]["Overview"];

export default async function SettingsPage() {
  const [settings, revisions, overview] = await Promise.all([
    apiGetResult<SettingsState>("/settings"),
    apiGet<SettingsRevisionPage>("/settings/revisions?limit=50"),
    apiGet<Overview>("/overview"),
  ]);

  return (
    <SettingsWorkspace
      initialOverview={overview}
      initialRevisions={revisions}
      initialSettings={settings.data}
      initialSettingsEtag={settings.etag}
    />
  );
}
