import type { Metadata } from "next";
import type { components } from "@ntip/contracts";
import { UsersWorkspace } from "@/components/security/users-workspace";
import { apiGet } from "@/lib/server-api";

export const metadata: Metadata = {
  title: "Users | NTIP",
};

type UserPage = components["schemas"]["UserPage"];

export default async function UsersPage() {
  const users = await apiGet<UserPage>("/users?limit=50");
  return <UsersWorkspace initialUsers={users} />;
}
