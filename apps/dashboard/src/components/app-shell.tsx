"use client";

import { Button, cn, Tooltip, TooltipContent, TooltipTrigger } from "@ntip/ui";
import {
  Activity,
  CircleUserRound,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Monitor,
  Moon,
  Network,
  Server,
  Settings,
  Sun,
  Users,
  Waypoints,
  type LucideIcon,
} from "lucide-react";
import { useTheme } from "next-themes";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useSyncExternalStore, type ReactNode } from "react";
import type { DashboardAuthContext } from "@/components/auth-context";
import { AuthContextProvider } from "@/components/auth-context";
import { GlobalSearch } from "@/components/global-search";
import { UtcClock } from "@/components/utc-clock";
import { can, type Capability } from "@/lib/capabilities";

type NavItem = Readonly<{
  href: string;
  label: string;
  icon: LucideIcon;
  capability?: Capability;
}>;

const primaryNavigation: readonly NavItem[] = [
  { href: "/overview", label: "Overview", icon: LayoutDashboard },
  { href: "/vnrs", label: "VNRs", icon: Network },
  { href: "/nodes", label: "Nodes", icon: Server },
  { href: "/topology", label: "Topology", icon: Waypoints },
  { href: "/activity", label: "Activity", icon: Activity },
];

const securityNavigation: readonly NavItem[] = [
  { href: "/security/users", label: "Users", icon: Users, capability: "users:manage" },
  { href: "/security/sessions", label: "Sessions", icon: KeyRound },
];

function isCurrentPath(pathname: string, href: string): boolean {
  return pathname === href || (href !== "/overview" && pathname.startsWith(`${href}/`));
}

function NavigationLink({ item, pathname }: Readonly<{ item: NavItem; pathname: string }>) {
  const active = isCurrentPath(pathname, item.href);
  const Icon = item.icon;
  return (
    <Link
      href={item.href}
      aria-current={active ? "page" : undefined}
      className={cn(
        "group relative flex h-9 items-center gap-3 px-3 text-sm font-medium transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring",
        active
          ? "bg-primary-muted text-primary-strong"
          : "text-muted-foreground hover:bg-accent hover:text-foreground",
      )}
    >
      {active ? <span className="absolute inset-y-1.5 left-0 w-0.5 bg-primary" /> : null}
      <Icon aria-hidden="true" className="size-4" strokeWidth={1.7} />
      <span>{item.label}</span>
    </Link>
  );
}

function ThemeControl() {
  const { theme, setTheme } = useTheme();
  const mounted = useSyncExternalStore(
    () => () => undefined,
    () => true,
    () => false,
  );

  const current = mounted ? (theme ?? "system") : "system";
  const next = current === "system" ? "light" : current === "light" ? "dark" : "system";
  const label = `Theme: ${current}. Switch to ${next}.`;
  const Icon = current === "light" ? Sun : current === "dark" ? Moon : Monitor;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          size="icon"
          variant="ghost"
          aria-label={label}
          onClick={() => setTheme(next)}
        >
          <Icon aria-hidden="true" />
        </Button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}

function SessionControl({ auth }: Readonly<{ auth: DashboardAuthContext }>) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function logout() {
    setPending(true);
    setError(null);
    try {
      const response = await fetch("/api/v1/auth/logout", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Idempotency-Key": crypto.randomUUID(),
          "X-CSRF-Token": auth.csrfToken,
        },
      });
      if (!response.ok && response.status !== 401) throw new Error("Sign out failed");
      window.location.assign("/login");
    } catch {
      setError("Sign out failed. Try again.");
      setPending(false);
    }
  }

  return (
    <div className="flex items-center gap-1">
      <span className="sr-only" aria-live="polite">
        {error}
      </span>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            type="button"
            size="icon"
            variant="ghost"
            aria-label="Sign out"
            disabled={pending}
            onClick={() => void logout()}
          >
            <LogOut aria-hidden="true" />
          </Button>
        </TooltipTrigger>
        <TooltipContent>{pending ? "Signing out" : error ?? "Sign out"}</TooltipContent>
      </Tooltip>
    </div>
  );
}

function titleForPath(pathname: string): string {
  const matches = [...primaryNavigation, ...securityNavigation, { href: "/settings", label: "Settings", icon: Settings }]
    .filter((item) => isCurrentPath(pathname, item.href))
    .sort((left, right) => right.href.length - left.href.length);
  return matches[0]?.label ?? "Management";
}

export function AppShell({
  auth,
  children,
}: Readonly<{ auth: DashboardAuthContext; children: ReactNode }>) {
  const pathname = usePathname();
  const securityItems = securityNavigation.filter(
    (item) => item.capability === undefined || can(auth.user.role, item.capability),
  );
  const pageTitle = titleForPath(pathname);

  return (
    <AuthContextProvider auth={auth}>
      <div className="grid h-screen min-h-[42rem] grid-cols-[13rem_minmax(0,1fr)] overflow-hidden bg-background">
        <aside className="flex min-h-0 flex-col border-r border-border bg-card" aria-label="Primary navigation">
          <div className="flex h-14 shrink-0 items-center border-b border-border px-4">
            <Link
              href="/overview"
              className="flex items-baseline gap-2 rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              aria-label="NTIP overview"
            >
              <span className="font-mono text-base font-semibold tracking-[0.11em] text-primary-strong">NTIP</span>
              <span className="text-[0.625rem] font-semibold uppercase tracking-[0.09em] text-muted-foreground">
                Management
              </span>
            </Link>
          </div>

          <nav className="min-h-0 flex-1 overflow-y-auto py-3">
            <div className="space-y-0.5 px-2">
              {primaryNavigation.map((item) => (
                <NavigationLink key={item.href} item={item} pathname={pathname} />
              ))}
            </div>

            <div className="mx-3 my-4 border-t border-border" />
            <p className="mb-1 px-5 font-mono text-[0.625rem] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Security
            </p>
            <div className="space-y-0.5 px-2">
              {securityItems.map((item) => (
                <NavigationLink key={item.href} item={item} pathname={pathname} />
              ))}
            </div>
          </nav>

          <div className="shrink-0 border-t border-border p-2">
            <NavigationLink
              item={{ href: "/settings", label: "Settings", icon: Settings }}
              pathname={pathname}
            />
          </div>
        </aside>

        <div className="flex min-h-0 min-w-0 flex-col">
          <header className="grid h-14 shrink-0 grid-cols-[minmax(8rem,1fr)_minmax(14rem,28rem)_minmax(16rem,1fr)] items-center gap-3 border-b border-border bg-card px-5">
            <div className="flex min-w-0 items-center gap-3">
              <h1 className="truncate text-sm font-semibold">{pageTitle}</h1>
              <span className="h-4 w-px bg-border" aria-hidden="true" />
              <span className="font-mono text-[0.6875rem] text-muted-foreground">
                role:{auth.user.role}
              </span>
            </div>
            <GlobalSearch />
            <div className="flex items-center justify-end gap-2">
              <UtcClock />
              <span className="h-4 w-px bg-border" aria-hidden="true" />
              <div className="flex items-center gap-2 border-r border-border pr-3 text-xs">
                <span className="flex size-7 items-center justify-center bg-secondary text-muted-foreground">
                  <CircleUserRound aria-hidden="true" className="size-4" />
                </span>
                <span className="max-w-40 truncate font-medium">{auth.user.username}</span>
              </div>
              <ThemeControl />
              <SessionControl auth={auth} />
            </div>
          </header>
          <main className="min-h-0 flex-1 overflow-y-auto bg-background">{children}</main>
        </div>
      </div>
    </AuthContextProvider>
  );
}
