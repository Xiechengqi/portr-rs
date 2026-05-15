"use client";

import Image from "next/image";
import Link from "next/link";
import { LogOut, Settings, UserRound } from "lucide-react";
import * as React from "react";
import { LoginDialog } from "@/components/auth/login-dialog";
import { AuthProvider, useAuth } from "@/components/auth/auth-provider";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { getDashboard } from "@/lib/api";
import type { DashboardResponse } from "@/lib/types";
import { formatNumber, formatRelativeTime } from "@/lib/utils";

function countDistinctCountries(data: DashboardResponse | null) {
  const set = new Set<string>();
  if (data?.map?.server?.countryCode) set.add(data.map.server.countryCode);
  for (const client of data?.map?.clients || []) {
    if (client.countryCode) set.add(client.countryCode);
  }
  return set.size;
}

function TopbarStats() {
  const [data, setData] = React.useState<DashboardResponse | null>(null);

  const load = React.useCallback(async () => {
    setData(await getDashboard());
  }, []);

  React.useEffect(() => {
    load().catch(console.error);
    const id = window.setInterval(() => load().catch(console.error), 5000);
    return () => window.clearInterval(id);
  }, [load]);

  return (
    <div className="hidden flex-wrap items-center justify-end gap-2 text-xs text-muted-foreground lg:flex">
      <span title="Total number of clients registered on this router.">
        <strong className="text-foreground">{formatNumber(data?.stats?.clients || 0)}</strong> clients
      </span>
      <span className="opacity-40">·</span>
      <span title="Distinct countries currently routing traffic through this router.">
        <strong className="text-foreground">{formatNumber(countDistinctCountries(data))}</strong> countries
      </span>
      <span className="opacity-40">·</span>
      <span title="Clients whose share status is currently active.">
        <strong className="text-foreground">{formatNumber(data?.stats?.activeShares || 0)}</strong> active shares
      </span>
      <span className="opacity-40">·</span>
      <span title="Total HTTP requests currently in-flight across every share.">
        <strong className="text-foreground">{formatNumber(data?.stats?.totalActiveRequests || 0)}</strong> in-flight requests
      </span>
      <span className="border-l pl-3">synced {formatRelativeTime(data?.generatedAt)}</span>
    </div>
  );
}

function Topbar({ active }: { active: "dashboard" | "settings" }) {
  const { session, loading, logout } = useAuth();
  const [loginOpen, setLoginOpen] = React.useState(false);
  const authed = !!session?.authenticated;

  return (
    <header className="mx-auto flex w-[calc(100%-2rem)] max-w-7xl items-center justify-between gap-4 py-5">
      <Link href="/" className="flex items-center gap-3">
        <Image src="/router-logo.svg" alt="" width={36} height={36} className="h-9 w-9" priority />
        <span className="text-base font-extrabold leading-none">CC-Switch Router</span>
      </Link>
      <div className="flex flex-1 items-center justify-end gap-4">
        {active === "dashboard" ? <TopbarStats /> : null}
        {authed ? (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <UserRound className="h-4 w-4" />
                <span className="hidden max-w-48 truncate sm:inline">{session?.user?.email}</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>{session?.user?.email}</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {session?.isAdmin ? (
                <DropdownMenuItem asChild>
                  <Link href="/settings/" target="_blank" rel="noopener noreferrer">
                    <Settings className="h-4 w-4" />
                    Settings
                  </Link>
                </DropdownMenuItem>
              ) : null}
              <DropdownMenuItem onClick={() => logout().catch(console.error)} className="text-destructive">
                <LogOut className="h-4 w-4" />
                Logout
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        ) : (
          <Button variant="outline" size="sm" onClick={() => setLoginOpen(true)} disabled={loading}>
            Login
          </Button>
        )}
      </div>
      <LoginDialog open={loginOpen} onOpenChange={setLoginOpen} />
    </header>
  );
}

export function AppShell({
  active,
  children,
}: {
  active: "dashboard" | "settings";
  children: React.ReactNode;
}) {
  return (
    <AuthProvider>
      <Topbar active={active} />
      {children}
    </AuthProvider>
  );
}
