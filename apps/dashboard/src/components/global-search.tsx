"use client";

import type { components } from "@ntip/contracts";
import { Search } from "lucide-react";
import { useRouter } from "next/navigation";
import { useId, useMemo, useState, type KeyboardEvent } from "react";
import { cn } from "@ntip/ui";

type Topology = components["schemas"]["Topology"];
type SearchResult = Readonly<{ href: string; key: string; label: string; meta: string }>;

export function GlobalSearch() {
  const router = useRouter();
  const listId = useId();
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [topology, setTopology] = useState<Topology | null>(null);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);

  async function ensureTopology(): Promise<void> {
    if (topology !== null || loading) return;
    setLoading(true);
    setFailed(false);
    try {
      const response = await fetch("/api/v1/topology", {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(8_000),
      });
      if (!response.ok) throw new Error("Topology search unavailable");
      setTopology(await response.json() as Topology);
    } catch {
      setFailed(true);
    } finally {
      setLoading(false);
    }
  }

  const results = useMemo((): readonly SearchResult[] => {
    const normalized = query.trim().toLowerCase();
    if (normalized.length < 2 || topology === null) return [];
    const candidates: SearchResult[] = [
      ...topology.vnrs.map((vnr) => ({
        href: `/vnrs/${encodeURIComponent(vnr.name)}`,
        key: `vnr:${vnr.name}`,
        label: vnr.name,
        meta: `VNR · ${vnr.cidr}`,
      })),
      ...topology.nodes.map((node) => ({
        href: `/nodes/${encodeURIComponent(node.id)}`,
        key: `node:${node.id}`,
        label: node.name,
        meta: `Node · ${node.address} · ${node.vnrName}`,
      })),
      ...topology.routes.map((route) => ({
        href: `/nodes/${encodeURIComponent(route.nodeId)}`,
        key: `route:${route.id}`,
        label: route.prefix,
        meta: `Route · ${route.nodeName}`,
      })),
    ];
    return candidates
      .filter((candidate) => `${candidate.label} ${candidate.meta}`.toLowerCase().includes(normalized))
      .sort((left, right) => left.label.localeCompare(right.label))
      .slice(0, 8);
  }, [query, topology]);

  function navigate(result: SearchResult): void {
    setOpen(false);
    setQuery("");
    router.push(result.href);
  }

  function handleKeyDown(event: KeyboardEvent<HTMLInputElement>): void {
    if (event.key === "Escape") {
      setOpen(false);
      return;
    }
    if (results.length === 0) return;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveIndex((index) => (index + 1) % results.length);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex((index) => (index - 1 + results.length) % results.length);
    } else if (event.key === "Enter") {
      event.preventDefault();
      const result = results[activeIndex];
      if (result !== undefined) navigate(result);
    }
  }

  const activeResult = results[activeIndex];
  return (
    <div className="relative w-full max-w-[28rem]">
      <Search aria-hidden="true" className="pointer-events-none absolute start-2.5 top-1/2 z-10 size-3.5 -translate-y-1/2 text-muted-foreground" />
      <input
        type="search"
        value={query}
        role="combobox"
        aria-label="Search VNRs, Nodes, addresses, and routes"
        aria-autocomplete="list"
        aria-controls={listId}
        aria-expanded={open && query.trim().length >= 2}
        aria-activedescendant={activeResult === undefined ? undefined : `${listId}-${activeIndex}`}
        autoComplete="off"
        spellCheck={false}
        placeholder="Search VNRs, Nodes, IPs, routes"
        className="h-8 w-full rounded-sm border border-input bg-secondary ps-8 pe-3 text-xs outline-none placeholder:text-muted-foreground focus:border-ring focus:ring-2 focus:ring-ring/25"
        onFocus={() => { setOpen(true); void ensureTopology(); }}
        onBlur={() => window.setTimeout(() => setOpen(false), 120)}
        onChange={(event) => { setQuery(event.target.value); setActiveIndex(0); setOpen(true); void ensureTopology(); }}
        onKeyDown={handleKeyDown}
      />
      {open && query.trim().length >= 2 ? (
        <div id={listId} role="listbox" className="absolute inset-x-0 top-10 z-50 overflow-hidden rounded-md border border-border bg-elevated shadow-overlay">
          {loading ? <p className="px-3 py-3 text-xs text-muted-foreground">Loading topology register…</p> : null}
          {failed ? <p className="px-3 py-3 text-xs text-warning">Search is unavailable while the API is unreachable.</p> : null}
          {!loading && !failed && results.length === 0 ? <p className="px-3 py-3 text-xs text-muted-foreground">No matching inventory.</p> : null}
          {results.map((result, index) => (
            <button
              key={result.key}
              id={`${listId}-${index}`}
              type="button"
              role="option"
              aria-selected={index === activeIndex}
              className={cn("flex w-full items-center justify-between gap-4 border-b border-border px-3 py-2 text-start last:border-0 hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring", index === activeIndex && "bg-accent")}
              onMouseDown={(event) => event.preventDefault()}
              onMouseEnter={() => setActiveIndex(index)}
              onClick={() => navigate(result)}
            >
              <span className="truncate text-xs font-medium">{result.label}</span>
              <span className="truncate font-mono text-[0.625rem] text-muted-foreground">{result.meta}</span>
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}
