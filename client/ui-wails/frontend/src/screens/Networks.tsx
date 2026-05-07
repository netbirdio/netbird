import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import { Networks as NetworksSvc } from "@bindings/services";
import type { Network } from "@bindings/services/models.js";
import { Button } from "../components/Button";
import { Tabs } from "../components/Tabs";

export default function Networks() {
  const [routes, setRoutes] = useState<Network[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const list = await NetworksSvc.List();
      setRoutes(list);
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const toggle = async (id: string, selected: boolean) => {
    try {
      if (selected) {
        await NetworksSvc.Deselect({ networkIds: [id], append: false, all: false });
      } else {
        await NetworksSvc.Select({ networkIds: [id], append: true, all: false });
      }
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  };

  const setAll = async (ids: string[], on: boolean) => {
    try {
      if (on) {
        await NetworksSvc.Select({ networkIds: ids, append: false, all: true });
      } else {
        await NetworksSvc.Deselect({ networkIds: ids, append: false, all: true });
      }
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  };

  const overlapping = useMemo(() => filterOverlapping(routes), [routes]);
  const exitNodes = useMemo(() => routes.filter((r) => r.range === "0.0.0.0/0"), [routes]);

  return (
    <div className="flex h-full flex-col p-6">
      <div className="mb-3 flex items-center justify-between">
        <h1 className="text-xl font-semibold">Networks</h1>
        <Button variant="secondary" size="sm" onClick={refresh} disabled={loading}>
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} strokeWidth={1.5} />
          Refresh
        </Button>
      </div>

      {error && (
        <p className="mb-2 text-sm text-red-500">{error}</p>
      )}

      <div className="flex-1 overflow-hidden">
        <Tabs
          tabs={[
            {
              value: "all",
              label: `All (${routes.length})`,
              content: <NetworkList routes={routes} onToggle={toggle} onSetAll={setAll} />,
            },
            {
              value: "overlap",
              label: `Overlapping (${overlapping.length})`,
              content: <NetworkList routes={overlapping} onToggle={toggle} onSetAll={setAll} />,
            },
            {
              value: "exit",
              label: `Exit-node (${exitNodes.length})`,
              content: <NetworkList routes={exitNodes} onToggle={toggle} onSetAll={setAll} />,
            },
          ]}
        />
      </div>
    </div>
  );
}

function NetworkList({
  routes,
  onToggle,
  onSetAll,
}: {
  routes: Network[];
  onToggle: (id: string, selected: boolean) => void;
  onSetAll: (ids: string[], on: boolean) => void;
}) {
  if (routes.length === 0) {
    return <p className="p-4 text-sm text-nb-gray-500">No networks.</p>;
  }
  const ids = routes.map((r) => r.id);
  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 gap-2 border-b border-nb-gray-200 px-4 py-2 dark:border-nb-gray-800">
        <Button size="sm" variant="ghost" onClick={() => onSetAll(ids, true)}>
          Select all
        </Button>
        <Button size="sm" variant="ghost" onClick={() => onSetAll(ids, false)}>
          Deselect all
        </Button>
      </div>
      <ul className="flex-1 overflow-auto divide-y divide-nb-gray-200 dark:divide-nb-gray-800">
        {routes.map((r) => (
          <li key={r.id} className="flex items-start gap-3 px-4 py-3">
            <input
              type="checkbox"
              checked={r.selected}
              onChange={() => onToggle(r.id, r.selected)}
              className="mt-1 h-4 w-4 accent-netbird"
            />
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium">{r.id}</p>
              <p className="truncate font-mono text-xs text-nb-gray-500">{r.range}</p>
              {r.domains.length > 0 && (
                <p className="mt-0.5 truncate text-xs text-nb-gray-500">
                  {r.domains.join(", ")}
                </p>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function filterOverlapping(routes: Network[]): Network[] {
  const byRange = new Map<string, Network[]>();
  for (const r of routes) {
    if (r.domains.length > 0) continue;
    const arr = byRange.get(r.range) ?? [];
    arr.push(r);
    byRange.set(r.range, arr);
  }
  const out: Network[] = [];
  for (const arr of byRange.values()) {
    if (arr.length > 1) out.push(...arr);
  }
  return out;
}
