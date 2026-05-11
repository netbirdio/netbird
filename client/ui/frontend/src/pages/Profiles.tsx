import { FormEvent, useCallback, useEffect, useState } from "react";
import { Plus, RefreshCw } from "lucide-react";
import {
  Profiles as ProfilesSvc,
  Connection,
} from "../../bindings/github.com/netbirdio/netbird/client/ui/services";
import type { Profile } from "../../bindings/github.com/netbirdio/netbird/client/ui/services/models.js";
import { Button } from "../components/Button";
import { Input } from "../components/Input";
import { Card } from "../components/Card";

export default function Profiles() {
  const [username, setUsername] = useState("");
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const u = username || (await ProfilesSvc.Username());
      if (!username) setUsername(u);
      const list = await ProfilesSvc.List(u);
      setProfiles(list);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, [username]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const select = async (name: string) => {
    try {
      await ProfilesSvc.Switch({ profileName: name, username });
      await Connection.Up({ profileName: name, username });
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  };

  const deregister = async (name: string) => {
    try {
      await Connection.Logout({ profileName: name, username });
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  };

  const remove = async (name: string) => {
    if (name === "default") return;
    try {
      await ProfilesSvc.Remove({ profileName: name, username });
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="space-y-4 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Profiles</h1>
        <div className="flex gap-2">
          <Button variant="secondary" size="sm" onClick={refresh}>
            <RefreshCw className="h-3.5 w-3.5" strokeWidth={1.5} /> Refresh
          </Button>
          <Button size="sm" onClick={() => setAdding(true)}>
            <Plus className="h-3.5 w-3.5" strokeWidth={1.5} /> Add
          </Button>
        </div>
      </div>

      {error && <p className="text-sm text-red-500">{error}</p>}

      <div className="space-y-2">
        {profiles.map((p) => (
          <Card key={p.name} className="flex items-center gap-3">
            <input
              type="radio"
              name="active-profile"
              checked={p.isActive}
              onChange={() => select(p.name)}
              className="h-4 w-4 accent-netbird"
            />
            <div className="flex-1">
              <p className="text-sm font-medium">{p.name}</p>
              {p.isActive && <p className="text-xs text-nb-gray-500">Active</p>}
            </div>
            <Button size="sm" variant="ghost" onClick={() => deregister(p.name)}>
              Deregister
            </Button>
            <Button
              size="sm"
              variant="danger"
              disabled={p.name === "default"}
              onClick={() => remove(p.name)}
            >
              Remove
            </Button>
          </Card>
        ))}
        {profiles.length === 0 && (
          <p className="text-sm text-nb-gray-500">No profiles.</p>
        )}
      </div>

      {adding && (
        <AddDialog
          username={username}
          onClose={() => setAdding(false)}
          onAdded={async () => {
            setAdding(false);
            await refresh();
          }}
        />
      )}
    </div>
  );
}

function AddDialog({
  username,
  onClose,
  onAdded,
}: {
  username: string;
  onClose: () => void;
  onAdded: () => void;
}) {
  const [name, setName] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    try {
      await ProfilesSvc.Add({ profileName: name.trim(), username });
      onAdded();
    } catch (e) {
      setErr(String(e));
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <form
        onSubmit={submit}
        className="w-80 rounded-lg border border-nb-gray-200 bg-white p-4 shadow-lg dark:border-nb-gray-800 dark:bg-nb-gray-925"
      >
        <h2 className="mb-3 text-base font-semibold">New profile</h2>
        <Input
          autoFocus
          label="Name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        {err && <p className="mt-2 text-xs text-red-500">{err}</p>}
        <div className="mt-4 flex justify-end gap-2">
          <Button type="button" variant="ghost" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" size="sm">
            Add
          </Button>
        </div>
      </form>
    </div>
  );
}
