import { useCallback, useEffect, useState } from "react";
import {
  Settings as SettingsSvc,
  Profiles as ProfilesSvc,
} from "@bindings/services";
import type { Config } from "@bindings/services/models.js";
import { Button } from "../components/Button";
import { Input } from "../components/Input";
import { Switch } from "../components/Switch";
import { Tabs } from "../components/Tabs";

interface Ctx {
  cfg: Config;
  setField: <K extends keyof Config>(k: K, v: Config[K]) => void;
}

export default function Settings() {
  const [username, setUsername] = useState("");
  const [profile, setProfile] = useState("");
  const [cfg, setCfg] = useState<Config | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      const u = await ProfilesSvc.Username();
      const active = await ProfilesSvc.GetActive();
      const profileName = active.profileName || "default";
      setUsername(u);
      setProfile(profileName);
      const c = await SettingsSvc.GetConfig({ profileName, username: u });
      setCfg(c);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const setField: Ctx["setField"] = (k, v) => {
    setCfg((c) => (c ? { ...c, [k]: v } : c));
  };

  const save = async () => {
    if (!cfg) return;
    setSaving(true);
    try {
      await SettingsSvc.SetConfig({
        profileName: profile,
        username,
        managementUrl: cfg.managementUrl,
        adminUrl: cfg.adminUrl,
        interfaceName: cfg.interfaceName,
        wireguardPort: cfg.wireguardPort,
        mtu: cfg.mtu,
        preSharedKey: cfg.preSharedKey,
        disableAutoConnect: cfg.disableAutoConnect,
        serverSshAllowed: cfg.serverSshAllowed,
        rosenpassEnabled: cfg.rosenpassEnabled,
        rosenpassPermissive: cfg.rosenpassPermissive,
        disableNotifications: cfg.disableNotifications,
        lazyConnectionEnabled: cfg.lazyConnectionEnabled,
        blockInbound: cfg.blockInbound,
        networkMonitor: cfg.networkMonitor,
        disableClientRoutes: cfg.disableClientRoutes,
        disableServerRoutes: cfg.disableServerRoutes,
        disableDns: cfg.disableDns,
        disableIpv6: cfg.disableIpv6,
        blockLanAccess: cfg.blockLanAccess,
        enableSshRoot: cfg.enableSshRoot,
        enableSshSftp: cfg.enableSshSftp,
        enableSshLocalPortForwarding: cfg.enableSshLocalPortForwarding,
        enableSshRemotePortForwarding: cfg.enableSshRemotePortForwarding,
        disableSshAuth: cfg.disableSshAuth,
        sshJwtCacheTtl: cfg.sshJwtCacheTtl,
      });
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  };

  if (!cfg) {
    return <div className="p-6 text-sm text-nb-gray-500">Loading…</div>;
  }

  const ctx: Ctx = { cfg, setField };

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b border-nb-gray-200 px-6 py-3 dark:border-nb-gray-800">
        <h1 className="text-xl font-semibold">Settings</h1>
        <Button onClick={save} disabled={saving}>
          {saving ? "Saving…" : "Save"}
        </Button>
      </div>
      {error && <p className="px-6 py-2 text-sm text-red-500">{error}</p>}
      <div className="flex-1 overflow-hidden">
        <Tabs
          tabs={[
            { value: "conn", label: "Connection", content: <ConnectionTab {...ctx} /> },
            { value: "net", label: "Network", content: <NetworkTab {...ctx} /> },
            { value: "ssh", label: "SSH", content: <SSHTab {...ctx} /> },
          ]}
        />
      </div>
    </div>
  );
}

function ConnectionTab({ cfg, setField }: Ctx) {
  return (
    <div className="grid max-w-2xl gap-4 p-6">
      <Input
        label="Management URL"
        value={cfg.managementUrl}
        onChange={(e) => setField("managementUrl", e.target.value)}
      />
      <Input
        label="Pre-shared key"
        type="password"
        value={cfg.preSharedKey}
        onChange={(e) => setField("preSharedKey", e.target.value)}
      />
      <Input
        label="Interface name"
        value={cfg.interfaceName}
        onChange={(e) => setField("interfaceName", e.target.value)}
      />
      <div className="grid grid-cols-2 gap-4">
        <Input
          label="WireGuard port"
          type="number"
          value={cfg.wireguardPort}
          onChange={(e) => setField("wireguardPort", Number(e.target.value))}
        />
        <Input
          label="MTU"
          type="number"
          value={cfg.mtu}
          onChange={(e) => setField("mtu", Number(e.target.value))}
        />
      </div>
      <Switch
        checked={cfg.rosenpassEnabled}
        onChange={(v) => setField("rosenpassEnabled", v)}
        label="Rosenpass (post-quantum)"
      />
      <Switch
        checked={cfg.rosenpassPermissive}
        onChange={(v) => setField("rosenpassPermissive", v)}
        label="Rosenpass permissive mode"
      />
    </div>
  );
}

function NetworkTab({ cfg, setField }: Ctx) {
  return (
    <div className="grid max-w-xl gap-4 p-6">
      <Switch
        checked={cfg.networkMonitor}
        onChange={(v) => setField("networkMonitor", v)}
        label="Network monitor"
      />
      <Switch
        checked={cfg.disableDns}
        onChange={(v) => setField("disableDns", v)}
        label="Disable DNS"
      />
      <Switch
        checked={cfg.disableClientRoutes}
        onChange={(v) => setField("disableClientRoutes", v)}
        label="Disable client routes"
      />
      <Switch
        checked={cfg.disableServerRoutes}
        onChange={(v) => setField("disableServerRoutes", v)}
        label="Disable server routes"
      />
      <Switch
        checked={cfg.disableIpv6}
        onChange={(v) => setField("disableIpv6", v)}
        label="Disable IPv6 overlay addressing"
      />
      <Switch
        checked={cfg.blockLanAccess}
        onChange={(v) => setField("blockLanAccess", v)}
        label="Block LAN access"
      />
      <Switch
        checked={cfg.blockInbound}
        onChange={(v) => setField("blockInbound", v)}
        label="Block inbound connections"
      />
    </div>
  );
}

function SSHTab({ cfg, setField }: Ctx) {
  return (
    <div className="grid max-w-xl gap-4 p-6">
      <Switch
        checked={cfg.serverSshAllowed}
        onChange={(v) => setField("serverSshAllowed", v)}
        label="Server SSH allowed"
      />
      <Switch
        checked={cfg.enableSshRoot}
        onChange={(v) => setField("enableSshRoot", v)}
        label="SSH root login"
      />
      <Switch
        checked={cfg.enableSshSftp}
        onChange={(v) => setField("enableSshSftp", v)}
        label="SFTP"
      />
      <Switch
        checked={cfg.enableSshLocalPortForwarding}
        onChange={(v) => setField("enableSshLocalPortForwarding", v)}
        label="Local port forwarding"
      />
      <Switch
        checked={cfg.enableSshRemotePortForwarding}
        onChange={(v) => setField("enableSshRemotePortForwarding", v)}
        label="Remote port forwarding"
      />
      <Switch
        checked={cfg.disableSshAuth}
        onChange={(v) => setField("disableSshAuth", v)}
        label="Disable SSH auth"
      />
      <Input
        label="JWT cache TTL (seconds)"
        type="number"
        value={cfg.sshJwtCacheTtl}
        onChange={(e) => setField("sshJwtCacheTtl", Number(e.target.value))}
      />
    </div>
  );
}
