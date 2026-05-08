import FancyToggleSwitch from "@/components/FancyToggleSwitch";
import { HelpText } from "@/components/HelpText";
import { Input } from "@/components/Input";
import { Label } from "@/components/Label";
import { cn } from "@/lib/cn";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/modules/settings/SettingsContext.tsx";
import { type ChangeEvent, useEffect, useState } from "react";

export function SettingsSSH() {
    const { config, setField } = useSettings();
    const isSSHServerEnabled = config.serverSshAllowed;
    const [jwtTtlInput, setJwtTtlInput] = useState(String(config.sshJwtCacheTtl));

    // Keep the local input in sync when the config changes from elsewhere
    useEffect(() => {
        setJwtTtlInput(String(config.sshJwtCacheTtl));
    }, [config.sshJwtCacheTtl]);

    const handleJwtTtlChange = (e: ChangeEvent<HTMLInputElement>) => {
        const v = e.target.value;
        setJwtTtlInput(v);
        if (v === "") return;
        const n = Number(v);
        if (Number.isFinite(n) && n >= 0) {
            setField("sshJwtCacheTtl", n);
        }
    };

    const handleJwtTtlBlur = () => {
        if (jwtTtlInput === "") {
            setJwtTtlInput("0");
            setField("sshJwtCacheTtl", 0);
            return;
        }
        const n = Number(jwtTtlInput);
        if (!Number.isFinite(n) || n < 0) {
            setJwtTtlInput(String(config.sshJwtCacheTtl));
        }
    };
    return (
        <>
            <SectionGroup title={"Server"}>
                <FancyToggleSwitch
                    value={config.serverSshAllowed}
                    onChange={(v) => setField("serverSshAllowed", v)}
                    label={"Enable SSH Server"}
                    helpText={
                        "Run the NetBird SSH server on this host so other peers can connect to it."
                    }
                />
            </SectionGroup>

            <SectionGroup title={"Capabilities"} disabled={!isSSHServerEnabled}>
                <FancyToggleSwitch
                    value={config.enableSshRoot}
                    onChange={(v) => setField("enableSshRoot", v)}
                    label={"Allow Root Login"}
                    helpText={
                        "Let peers sign in as the root user. Disable to require a non-privileged account."
                    }
                />
                <FancyToggleSwitch
                    value={config.enableSshSftp}
                    onChange={(v) => setField("enableSshSftp", v)}
                    label={"Allow SFTP"}
                    helpText={"Transfer files securely using native SFTP or SCP clients."}
                />
                <FancyToggleSwitch
                    value={config.enableSshLocalPortForwarding}
                    onChange={(v) => setField("enableSshLocalPortForwarding", v)}
                    label={"Local Port Forwarding"}
                    helpText={
                        "Let connecting peers tunnel local ports to services reachable from this host."
                    }
                />
                <FancyToggleSwitch
                    value={config.enableSshRemotePortForwarding}
                    onChange={(v) => setField("enableSshRemotePortForwarding", v)}
                    label={"Remote Port Forwarding"}
                    helpText={
                        "Let connecting peers expose ports on this host back to their own machine."
                    }
                />
            </SectionGroup>

            <SectionGroup title={"Authentication"} disabled={!isSSHServerEnabled}>
                <FancyToggleSwitch
                    value={!config.disableSshAuth}
                    onChange={(v) => setField("disableSshAuth", !v)}
                    label={"Enable JWT Authentication"}
                    helpText={
                        "Verify each SSH session against your IdP for user identity and audit. Disable to rely on network ACL policies only, useful when no IdP is available."
                    }
                />
                <div
                    className={cn(
                        "flex items-center gap-6 justify-between",
                        config.disableSshAuth && "opacity-50 pointer-events-none",
                    )}
                >
                    <div className={"flex-1 max-w-md"}>
                        <Label as={"div"}>JWT Cache TTL (Seconds)</Label>
                        <HelpText margin={false}>
                            How long this client caches a JWT before prompting again on outgoing SSH
                            connections. Set to 0 to disable caching and authenticate on every
                            connection.
                        </HelpText>
                    </div>
                    <div className={"w-40 shrink-0"}>
                        <Input
                            type={"number"}
                            min={0}
                            value={jwtTtlInput}
                            onChange={handleJwtTtlChange}
                            onBlur={handleJwtTtlBlur}
                            customSuffix={"Seconds"}
                        />
                    </div>
                </div>
            </SectionGroup>
        </>
    );
}
