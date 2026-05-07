import FancyToggleSwitch from "@/components/FancyToggleSwitch";
import { HelpText } from "@/components/HelpText";
import { Input } from "@/components/Input";
import { Label } from "@/components/Label";
import { cn } from "@/lib/cn";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/modules/settings/SettingsContext.tsx";

export function SettingsSSH() {
    const { config, setField } = useSettings();
    const sshOff = !config.serverSshAllowed;
    return (
        <>
            <SectionGroup title={"Server"}>
                <FancyToggleSwitch
                    value={config.serverSshAllowed}
                    onChange={(v) => setField("serverSshAllowed", v)}
                    label={"Allow SSH"}
                    helpText={
                        "Run the NetBird SSH server on this host so other peers can connect to it."
                    }
                />
            </SectionGroup>

            <SectionGroup title={"Capabilities"}>
                <FancyToggleSwitch
                    value={config.enableSshRoot}
                    onChange={(v) => setField("enableSshRoot", v)}
                    label={"Allow root login"}
                    helpText={
                        "Permit incoming SSH sessions to authenticate as root."
                    }
                    disabled={sshOff}
                />
                <FancyToggleSwitch
                    value={config.enableSshSftp}
                    onChange={(v) => setField("enableSshSftp", v)}
                    label={"Enable SFTP"}
                    helpText={"Allow file transfers over the NetBird SSH server."}
                    disabled={sshOff}
                />
                <FancyToggleSwitch
                    value={config.enableSshLocalPortForwarding}
                    onChange={(v) => setField("enableSshLocalPortForwarding", v)}
                    label={"Local port forwarding"}
                    helpText={
                        "Allow clients to forward local ports through this host."
                    }
                    disabled={sshOff}
                />
                <FancyToggleSwitch
                    value={config.enableSshRemotePortForwarding}
                    onChange={(v) =>
                        setField("enableSshRemotePortForwarding", v)
                    }
                    label={"Remote port forwarding"}
                    helpText={
                        "Allow clients to expose remote ports back through this host."
                    }
                    disabled={sshOff}
                />
            </SectionGroup>

            <SectionGroup title={"Authentication"}>
                <FancyToggleSwitch
                    value={config.disableSshAuth}
                    onChange={(v) => setField("disableSshAuth", v)}
                    label={"Disable SSH auth"}
                    helpText={
                        "Skip JWT authentication for incoming SSH sessions. Insecure — diagnostics only."
                    }
                    disabled={sshOff}
                />
                <div
                    className={cn(
                        "flex items-center gap-6",
                        sshOff && "opacity-50 pointer-events-none",
                    )}
                >
                    <div className={"flex-1 max-w-md"}>
                        <Label as={"div"}>JWT cache TTL</Label>
                        <HelpText margin={false}>
                            How long verified JWTs are cached before
                            re-validation. Shorter values increase load on the
                            management server; longer values delay revocation.
                        </HelpText>
                    </div>
                    <div className={"w-32 shrink-0"}>
                        <Input
                            type={"number"}
                            value={config.sshJwtCacheTtl}
                            onChange={(e) =>
                                setField(
                                    "sshJwtCacheTtl",
                                    Number(e.target.value),
                                )
                            }
                            customSuffix={
                                <span className={"text-nb-gray-400"}>s</span>
                            }
                            disabled={sshOff}
                        />
                    </div>
                </div>
            </SectionGroup>
        </>
    );
}
