import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { useInstallation } from "@/hooks/useInstallation";

// Read-only details of a named installation, for support and screenshots. The
// default installation shows nothing.
export function InstallationDetailsCard() {
    const { t } = useTranslation();
    const installation = useInstallation();
    if (!installation) return null;

    const role =
        installation.role === "primary"
            ? t("settings.about.installation.rolePrimary")
            : t("settings.about.installation.roleSecondary");

    return (
        <div
            className={
                "w-full max-w-lg rounded-md border border-nb-gray-800 bg-nb-gray-910 px-4 py-3"
            }
        >
            <p className={"mb-2 text-sm font-semibold"}>{t("settings.about.installation.title")}</p>
            <dl className={"grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-sm"}>
                <Row label={t("settings.about.installation.name")}>
                    <span className={"font-mono"}>{installation.name}</span>
                </Row>
                <Row label={t("settings.about.installation.label")}>{installation.label}</Row>
                <Row label={t("settings.about.installation.color")}>
                    {installation.color ? (
                        <span className={"inline-flex items-center gap-2"}>
                            <span
                                aria-hidden={"true"}
                                className={"h-3 w-3 rounded-full border border-nb-gray-700"}
                                style={{ backgroundColor: installation.color }}
                            />
                            <span className={"font-mono"}>{installation.color}</span>
                        </span>
                    ) : (
                        t("settings.about.installation.noColor")
                    )}
                </Row>
                <Row label={t("settings.about.installation.role")}>{role}</Row>
            </dl>
        </div>
    );
}

function Row({ label, children }: Readonly<{ label: string; children: ReactNode }>) {
    return (
        <>
            <dt className={"text-nb-gray-300"}>{label}</dt>
            <dd className={"cursor-text text-nb-gray-100 select-text"}>{children}</dd>
        </>
    );
}
