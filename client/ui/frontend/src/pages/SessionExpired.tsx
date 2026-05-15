import { useTranslation } from "react-i18next";
import { ShieldAlertIcon } from "lucide-react";
import { Button } from "@/components/Button";

export default function SessionExpired() {
    const { t } = useTranslation();
    return (
        <div
            className={
                "h-full w-full flex flex-col items-center justify-center text-center px-6 py-8 bg-nb-gray-950"
            }
        >
            <div
                className={
                    "h-12 w-12 rounded-full flex items-center justify-center bg-nb-gray-900 text-netbird mb-4"
                }
            >
                <ShieldAlertIcon size={22} />
            </div>
            <h1 className={"text-base font-semibold text-nb-gray-100"}>
                {t("sessionExpired.title")}
            </h1>
            <p className={"text-xs text-nb-gray-400 mt-1.5 max-w-[20rem] leading-snug"}>
                {t("sessionExpired.description")}
            </p>
            <div className={"flex gap-2 mt-5 w-full max-w-[18rem]"}>
                <Button variant={"secondary"} size={"xs"} className={"flex-1"}>
                    {t("sessionExpired.later")}
                </Button>
                <Button variant={"primary"} size={"xs"} className={"flex-1"}>
                    {t("sessionExpired.signIn")}
                </Button>
            </div>
        </div>
    );
}
