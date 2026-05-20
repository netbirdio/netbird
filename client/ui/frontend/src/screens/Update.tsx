import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Loader2 } from "lucide-react";
import { Dialogs } from "@wailsio/runtime";
import { Update as UpdateSvc } from "@bindings/services";
import i18next from "@/lib/i18n";
import { formatErrorMessage } from "@/lib/errors";

const TIMEOUT_MS = 15 * 60 * 1000;

const showError = (message: string) =>
  Dialogs.Error({ Title: i18next.t("update.page.failedTitle"), Message: message });

export default function Update() {
  const { t } = useTranslation();
  const [done, setDone] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    UpdateSvc.Trigger().catch((e) => {
      if (cancelled) return;
      setFailed(true);
      void showError(formatErrorMessage(e));
    });

    const start = Date.now();
    const timer = setInterval(async () => {
      if (Date.now() - start > TIMEOUT_MS) {
        clearInterval(timer);
        setFailed(true);
        void showError(i18next.t("update.page.timeoutMessage"));
        return;
      }
      try {
        const r = await UpdateSvc.GetInstallerResult();
        if (r.success) {
          setDone(true);
          clearInterval(timer);
        } else if (r.errorMsg) {
          clearInterval(timer);
          setFailed(true);
          void showError(r.errorMsg);
        }
      } catch {
        // installer not finished yet
      }
    }, 2000);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  return (
    <div className="flex h-full items-center justify-center p-6">
      <div className="text-center">
        {done ? (
          <h1 className="text-xl font-semibold text-green-500">
            {t("update.page.complete")}
          </h1>
        ) : failed ? (
          <h1 className="text-xl font-semibold text-red-500">
            {t("update.page.failed")}
          </h1>
        ) : (
          <>
            <Loader2 className="mx-auto mb-3 h-8 w-8 animate-spin text-netbird" strokeWidth={1.5} />
            <h1 className="text-xl font-semibold">{t("update.page.updating")}</h1>
            <p className="mt-1 text-sm text-nb-gray-500">
              {t("update.page.dontClose")}
            </p>
          </>
        )}
      </div>
    </div>
  );
}
