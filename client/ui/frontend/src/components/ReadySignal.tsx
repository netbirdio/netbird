import { useEffect, useRef } from "react";
import { useSearchParams } from "react-router-dom";
import { Events } from "@wailsio/runtime";
import { useStatus } from "@/contexts/StatusContext.tsx";

const EVENT_WINDOW_PAINTED = "netbird:window-painted";

export const ReadySignal = () => {
    const { isReady } = useStatus();
    const [params] = useSearchParams();
    const generation = params.get("gen") ?? "";
    const sent = useRef<string | null>(null);

    useEffect(() => {
        if (!isReady || sent.current === generation) return;
        sent.current = generation;
        void Events.Emit(EVENT_WINDOW_PAINTED, generation);
    }, [isReady, generation]);

    return null;
};
