import { useEffect, useRef } from "react";
import { Events } from "@wailsio/runtime";
import { useStatus } from "@/contexts/StatusContext.tsx";

const EVENT_WINDOW_PAINTED = "netbird:window-painted";

export const ReadySignal = () => {
    const { isReady } = useStatus();
    const sent = useRef(false);

    useEffect(() => {
        if (!isReady || sent.current) return;
        sent.current = true;
        void Events.Emit(EVENT_WINDOW_PAINTED);
    }, [isReady]);

    return null;
};
