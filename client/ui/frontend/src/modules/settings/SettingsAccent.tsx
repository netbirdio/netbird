import { useCallback, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";

export function useAccentTrigger() {
    const clicksRef = useRef(0);
    const lastClickRef = useRef(0);

    return useCallback(() => {
        const now = performance.now();
        if (now - lastClickRef.current > 400) {
            clicksRef.current = 0;
        }
        lastClickRef.current = now;
        clicksRef.current += 1;
        if (clicksRef.current >= 10) {
            clicksRef.current = 0;
            triggerAccent();
        }
    }, []);
}

function triggerAccent() {
    if (document.getElementById("nb-accent-root")) return;

    const container = document.createElement("div");
    container.id = "nb-accent-root";
    document.body.appendChild(container);
    const root = createRoot(container);

    const cleanup = () => {
        root.unmount();
        container.remove();
    };

    root.render(<Accent onDone={cleanup} />);
}

function Accent({ onDone }: Readonly<{ onDone: () => void }>) {
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const [visible, setVisible] = useState(false);

    useEffect(() => {
        const raf = requestAnimationFrame(() => setVisible(true));
        return () => cancelAnimationFrame(raf);
    }, []);

    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        if (!ctx) return;

        const dpr = window.devicePixelRatio || 1;
        const resize = () => {
            canvas.width = window.innerWidth * dpr;
            canvas.height = window.innerHeight * dpr;
            canvas.style.width = `${window.innerWidth}px`;
            canvas.style.height = `${window.innerHeight}px`;
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        };
        resize();
        window.addEventListener("resize", resize);

        const chars = "TEAMNETBIRD";
        const fontSize = 16;
        const columns = Math.floor(window.innerWidth / fontSize);
        const drops = Array.from({ length: columns }, () => Math.random() * -50);

        let raf = 0;
        let last = 0;
        const draw = (t: number) => {
            if (t - last > 50) {
                last = t;

                ctx.globalCompositeOperation = "destination-out";
                ctx.fillStyle = "rgba(0, 0, 0, 0.12)";
                ctx.fillRect(0, 0, window.innerWidth, window.innerHeight);

                ctx.globalCompositeOperation = "source-over";
                ctx.font = `${fontSize}px ui-monospace, monospace`;
                ctx.fillStyle = "#f68330";

                for (let i = 0; i < drops.length; i++) {
                    const ch = chars[Math.floor(Math.random() * chars.length)];
                    const y = drops[i] * fontSize;
                    ctx.fillText(ch, i * fontSize, y);
                    if (y > window.innerHeight && Math.random() > 0.975) {
                        drops[i] = 0;
                    }
                    drops[i]++;
                }
            }
            raf = requestAnimationFrame(draw);
        };
        raf = requestAnimationFrame(draw);

        const timeout = globalThis.setTimeout(() => {
            setVisible(false);
            globalThis.setTimeout(onDone, 500);
        }, 9000);

        return () => {
            cancelAnimationFrame(raf);
            globalThis.clearTimeout(timeout);
            window.removeEventListener("resize", resize);
        };
    }, [onDone]);

    return (
        <div
            className={`pointer-events-none fixed inset-0 z-50 bg-black/5 transition-opacity duration-500 ${visible ? "opacity-100" : "opacity-0"}`}
        >
            <canvas ref={canvasRef} className={"block"} />
        </div>
    );
}
