import { useCallback, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import netbirdLogo from "@/assets/logos/netbird.svg";

const scratch = new Uint32Array(1);

function random() {
    crypto.getRandomValues(scratch);
    return scratch[0] / 2 ** 32;
}

type Mask = {
    cols: number;
    rows: number;
    cells: Uint8Array;
    seeds: Uint8Array;
    glow: Float32Array;
};

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

        const chars = "DRIBTENMAET".split("").reverse().join("");

        let disposed = false;
        let mask: Mask | null = null;

        const dpr = window.devicePixelRatio || 1;
        let columns = 0;
        let drops: number[] = [];

        const resize = () => {
            canvas.width = window.innerWidth * dpr;
            canvas.height = window.innerHeight * dpr;
            canvas.style.width = `${window.innerWidth}px`;
            canvas.style.height = `${window.innerHeight}px`;
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

            const next = Math.floor(window.innerWidth / 15);
            if (next !== columns) {
                columns = next;
                drops = Array.from({ length: columns }, () => random() * -60);
            }
            void buildMask().then((m) => {
                if (!disposed) mask = m;
            });
        };
        resize();
        window.addEventListener("resize", resize);

        let raf = 0;
        let last = 0;
        let frame = 0;
        const draw = (t: number) => {
            if (t - last > 50) {
                last = t;

                ctx.globalCompositeOperation = "destination-out";
                ctx.fillStyle = "rgba(0, 0, 0, 0.12)";
                ctx.fillRect(0, 0, window.innerWidth, window.innerHeight);

                ctx.globalCompositeOperation = "source-over";
                ctx.font = "15px ui-monospace, monospace";
                ctx.textBaseline = "top";

                ctx.shadowBlur = 0;
                ctx.fillStyle = "rgba(246, 131, 48, 0.5)";
                for (let i = 0; i < drops.length; i++) {
                    const ch = chars[Math.floor(random() * chars.length)];
                    const y = drops[i] * 15;
                    ctx.fillText(ch, i * 15, y);

                    igniteTrail(mask, i, Math.floor(drops[i]));

                    if (y > window.innerHeight && random() > 0.86) {
                        drops[i] = random() * -12;
                    }
                    drops[i]++;
                }

                drawGlow(ctx, mask, frame, chars);
                frame++;
            }
            raf = requestAnimationFrame(draw);
        };
        raf = requestAnimationFrame(draw);

        const timeout = globalThis.setTimeout(() => {
            setVisible(false);
            globalThis.setTimeout(onDone, 500);
        }, 9000);

        return () => {
            disposed = true;
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

function igniteTrail(mask: Mask | null, col: number, row: number) {
    if (!mask || col < 0 || col >= mask.cols) return;
    for (let k = 0; k < 6; k++) {
        const r = row - k;
        if (r < 0 || r >= mask.rows) continue;
        const idx = r * mask.cols + col;
        if (mask.cells[idx] === 0) continue;
        const heat = 1 - k / 6;
        if (heat > mask.glow[idx]) mask.glow[idx] = heat;
    }
}

function drawGlow(ctx: CanvasRenderingContext2D, mask: Mask | null, frame: number, chars: string) {
    if (!mask) return;

    for (let idx = 0; idx < mask.cells.length; idx++) {
        const heat = fade(mask, idx);
        if (heat === 0) continue;

        const seed = mask.seeds[idx];
        const core = mask.cells[idx] === 2;

        ctx.shadowColor = core ? "#f05252" : "#f68330";
        ctx.shadowBlur = 10 * heat;
        ctx.fillStyle = core ? `rgba(255, 226, 210, ${heat})` : `rgba(255, 255, 255, ${heat})`;
        ctx.fillText(
            chars[(seed + Math.floor(frame / (3 + (seed % 5)))) % chars.length],
            (idx % mask.cols) * 15,
            Math.floor(idx / mask.cols) * 15,
        );
    }
    ctx.shadowBlur = 0;
}

function fade(mask: Mask, idx: number) {
    if (mask.cells[idx] === 0) return 0;

    const heat = mask.glow[idx];
    if (heat <= 0.02) {
        mask.glow[idx] = 0;
        return 0;
    }
    mask.glow[idx] = heat * 0.94;
    return heat;
}

function loadLogo() {
    return new Promise<HTMLImageElement>((resolve, reject) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = reject;
        img.src = netbirdLogo;
    });
}

async function buildMask(): Promise<Mask | null> {
    const cols = Math.floor(window.innerWidth / 15);
    const rows = Math.ceil(window.innerHeight / 15);
    if (cols <= 0 || rows <= 0) return null;

    let img: HTMLImageElement;
    try {
        img = await loadLogo();
    } catch {
        return null;
    }

    const off = document.createElement("canvas");
    off.width = cols;
    off.height = rows;
    const offCtx = off.getContext("2d", { willReadFrequently: true });
    if (!offCtx) return null;

    const aspect = (img.naturalWidth || 31) / (img.naturalHeight || 23);
    let w = cols * 0.8;
    let h = w / aspect;
    if (h > rows * 0.8) {
        h = rows * 0.8;
        w = h * aspect;
    }

    offCtx.imageSmoothingEnabled = false;
    offCtx.drawImage(img, (cols - w) / 2, (rows - h) / 2, w, h);

    const { data } = offCtx.getImageData(0, 0, cols, rows);
    const cells = new Uint8Array(cols * rows);
    const seeds = new Uint8Array(cols * rows);
    const glow = new Float32Array(cols * rows);
    for (let i = 0; i < cells.length; i++) {
        seeds[i] = Math.floor(random() * 251);
        const alpha = data[i * 4 + 3];
        if (alpha < 64) continue;
        const r = data[i * 4];
        const g = data[i * 4 + 1];
        const b = data[i * 4 + 2];
        cells[i] = r > 180 && g < 130 && b < 130 && g <= b + 24 ? 2 : 1;
    }
    return { cols, rows, cells, seeds, glow };
}
