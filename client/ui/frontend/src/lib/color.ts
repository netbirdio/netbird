import chroma from "chroma-js";

export const generateColorFromString = (str?: string) => {
    if (!str) return "#f68330";
    if (str.includes("System")) return "#808080";
    if (str.toLowerCase().startsWith("netbird")) return "#f68330";
    let hash = 0;
    str.split("").forEach((char) => {
        hash = char.charCodeAt(0) + ((hash << 5) - hash);
    });
    let colour = "#";
    for (let i = 0; i < 3; i++) {
        const value = (hash >> (i * 8)) & 0xff;
        colour += value.toString(16).padStart(2, "0");
    }
    return chroma(colour).saturate(2).luminance(0.4).hex();
};
