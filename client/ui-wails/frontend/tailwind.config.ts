import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    fontFamily: {
      sans: ['"Inter Variable"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      mono: ['"JetBrains Mono Variable"', 'ui-monospace', 'monospace'],
    },
    extend: {
      colors: {
        "nb-gray": {
          DEFAULT: "#181A1D",
          50: "#f4f6f7",
          100: "#e4e7e9",
          200: "#cbd2d6",
          250: "#b7c0c6",
          300: "#a3adb5",
          350: "#8f9ca8",
          400: "#7c8994",
          500: "#616e79",
          600: "#535d67",
          700: "#474e57",
          800: "#3f444b",
          850: "#363b40",
          900: "#2e3238",
          910: "#2b2f33",
          920: "#25282d",
          925: "#1e2123",
          930: "#25282c",
          935: "#1f2124",
          940: "#1c1e21",
          950: "#181a1d",
          960: "#16181b",
        },
        netbird: {
          DEFAULT: "#f68330",
          50: "#fff6ed",
          100: "#feecd6",
          150: "#ffdfb8",
          200: "#ffd4a6",
          300: "#fab677",
          400: "#f68330",
          500: "#f46d1b",
          600: "#e55311",
          700: "#be3e10",
          800: "#973215",
          900: "#7a2b14",
          950: "#421308",
        },
      },
      backgroundImage: {
        "conic-netbird": "conic-gradient(from 0deg, #e55311 0%, #f68330 10%, #e55311 20%, #e55311 100%)",
      },
      keyframes: {
        "pulse-reverse": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.4" },
        },
        "spin-slow": {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
        "ping-slow": {
          "0%": { transform: "scale(1)", opacity: "1" },
          "75%, 100%": { transform: "scale(2)", opacity: "0" },
        },
      },
      animation: {
        "ping-slow": "ping-slow 2s cubic-bezier(0, 0, 0.2, 1) infinite",
        "pulse-slow": "pulse-reverse 2s cubic-bezier(0.5, 0, 0.6, 1) infinite",
        "pulse-slower": "pulse-reverse 3s cubic-bezier(0.5, 0, 0.6, 1) infinite",
        "spin-slow": "spin-slow 2s linear infinite",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};

export default config;
