import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        netbird: {
          DEFAULT: "#f68330",
          50: "#fff6ed",
          100: "#feecd6",
          200: "#ffd4a6",
          300: "#fab677",
          400: "#f68330",
          500: "#f46d1b",
          600: "#e55311",
          700: "#be3e10",
          800: "#973215",
          900: "#7a2b14",
        },
        "nb-gray": {
          DEFAULT: "#181A1D",
          50: "#f4f6f7",
          100: "#e4e7e9",
          200: "#cbd2d6",
          300: "#a3adb5",
          400: "#7c8994",
          500: "#616e79",
          600: "#535d67",
          700: "#474e57",
          800: "#3f444b",
          900: "#2e3238",
          925: "#1e2123",
          940: "#1c1e21",
          950: "#181a1d",
        },
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};

export default config;
