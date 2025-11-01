/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        icy: {
          blue: '#a3d7e5',
          'blue-dark': '#8cc8d7',
          'blue-light': '#c8ebf5',
          'blue-alpha': 'rgba(163, 215, 229, 0.3)',
        },
        dark: {
          bg: '#121218',
          'bg-light': '#18181e',
          'bg-card': '#1c1c23',
          view: '#101014',
        },
        text: {
          light: '#f8f8fc',
          muted: '#a0a0aa',
          dark: '#0a0a0f',
        },
      },
      borderRadius: {
        'glass': '12px',
      },
      boxShadow: {
        'glass': '0 8px 32px 0 rgba(163, 215, 229, 0.1)',
        'glass-hover': '0 8px 32px 0 rgba(163, 215, 229, 0.2)',
        'icy-glow': '0 0 20px rgba(163, 215, 229, 0.5)',
      },
      backdropBlur: {
        'glass': '10px',
      },
    },
  },
  plugins: [],
}
