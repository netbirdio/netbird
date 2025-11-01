/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        nb: {
          orange: '#F68330',
          'orange-dark': '#F35E32',
          'orange-light': '#FF9340',
          'orange-alpha': 'rgba(246, 131, 48, 0.3)',
        },
        gray: {
          bg: '#1a1a1a',
          'bg-light': '#2a2a2a',
          'bg-card': '#323232',
          'bg-dark': '#121212',
        },
        text: {
          light: '#f2f2f2',
          muted: '#a0a0aa',
          dark: '#0a0a0f',
        },
      },
      borderRadius: {
        'nb': '12px',
      },
      boxShadow: {
        'nb': '0 8px 32px 0 rgba(246, 131, 48, 0.1)',
        'nb-hover': '0 12px 48px 0 rgba(246, 131, 48, 0.2)',
        'orange-glow': '0 0 20px rgba(246, 131, 48, 0.5)',
      },
    },
  },
  plugins: [],
}
