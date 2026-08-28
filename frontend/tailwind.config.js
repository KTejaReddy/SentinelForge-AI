/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: {
          950: "#070b14",
          900: "#0b1220",
          850: "#0e1626",
          800: "#111b30",
          700: "#1a2740",
          600: "#24344f",
        },
        accent: {
          400: "#38bdf8",
          500: "#0ea5e9",
        },
        danger: "#ef4444",
        warn: "#f59e0b",
        good: "#22c55e",
      },
      fontFamily: {
        mono: ["'JetBrains Mono'", "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      boxShadow: {
        glow: "0 0 24px rgba(56,189,248,0.15)",
      },
    },
  },
  plugins: [],
};
