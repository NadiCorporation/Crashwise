/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "#000000",
        foreground: "#ffffff",
        border: "#222222",
        muted: "#111111",
        "muted-foreground": "#888888",
        accent: {
          red: "#ef4444",
          orange: "#f97316",
          green: "#10b981",
          blue: "#3b82f6",
        },
      },
    },
  },
  plugins: [],
};
