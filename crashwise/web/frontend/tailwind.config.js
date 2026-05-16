/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#0d1117",
        foreground: "#c9d1d9",
        muted: { DEFAULT: "#161b22", foreground: "#8b949e" },
        border: "#30363d",
        "accent-green": "#3fb950",
        "accent-red": "#f85149",
        "accent-orange": "#d29922",
        "accent-blue": "#58a6ff",
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"SF Mono"', '"Fira Code"', "monospace"],
      },
    },
  },
  plugins: [],
};
