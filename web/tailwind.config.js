/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ok: "#1a7f37",
        link: "#1f6feb",
        inferred: "#d97706",
        gap: "#b91c1c",
        evidence: "#7c3aed",
        offense: "#c2410c",
        defense: "#15803d",
        template: "#6b7280",
      },
    },
  },
  plugins: [],
};
