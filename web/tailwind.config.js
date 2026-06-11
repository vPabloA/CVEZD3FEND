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
        // Reasoning workbench extension (UIX_CONTRACT §4): the live reasoning
        // plane's edge-classification taxonomy reuses ok/link/inferred/gap/
        // template above for 6 of its 7 levels; "conditional" is the one
        // genuinely new concept (a route step that only applies under a
        // specific precondition).
        conditional: "#0e7490",
      },
    },
  },
  plugins: [],
};
