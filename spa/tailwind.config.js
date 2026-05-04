/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
      colors: {
        // Tactic palette: matches ATT&CK Navigator-ish hues, dark-mode tuned.
        tactic: {
          execution: "#dc2626",
          persistence: "#ea580c",
          privilege_escalation: "#d97706",
          defense_evasion: "#65a30d",
          credential_access: "#0891b2",
          discovery: "#2563eb",
          lateral_movement: "#7c3aed",
          collection: "#db2777",
          command_and_control: "#be185d",
          exfiltration: "#9f1239",
          impact: "#7f1d1d",
          initial_access: "#475569",
          reconnaissance: "#334155",
          resource_development: "#1e293b",
        },
      },
    },
  },
  plugins: [],
};
