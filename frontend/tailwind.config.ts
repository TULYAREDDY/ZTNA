import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        display: [
          "'Aeonik Pro'",
          "'Inter Display'",
          "Inter",
          "system-ui",
          "sans-serif",
        ],
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "monospace"],
      },
      colors: {
        canvas: {
          dark: "#000000",
          light: "#ffffff",
        },
        surface: {
          deep: "#0a0a0a",
          elevated: "#16181a",
          soft: "#f4f4f4",
          card: "#ffffff",
        },
        hairline: {
          dark: "rgba(255,255,255,0.10)",
          soft: "rgba(255,255,255,0.06)",
          light: "#e2e2e7",
        },
        brand: {
          DEFAULT: "#494fdf",
          bright: "#4f55f1",
          deep: "#3a40c4",
        },
        ink: {
          onDark: "#ffffff",
          onDarkMute: "rgba(255,255,255,0.72)",
          onDarkDim: "rgba(255,255,255,0.48)",
          onDarkFaint: "rgba(255,255,255,0.28)",
        },
        verdict: {
          allow: "#00a87e",
          monitor: "#ec7e00",
          block: "#e23b4a",
        },
        chart: {
          a: "#494fdf",
          b: "#00a87e",
          c: "#ec7e00",
          d: "#e23b4a",
          e: "#007bc2",
          f: "#b09000",
        },
      },
      borderRadius: {
        pill: "9999px",
        card: "20px",
        input: "12px",
        tile: "8px",
      },
      spacing: {
        // Semantic step tokens (used as gap-*, space-*, p-*).
        card: "1rem",      // 16 px — inside-card spacing
        grid: "1.25rem",   // 20 px — between-card grid spacing
        section: "2rem",   // 32 px — between page sections
      },
      opacity: {
        3: "0.03",
        4: "0.04",
        8: "0.08",
        12: "0.12",
      },
      animation: {
        "fade-in": "fadeIn 0.18s ease-out",
        "slide-in": "slideIn 0.18s ease-out",
        blink: "blink 1.4s ease-in-out infinite",
      },
      keyframes: {
        fadeIn: { "0%": { opacity: "0" }, "100%": { opacity: "1" } },
        slideIn: {
          "0%": { opacity: "0", transform: "translateX(-6px)" },
          "100%": { opacity: "1", transform: "translateX(0)" },
        },
        blink: { "0%,100%": { opacity: "1" }, "50%": { opacity: "0.35" } },
      },
    },
  },
  plugins: [],
} satisfies Config;
