/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#FAFAF8",
        surface: {
          DEFAULT: "#FFFFFF",
          muted: "#F4F4F2",
          dim: "#EBEBE8",
          dark: "#111111",
        },
        border: {
          DEFAULT: "#E5E5E5",
          muted: "#ECECE8",
          strong: "#D1D1D1",
          focus: "#111111",
        },
        primary: {
          DEFAULT: "#111111",
          hover: "#222222",
          foreground: "#FFFFFF",
        },
        secondary: {
          DEFAULT: "#6B6B6B",
          foreground: "#111111",
        },
        status: {
          healthy: "#10B981", // Emerald Green
          warning: "#F59E0B", // Amber
          critical: "#EF4444", // Ruby Red
          neutral: "#6B6B6B",
        }
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "sans-serif"],
        mono: ["JetBrains Mono", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        'subtle': '0 1px 2px 0 rgba(0, 0, 0, 0.03)',
        'card': '0 1px 3px 0 rgba(0, 0, 0, 0.04), 0 1px 2px -1px rgba(0, 0, 0, 0.02)',
        'dropdown': '0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -2px rgba(0, 0, 0, 0.03)',
      },
      borderRadius: {
        'DEFAULT': '4px',
        'sm': '2px',
        'md': '4px',
        'lg': '6px',
        'xl': '8px',
      }
    },
  },
  plugins: [],
}
