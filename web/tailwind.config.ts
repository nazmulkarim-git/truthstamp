import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      borderRadius: {
        lg: "0.75rem",
        md: "0.6rem",
        sm: "0.4rem",
      },
      colors: {
        border: "hsl(214 20% 90%)",
        input: "hsl(214 20% 90%)",
        ring: "hsl(221 83% 53%)",
        background: "hsl(0 0% 100%)",
        foreground: "hsl(222 47% 11%)",
        muted: "hsl(210 40% 96.1%)",
        mutedForeground: "hsl(215 16% 47%)",
        primary: "hsl(221 83% 53%)",
        primaryForeground: "hsl(0 0% 98%)",
        secondary: "hsl(210 40% 96.1%)",
        secondaryForeground: "hsl(222 47% 11%)",
        destructive: "hsl(0 84% 60%)",
        destructiveForeground: "hsl(0 0% 98%)",
        accent: "hsl(214 32% 91%)",
        accentForeground: "hsl(222 47% 11%)",
        card: "hsl(0 0% 100%)",
        cardForeground: "hsl(222 47% 11%)",
      },
      boxShadow: {
        soft: "0 12px 30px rgba(2, 6, 23, 0.08)",
        glow: "0 0 0 1px rgba(59,130,246,0.12), 0 20px 50px rgba(59,130,246,0.18)",
      },
    },
  },
  plugins: [],
};
export default config;
