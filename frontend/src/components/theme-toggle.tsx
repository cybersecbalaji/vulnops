"use client";

import { Moon, Sun, Monitor } from "lucide-react";
import { useTheme, type Theme } from "@/contexts/ThemeContext";
import { Button } from "@/components/ui/button";

/**
 * Cycling theme toggle: Light → Dark → System → Light…
 *
 * The current icon always reflects the user's explicit choice (not the
 * resolved system preference) so clicking Monitor → Sun is unambiguous.
 */
export function ThemeToggle() {
  const { theme, setTheme } = useTheme();

  const cycle: Record<Theme, Theme> = {
    light: "dark",
    dark: "system",
    system: "light",
  };
  const nextLabels: Record<Theme, string> = {
    light: "Switch to dark mode",
    dark: "Switch to follow system",
    system: "Switch to light mode",
  };

  const Icon = theme === "light" ? Sun : theme === "dark" ? Moon : Monitor;
  const currentLabel = theme === "light" ? "Light" : theme === "dark" ? "Dark" : "System";

  return (
    <Button
      variant="ghost"
      size="sm"
      className="h-8 w-8 px-0"
      onClick={() => setTheme(cycle[theme])}
      title={`Theme: ${currentLabel} — ${nextLabels[theme]}`}
      aria-label={nextLabels[theme]}
    >
      <Icon className="h-4 w-4" />
    </Button>
  );
}
