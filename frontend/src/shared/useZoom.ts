import { useEffect } from "react";
import { EventsOn } from "../../wailsjs/runtime/runtime";

const LEVELS = [0.8, 0.9, 1, 1.1, 1.25, 1.4, 1.6, 1.8, 2];
const STORAGE_KEY = "zoom-level";

// Pick a starting level from the screen so 4K displays at 1x scaling aren't tiny.
function defaultLevel(): number {
  const w = window.screen.width;
  return LEVELS.indexOf(w >= 3200 ? 1.6 : w >= 2400 ? 1.25 : 1);
}
const DEFAULT = defaultLevel();

function load(): number {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const i = Number(raw);
    return raw !== null && Number.isInteger(i) && i >= 0 && i < LEVELS.length ? i : DEFAULT;
  } catch {
    return DEFAULT;
  }
}

function apply(i: number) {
  document.documentElement.style.setProperty("--zoom", String(LEVELS[i]));
  try { localStorage.setItem(STORAGE_KEY, String(i)); } catch { /* storage unavailable */ }
}

export function useZoom(onChange: (percent: number) => void) {
  useEffect(() => {
    let level = load();
    apply(level);

    const step = (dir: string) => {
      const next = dir === "in" ? Math.min(level + 1, LEVELS.length - 1)
        : dir === "out" ? Math.max(level - 1, 0)
        : DEFAULT;
      if (next === level) return;
      level = next;
      apply(level);
      onChange(Math.round(LEVELS[level] * 100));
    };

    const onWheel = (e: WheelEvent) => {
      if (!e.ctrlKey && !e.metaKey) return;
      e.preventDefault();
      step(e.deltaY < 0 ? "in" : "out");
    };

    // The menu accelerator catches Ctrl+= but not Ctrl+Shift+= ("+").
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "+") {
        e.preventDefault();
        step("in");
      }
    };

    window.addEventListener("wheel", onWheel, { passive: false });
    window.addEventListener("keydown", onKey);
    const off = EventsOn("zoom", step);
    return () => {
      window.removeEventListener("wheel", onWheel);
      window.removeEventListener("keydown", onKey);
      off();
    };
  }, []);
}
