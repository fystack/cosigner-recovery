import type { Step } from "../../shared/types";

export function StepDot({ n, label, step }: { n: number; label: string; step: Step }) {
  const cls = step === n ? "active" : step > n ? "done" : "";
  return (
    <div className={`step ${cls}`}>
      <div className="dot">{step > n ? "✓" : n}</div>
      {label}
    </div>
  );
}
