import { app as goapp } from "../../../wailsjs/go/models";

export function ProgressCard({ log, result }: { log: string[]; result: goapp.SweepResult | null }) {
  return (
    <div className="keycard stacked">
      <div className="keycard-head">
        <h3>Progress</h3>
        {result && !result.error && <span className="verifybadge">Done</span>}
      </div>
      <div className="sweep-log">{log.length ? log.join("\n") : "Waiting for the network…"}</div>
      {result?.error && <div className="error">{result.error}. Scan again to see what is left.</div>}
    </div>
  );
}
