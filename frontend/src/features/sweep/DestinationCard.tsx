import type { Busy } from "./busy";

export function DestinationCard({ to, rpc, busy, onToChange, onRpcChange, onScan }: {
  to: string;
  rpc: string;
  busy: Busy;
  onToChange: (v: string) => void;
  onRpcChange: (v: string) => void;
  onScan: () => void;
}) {
  return (
    <div className="share stacked">
      <div className="share-head"><span className="share-title">2 · Destination</span></div>
      <div className="field-label">Send everything to (Solana address)</div>
      <input className="text-input" placeholder="Enter the destination address" value={to}
        onChange={(e) => onToChange(e.target.value)} />
      <div className="field-label">RPC URL (optional)</div>
      <input className="text-input" placeholder="https://api.mainnet-beta.solana.com" value={rpc}
        onChange={(e) => onRpcChange(e.target.value)} />
      <div className="unlock-row">
        <button className="primary sm" disabled={!!busy || !to.trim()} onClick={onScan}>
          {busy === "scan" ? "Scanning…" : "Scan & preview"}
        </button>
      </div>
    </div>
  );
}
