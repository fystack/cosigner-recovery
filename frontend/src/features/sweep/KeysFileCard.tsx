import { app as goapp } from "../../../wailsjs/go/models";
import type { Busy } from "./busy";

export function KeysFileCard({ info, busy, onLoad }: {
  info: goapp.SweepKeysInfo | null;
  busy: Busy;
  onLoad: () => void;
}) {
  const wallets = info?.wallets ?? [];
  return (
    <div className="share">
      <div className="share-head">
        <span className="share-title">1 · Child keys file</span>
        {info?.loaded && <span className="badge ok">✓ {wallets.length} Solana wallets</span>}
      </div>
      <div className="share-meta">
        {info?.loaded ? "Loaded from the file exported by Recover keys." : "The .json file exported with \"Export all child keys…\"."}
      </div>
      <div className="unlock-row">
        <button className="sm" disabled={!!busy} onClick={onLoad}>{info?.loaded ? "Replace file…" : "Select file…"}</button>
      </div>
      {wallets.length > 0 && (
        <div className="sweep-wallets">
          {wallets.map((w) => (
            <div className="sweep-wallet" key={w.address}>
              <span>{w.name || "wallet"}</span>
              <span className="share-meta flush">{w.address}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
