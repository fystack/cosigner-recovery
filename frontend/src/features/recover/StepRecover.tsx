import { recovery } from "../../../wailsjs/go/models";
import { PROTOS } from "../../shared/constants";

export function StepRecover({ status, ready }: { status: recovery.Status | null; ready: string[] }) {
  return (
    <>
      <h1>Recover</h1>
      <p className="sub">Review before reconstructing. This combines the unlocked shares to rebuild the wallet's private keys.</p>
      <div className="threshold">
        <div className="thr-item">
          <div className="thr-label">Wallet</div>
          <div className="share-meta" style={{ marginTop: 6 }}>{status?.walletId || "—"}</div>
        </div>
      </div>
      <div className="threshold">
        {PROTOS.map((p) => {
          const c = status?.unlockedCounts?.[p] ?? 0;
          const ok = ready.includes(p);
          return (
            <div className="thr-item" key={p}>
              <div className="thr-label">{p}</div>
              <div className={`thr-count ${ok ? "ready" : ""}`}>{ok ? `${c} shares` : `${c} · need at least 2`}</div>
            </div>
          );
        })}
      </div>
      <div className="notice-warn">
        ⚠ Reconstructing materializes the full private key and defeats the wallet's threshold security. Only proceed offline, for recovery or migration.
      </div>
    </>
  );
}
