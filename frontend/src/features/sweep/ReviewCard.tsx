import { app as goapp } from "../../../wailsjs/go/models";
import type { Busy } from "./busy";

export function ReviewCard({ plan, confirmTo, busy, onConfirmToChange, onSend, onSave }: {
  plan: goapp.SweepPlanView;
  confirmTo: string;
  busy: Busy;
  onConfirmToChange: (v: string) => void;
  onSend: () => void;
  onSave: () => void;
}) {
  const count = plan.txs.length;
  const canSend = count > 0 && confirmTo.trim() === plan.to && !busy;
  return (
    <div className="keycard stacked">
      <div className="keycard-head">
        <h3>3 · Review</h3>
        <span className="verifybadge">{count} {count === 1 ? "transaction" : "transactions"}</span>
      </div>
      <div className="share-meta">Destination {plan.to}</div>
      {count === 0 && <div className="empty spaced">Nothing to transfer.</div>}
      {plan.txs.map((t, i) => (
        <div className="sweep-wallet" key={i}>
          <span>
            {t.name || "wallet"}
            <span className="share-meta sub-line">{t.signer}</span>
          </span>
          <span>{t.description}</span>
        </div>
      ))}
      {plan.notes.map((n, i) => <div className="keynote" key={i}>ℹ {n}</div>)}
      <div className="notice-warn spaced">
        ⚠ Balances are read live and these transactions expire in about 1 minute. Send or save now.
      </div>
      {count > 0 && (
        <>
          <div className="field-label">Type the destination address to confirm</div>
          <input className="text-input" placeholder="Paste the destination address again" value={confirmTo}
            onChange={(e) => onConfirmToChange(e.target.value)} />
          <div className="key-actions">
            <button className="primary sm" disabled={!canSend} onClick={onSend}>
              {busy === "send" ? "Sending…" : "Sign & send"}
            </button>
            <button className="sm" disabled={!!busy} onClick={onSave}>Sign & save to file…</button>
          </div>
        </>
      )}
    </div>
  );
}
