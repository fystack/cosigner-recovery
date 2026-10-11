import { useState } from "react";
import { UnlockWithPassphrase, UnlockWithRSAKeyFile } from "../../../wailsjs/go/app/App";
import { recovery } from "../../../wailsjs/go/models";
import { PROTOS, MIN_SHARES } from "../../shared/constants";

export function StepShares({ status, onAdd, onRefresh, onRemove, setError, hd, onAddPaths, onUnlockPaths, onRemovePaths }: {
  status: recovery.Status | null;
  hd: recovery.HDInfo | null;
  onAddPaths: () => void;
  onUnlockPaths: () => void;
  onRemovePaths: () => void;
  onAdd: () => void;
  onRefresh: () => Promise<void>;
  onRemove: (id: string) => void;
  setError: (s: string) => void;
}) {
  const shares = status?.shares ?? [];
  return (
    <>
      <h1>Add & unlock shares</h1>
      <p className="sub">
        Add each participant's share file. Supports RSA export bundles (.enc) and passphrase-protected shares (.mshare).
        Add every share you have — there's no need to enter the threshold. Recovery combines all unlocked shares
        and checks the result against the wallet's public key, so it only succeeds once enough participants are present.
      </p>

      <div className="threshold">
        {PROTOS.map((p) => {
          const c = status?.unlockedCounts?.[p] ?? 0;
          const total = status?.partyCounts?.[p] ?? 0;
          return (
            <div className="thr-item" key={p}>
              <div className="thr-label">{p} shares unlocked</div>
              <div className={`thr-count ${c >= MIN_SHARES ? "ready" : ""}`}>
                {c}{total > 0 && <span className="thr-total"> of {total} participants</span>}
              </div>
            </div>
          );
        })}
      </div>

      {status?.walletMismatch && (
        <div className="error">Unlocked shares belong to different wallets. Remove the mismatched ones.</div>
      )}

      {shares.length === 0 ? (
        <div className="empty">No shares added yet.<br />Click "Add share file" to begin.</div>
      ) : (
        shares.map((s) => (
          <ShareRow key={s.id} share={s} onRefresh={onRefresh} onRemove={onRemove} setError={setError} />
        ))
      )}

      <button className="primary" style={{ marginTop: 8 }} onClick={onAdd}>+ Add share file</button>

      <div className="share" style={{ marginTop: 16 }}>
        <div className="share-head">
          <span className="share-title">Child wallets (HD wallets only)</span>
          {(hd?.pending || hd?.loaded) && <span className="badge rsa">RSA bundle</span>}
          {hd?.loaded && <span className="badge ok">✓ Unlocked</span>}
          <div className="spacer" />
          {(hd?.pending || hd?.loaded) && <button className="danger" onClick={onRemovePaths}>Remove</button>}
        </div>
        <div className="share-meta">
          {hd?.loaded
            ? `Master wallet ${hd.masterWalletId} · ${hd.childCount} child wallets`
            : hd?.pending
              ? hd.fileName
              : "Optional. Add the child wallet list exported with the master share to recover every child wallet."}
        </div>
        {!hd?.pending && !hd?.loaded && (
          <div className="unlock-row">
            <button className="sm" onClick={onAddPaths}>+ Add child wallet list</button>
          </div>
        )}
        {hd?.pending && (
          <div className="unlock-row">
            <button className="primary sm" onClick={onUnlockPaths}>Select RSA private key…</button>
          </div>
        )}
      </div>
    </>
  );
}

function ShareRow({ share, onRefresh, onRemove, setError }: {
  share: recovery.ShareInfo;
  onRefresh: () => Promise<void>;
  onRemove: (id: string) => void;
  setError: (s: string) => void;
}) {
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);

  const unlockPass = async () => {
    setError(""); setBusy(true);
    try { await UnlockWithPassphrase(share.id, pass); setPass(""); await onRefresh(); }
    catch (e: any) { setError(String(e)); }
    finally { setBusy(false); }
  };
  const unlockRSA = async () => {
    setError(""); setBusy(true);
    try { await UnlockWithRSAKeyFile(share.id); await onRefresh(); }
    catch (e: any) { setError(String(e)); }
    finally { setBusy(false); }
  };

  const fmt = share.format === "rsa-bundle" ? "rsa" : "mshare";
  return (
    <div className="share">
      <div className="share-head">
        <span className="share-title">{share.participantId || "Unknown participant"}</span>
        <span className={`badge ${fmt}`}>{share.format === "rsa-bundle" ? "RSA bundle" : "Passphrase"}</span>
        {share.unlocked && <span className="badge ok">✓ Unlocked</span>}
        <div className="spacer" />
        <button className="danger" onClick={() => onRemove(share.id)}>Remove</button>
      </div>
      <div className="share-meta">Wallet {share.walletId || "—"}</div>
      <div className="protos">
        {(share.protocols ?? []).map((p) => <span className="proto-chip" key={p}>{p}</span>)}
      </div>

      {!share.unlocked && share.needsPassphrase && (
        <div className="unlock-row">
          <input type="password" placeholder="Enter 6-word passphrase" value={pass}
            onChange={(e) => setPass(e.target.value)} onKeyDown={(e) => e.key === "Enter" && unlockPass()} />
          <button className="primary sm" disabled={busy || !pass} onClick={unlockPass}>Unlock</button>
        </div>
      )}
      {!share.unlocked && share.needsRsaKey && (
        <div className="unlock-row">
          <button className="primary sm" disabled={busy} onClick={unlockRSA}>Select RSA private key…</button>
        </div>
      )}
    </div>
  );
}
