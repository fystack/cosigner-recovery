import { useEffect, useState } from "react";
import "./style.css";
import {
  AddShareFile,
  UnlockWithPassphrase,
  UnlockWithRSAKeyFile,
  RemoveShare,
  Status,
  Recover,
  Reset,
  CopyToClipboard,
  ClearClipboard,
  ExportKey,
} from "../wailsjs/go/main/App";
import { recovery } from "../wailsjs/go/models";

type Step = 1 | 2 | 3;
const PROTOS = ["ECDSA", "EdDSA"];
const THRESHOLD = 2;

const FYSTACK_LOGO_PATH =
  "m16.10173,5.68864a5,5 0 0 0 -5,-5l-6,0a5,5 0 0 0 -5,5l0,13.927a1,1 0 0 0 1.623,0.782l3.684,-2.93a4,4 0 0 1 2.49,-0.87l3.203,0a5,5 0 0 0 5,-5l0,-5.909z";

type ToastKind = "success" | "info" | "error";
type ToastState = { msg: string; kind: ToastKind } | null;

function useToast() {
  const [toast, setToast] = useState<ToastState>(null);
  const show = (msg: string, kind: ToastKind = "success") => {
    setToast({ msg, kind });
    setTimeout(() => setToast(null), kind === "error" ? 5000 : 2800);
  };
  return { toast, show, dismiss: () => setToast(null) };
}

const TOAST_ICON: Record<ToastKind, string> = { success: "✓", info: "i", error: "✕" };

function Toast({ toast, onDismiss }: { toast: ToastState; onDismiss: () => void }) {
  if (!toast || !toast.msg.trim()) return null;
  return (
    <div className={`toast toast-${toast.kind}`} onClick={onDismiss} role="status">
      <span className="toast-icon">{TOAST_ICON[toast.kind]}</span>
      <span className="toast-msg">{toast.msg}</span>
    </div>
  );
}

export default function App() {
  const [step, setStep] = useState<Step>(1);
  const [status, setStatus] = useState<recovery.Status | null>(null);
  const [keys, setKeys] = useState<recovery.CombinedKey[]>([]);
  const [confirm, setConfirm] = useState<null | { text: string; onYes: () => void }>(null);
  const toast = useToast();
  const showError = (m: string) => {
    const msg = String(m).replace(/^Error:\s*/i, "").trim();
    if (!msg || /cancel/i.test(msg)) return;
    toast.show(msg, "error");
  };

  const refresh = async () => setStatus(await Status());
  useEffect(() => { refresh(); }, []);

  const addFile = async () => {
    try {
      await AddShareFile();
      await refresh();
    } catch (e: any) {
      showError(String(e));
    }
  };

  const unlockedReady = PROTOS.filter((p) => (status?.unlockedCounts?.[p] ?? 0) >= THRESHOLD);
  const canRecover = unlockedReady.length > 0 && !status?.walletMismatch;

  const doRecover = async () => {
    try {
      setKeys(await Recover());
      setStep(3);
      toast.show("Keys reconstructed and verified", "success");
    } catch (e: any) {
      showError(String(e));
    }
  };

  const startOver = async () => {
    await Reset();
    setKeys([]);
    setStep(1);
    await refresh();
  };

  return (
    <div className="app">
      <div className="brandbar">
        <span className="brandmark">
          <svg width="15" height="18.5" viewBox="0 0 17 21" aria-hidden>
            <path d={FYSTACK_LOGO_PATH} fill="#fff" />
          </svg>
        </span>
        <span className="brandname">Fystack <span className="brandsub">Recovery</span></span>
      </div>

      <div className="secbanner">
        <div className="secbanner-icon">⚠</div>
        <div className="secbanner-body">
          <div className="secbanner-title">Air-gapped recovery</div>
          <div className="secbanner-sub">Stay offline · don't screenshot · never share recovered keys.</div>
        </div>
      </div>

      <div className="stepper">
        <StepDot n={1} label="Add & unlock shares" step={step} />
        <div className="bar" />
        <StepDot n={2} label="Recover" step={step} />
        <div className="bar" />
        <StepDot n={3} label="Result" step={step} />
      </div>

      <div className="content">
        <div className="content-inner">
          {step === 1 && (
            <StepShares
              status={status}
              onAdd={addFile}
              onRefresh={refresh}
              onRemove={async (id) => { await RemoveShare(id); await refresh(); }}
              setError={showError}
            />
          )}
          {step === 2 && <StepRecover status={status} ready={unlockedReady} />}
          {step === 3 && <StepResult keys={keys} toast={toast.show} setError={showError} setConfirm={setConfirm} />}
        </div>
      </div>

      <div className="footer">
        {step > 1 && step < 3 && <button onClick={() => setStep((s) => (s - 1) as Step)}>Back</button>}
        {step === 3 && <button onClick={() => setConfirm({ text: "Start over? This wipes all shares and recovered keys from memory.", onYes: startOver })}>Start over</button>}
        <div className="spacer" />
        {step === 1 && (
          <button className="primary" disabled={!canRecover} onClick={() => setStep(2)}>
            Continue
          </button>
        )}
        {step === 2 && (
          <button className="primary" disabled={!canRecover}
            onClick={() => setConfirm({ text: "Reconstruct the full private keys? This materializes secret keys in memory. Only do this offline for recovery.", onYes: () => { setConfirm(null); doRecover(); } })}>
            Recover keys
          </button>
        )}
      </div>

      {confirm && (
        <div className="overlay" onClick={() => setConfirm(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>Please confirm</h3>
            <p>{confirm.text}</p>
            <div className="modal-actions">
              <button onClick={() => setConfirm(null)}>Cancel</button>
              <button className="primary" onClick={() => { const fn = confirm.onYes; setConfirm(null); fn(); }}>Confirm</button>
            </div>
          </div>
        </div>
      )}

      <Toast toast={toast.toast} onDismiss={toast.dismiss} />
    </div>
  );
}

function StepDot({ n, label, step }: { n: number; label: string; step: Step }) {
  const cls = step === n ? "active" : step > n ? "done" : "";
  return (
    <div className={`step ${cls}`}>
      <div className="dot">{step > n ? "✓" : n}</div>
      {label}
    </div>
  );
}

function StepShares({ status, onAdd, onRefresh, onRemove, setError }: {
  status: recovery.Status | null;
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
        You need at least {THRESHOLD} unlocked shares per protocol.
      </p>

      <div className="threshold">
        {PROTOS.map((p) => {
          const c = status?.unlockedCounts?.[p] ?? 0;
          return (
            <div className="thr-item" key={p}>
              <div className="thr-label">{p} shares</div>
              <div className={`thr-count ${c >= THRESHOLD ? "ready" : ""}`}>{c} / {THRESHOLD}</div>
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
        {share.unlocked && <span className="badge ok">✓ unlocked</span>}
        <div className="spacer" />
        <button className="danger" onClick={() => onRemove(share.id)}>Remove</button>
      </div>
      <div className="share-meta">wallet {share.walletId || "—"}</div>
      <div className="protos">
        {(share.protocols ?? []).map((p) => <span className="proto-chip" key={p}>{p}</span>)}
      </div>

      {!share.unlocked && share.needsPassphrase && (
        <div className="unlock-row">
          <input type="password" placeholder="6-word passphrase" value={pass}
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

function StepRecover({ status, ready }: { status: recovery.Status | null; ready: string[] }) {
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
              <div className={`thr-count ${ok ? "ready" : ""}`}>{ok ? `${c} shares · ready` : `${c} · not enough`}</div>
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

function StepResult({ keys, toast, setError, setConfirm }: {
  keys: recovery.CombinedKey[];
  toast: (s: string, kind?: ToastKind) => void;
  setError: (s: string) => void;
  setConfirm: (c: null | { text: string; onYes: () => void }) => void;
}) {
  return (
    <>
      <h1>Recovered keys</h1>
      <p className="sub">Reconstructed and verified against the wallet's public keys. Handle these secrets with extreme care.</p>
      {keys.map((k) => <KeyCard key={k.protocol} k={k} toast={toast} setError={setError} setConfirm={setConfirm} />)}
    </>
  );
}

function KeyCard({ k, toast, setError, setConfirm }: {
  k: recovery.CombinedKey;
  toast: (s: string, kind?: ToastKind) => void;
  setError: (s: string) => void;
  setConfirm: (c: null | { text: string; onYes: () => void }) => void;
}) {
  const [reveal, setReveal] = useState(false);
  const [copied, setCopied] = useState(false);

  const copy = () => setConfirm({
    text: `Copy the ${k.protocol} private key to the clipboard? It will be cleared automatically after 20 seconds.`,
    onYes: async () => {
      setConfirm(null);
      await CopyToClipboard(k.privateKeyHex);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      toast("Copied · clipboard clears in 20s");
      setTimeout(() => { ClearClipboard(); }, 20000);
    },
  });

  const copyAddress = async () => {
    await CopyToClipboard(k.address);
    toast("Address copied", "info");
  };

  const doExport = () => setConfirm({
    text: `Export the ${k.protocol} private key to a file? Anyone with the file controls the wallet.`,
    onYes: async () => {
      setConfirm(null);
      try {
        const path = await ExportKey(k.protocol, k.privateKeyHex);
        toast("Exported to " + path);
      } catch (e: any) {
        if (!String(e).includes("cancelled")) setError(String(e));
      }
    },
  });

  return (
    <div className="keycard">
      <div className="keycard-head">
        <h3>{k.protocol}</h3>
        {k.verified && <span className="verifybadge">✓ verified against public key</span>}
        {k.testSigned && <span className="verifybadge">✓ test-signed</span>}
      </div>

      {k.address && (
        <>
          <div className="field-label">{k.addressLabel || "Address"}</div>
          <div className="addr-row">
            <div className="keyval" style={{ userSelect: "text", flex: 1 }}>{k.address}</div>
            <button className="sm" onClick={copyAddress}>Copy</button>
          </div>
        </>
      )}

      <div className="field-label">Private key (hex)</div>
      <div className={`keyval ${reveal ? "" : "hidden"}`}>
        {reveal ? k.privateKeyHex : "•".repeat(64)}
      </div>
      <div className="key-actions">
        <button className="sm" onClick={() => setReveal((r) => !r)}>{reveal ? "Hide" : "Reveal"}</button>
        <button className="sm" onClick={copy}>{copied ? "✓ Copied" : "Copy"}</button>
        <button className="sm" onClick={doExport}>Export…</button>
      </div>
      {k.note && <div className="keynote">ℹ {k.note}</div>}

      {k.publicKeyHex && (
        <>
          <div className="field-label">Public key (compressed)</div>
          <div className="keyval" style={{ userSelect: "text" }}>{k.publicKeyHex}</div>
        </>
      )}
    </div>
  );
}
