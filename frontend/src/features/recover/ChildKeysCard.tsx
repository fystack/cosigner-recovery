import { useState } from "react";
import { ExportChildKeys, ExportKeystores } from "../../../wailsjs/go/app/App";
import { recovery } from "../../../wailsjs/go/models";
import type { SetConfirm, ToastFn } from "../../shared/types";

export function ChildKeysCard({ hd, toast, setError, setConfirm }: {
  hd: recovery.HDInfo;
  toast: ToastFn;
  setError: (s: string) => void;
  setConfirm: SetConfirm;
}) {
  const [showKeystore, setShowKeystore] = useState(false);
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [busy, setBusy] = useState(false);

  const doExport = () => setConfirm({
    text: `Export the private keys of the master and all ${hd.childCount} child wallets to one file? Anyone with the file controls every one of these wallets.`,
    onYes: async () => {
      setConfirm(null);
      try {
        const path = await ExportChildKeys();
        toast("Exported to " + path);
      } catch (e: any) {
        if (!String(e).includes("cancelled")) setError(String(e));
      }
    },
  });

  const passwordError =
    password.length > 0 && password.length < 8
      ? "Use at least 8 characters."
      : password2.length > 0 && password !== password2
        ? "Passwords do not match."
        : "";

  const doKeystore = async () => {
    setBusy(true);
    try {
      const msg = await ExportKeystores(password);
      toast(msg);
      setPassword("");
      setPassword2("");
      setShowKeystore(false);
    } catch (e: any) {
      if (!String(e).includes("cancelled")) setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="keycard">
      <div className="keycard-head">
        <h3>Child wallets</h3>
        <span className="verifybadge">{hd.childCount} wallets</span>
      </div>
      <div className="keynote">
        Save every child key to one file. Use .json with recover-cli to sign for many wallets at once, or .csv to import the ECDSA keys elsewhere.
        To import into MetaMask, export password-protected keystore files.
      </div>
      <div className="key-actions">
        <button className="sm" onClick={doExport}>Export all child keys…</button>
        <button className="sm" onClick={() => setShowKeystore((v) => !v)}>Export keystore files…</button>
      </div>

      {showKeystore && (
        <>
          <div className="field-label">Keystore password</div>
          <div className="unlock-row">
            <input type="password" placeholder="Enter a password (8+ characters)" value={password}
              onChange={(e) => setPassword(e.target.value)} />
          </div>
          <div className="unlock-row">
            <input type="password" placeholder="Confirm the password" value={password2}
              onChange={(e) => setPassword2(e.target.value)} />
          </div>
          {passwordError && <div className="error">{passwordError}</div>}
          <div className="keynote">
            One file per EVM wallet (master and children). Solana keys cannot be exported this way. Encrypting takes a few seconds per wallet.
          </div>
          <div className="key-actions">
            <button className="primary sm" disabled={busy || password.length < 8 || password !== password2} onClick={doKeystore}>
              {busy ? "Encrypting…" : "Choose folder & export"}
            </button>
          </div>
        </>
      )}
    </div>
  );
}
