import { useState } from "react";
import { CopyToClipboard, ClearClipboard, ExportKey } from "../../../wailsjs/go/app/App";
import { recovery } from "../../../wailsjs/go/models";
import type { SetConfirm, ToastFn } from "../../shared/types";

export function KeyCard({ k, toast, setError, setConfirm }: {
  k: recovery.CombinedKey;
  toast: ToastFn;
  setError: (s: string) => void;
  setConfirm: SetConfirm;
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
        {k.verified && <span className="verifybadge">✓ Verified against public key</span>}
        {k.testSigned && <span className="verifybadge">✓ Test-signed</span>}
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
