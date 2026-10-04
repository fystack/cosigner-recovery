import { recovery } from "../../../wailsjs/go/models";
import type { SetConfirm, ToastFn } from "../../shared/types";
import { KeyCard } from "./KeyCard";
import { ChildKeysCard } from "./ChildKeysCard";

export function StepResult({ keys, hd, toast, setError, setConfirm }: {
  keys: recovery.CombinedKey[];
  hd: recovery.HDInfo | null;
  toast: ToastFn;
  setError: (s: string) => void;
  setConfirm: SetConfirm;
}) {
  return (
    <>
      <h1>Recovered keys</h1>
      <p className="sub">Reconstructed and verified against the wallet's public keys. Handle these secrets with extreme care.</p>
      {keys.map((k) => <KeyCard key={k.protocol} k={k} toast={toast} setError={setError} setConfirm={setConfirm} />)}
      {hd?.loaded && <ChildKeysCard hd={hd} toast={toast} setError={setError} setConfirm={setConfirm} />}
    </>
  );
}
