import { useEffect, useState } from "react";
import {
  LoadSweepKeys,
  SweepKeys,
  SweepSaveSigned,
  SweepScan,
  SweepSend,
} from "../../../wailsjs/go/app/App";
import { EventsOn } from "../../../wailsjs/runtime/runtime";
import { app as goapp } from "../../../wailsjs/go/models";
import type { SetConfirm, ToastFn } from "../../shared/types";
import type { Busy } from "./busy";
import { DestinationCard } from "./DestinationCard";
import { KeysFileCard } from "./KeysFileCard";
import { ProgressCard } from "./ProgressCard";
import { ReviewCard } from "./ReviewCard";

export function SweepFlow({ toast, setError, setConfirm }: {
  toast: ToastFn;
  setError: (msg: string) => void;
  setConfirm: SetConfirm;
}) {
  const [info, setInfo] = useState<goapp.SweepKeysInfo | null>(null);
  const [to, setTo] = useState("");
  const [rpc, setRpc] = useState("");
  const [plan, setPlan] = useState<goapp.SweepPlanView | null>(null);
  const [confirmTo, setConfirmTo] = useState("");
  const [busy, setBusy] = useState<Busy>("");
  const [log, setLog] = useState<string[]>([]);
  const [result, setResult] = useState<goapp.SweepResult | null>(null);

  useEffect(() => {
    SweepKeys().then(setInfo);
    return EventsOn("sweep:log", (line: string) => setLog((l) => [...l, line]));
  }, []);

  const run = async <T,>(label: Exclude<Busy, "">, fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(label);
    try {
      return await fn();
    } catch (e: any) {
      if (!String(e).includes("cancelled")) setError(String(e));
    } finally {
      setBusy("");
    }
  };

  const loadKeys = async () => {
    const res = await run("load", LoadSweepKeys);
    if (res?.loaded) {
      setInfo(res);
      setPlan(null);
      setResult(null);
    }
  };

  const scan = async () => {
    setResult(null);
    setLog([]);
    const res = await run("scan", () => SweepScan(to.trim(), rpc.trim()));
    if (res) {
      setPlan(res);
      setConfirmTo("");
    }
  };

  const send = () => setConfirm({
    text: `Send ${plan?.txs.length} transactions to ${plan?.to}? This cannot be undone.`,
    onYes: async () => {
      setConfirm(null);
      setLog([]);
      const res = await run("send", () => SweepSend(confirmTo.trim(), rpc.trim()));
      if (res) {
        setResult(res);
        setPlan(null);
        if (!res.error) toast("All transactions confirmed");
      }
    },
  });

  const saveSigned = async () => {
    const path = await run("save", SweepSaveSigned);
    if (path) toast("Saved to " + path);
  };

  return (
    <div className="content">
      <div className="content-inner">
        <h1>Transfer / sweep (Solana)</h1>
        <p className="sub">Moves every SPL token, then all SOL, from each wallet to one address. Nothing is sent until you confirm.</p>

        <KeysFileCard info={info} busy={busy} onLoad={loadKeys} />
        {info?.loaded && (
          <DestinationCard to={to} rpc={rpc} busy={busy} onToChange={setTo} onRpcChange={setRpc} onScan={scan} />
        )}
        {plan && (
          <ReviewCard plan={plan} confirmTo={confirmTo} busy={busy} onConfirmToChange={setConfirmTo}
            onSend={send} onSave={saveSigned} />
        )}
        {(busy === "send" || result) && <ProgressCard log={log} result={result} />}
      </div>
    </div>
  );
}
