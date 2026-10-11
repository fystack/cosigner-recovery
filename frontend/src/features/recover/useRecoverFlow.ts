import { useEffect, useState } from "react";
import {
  AddChildPathsFile,
  AddShareFile,
  HDStatus,
  Recover,
  RemoveChildPaths,
  RemoveShare,
  Reset,
  Status,
  UnlockChildPaths,
} from "../../../wailsjs/go/app/App";
import { recovery } from "../../../wailsjs/go/models";
import { PROTOS, MIN_SHARES } from "../../shared/constants";
import type { SetConfirm, Step, ToastFn } from "../../shared/types";

type Deps = {
  toast: ToastFn;
  setError: (msg: string) => void;
  setConfirm: SetConfirm;
};

export function useRecoverFlow({ toast, setError, setConfirm }: Deps) {
  const [step, setStep] = useState<Step>(1);
  const [status, setStatus] = useState<recovery.Status | null>(null);
  const [keys, setKeys] = useState<recovery.CombinedKey[]>([]);
  const [hd, setHd] = useState<recovery.HDInfo | null>(null);

  const refresh = async () => {
    setStatus(await Status());
    setHd(await HDStatus());
  };
  useEffect(() => { refresh(); }, []);

  const attempt = async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    try {
      const result = await fn();
      await refresh();
      return result;
    } catch (e: any) {
      setError(String(e));
    }
  };

  const unlockedReady = PROTOS.filter((p) => (status?.unlockedCounts?.[p] ?? 0) >= MIN_SHARES);
  const canRecover = unlockedReady.length > 0 && !status?.walletMismatch;

  const addShare = () => attempt(AddShareFile);
  const removeShare = async (id: string) => { await RemoveShare(id); await refresh(); };
  const addPaths = () => attempt(AddChildPathsFile);
  const removePaths = async () => { await RemoveChildPaths(); await refresh(); };

  const unlockPaths = async () => {
    const info = await attempt(UnlockChildPaths);
    if (info?.loaded) toast(`Loaded ${info.childCount} child wallets`, "success");
  };

  const recoverKeys = async () => {
    try {
      setKeys(await Recover());
      setStep(3);
      toast("Keys reconstructed and verified", "success");
    } catch (e: any) {
      setError(String(e));
    }
  };

  const startOver = async () => {
    await Reset();
    setKeys([]);
    setHd(null);
    setStep(1);
    await refresh();
  };

  const confirmRecover = () => setConfirm({
    text: "Reconstruct the full private keys? This materializes secret keys in memory. Only do this offline for recovery.",
    onYes: recoverKeys,
  });

  const confirmStartOver = () => setConfirm({
    text: "Start over? This wipes all shares and recovered keys from memory.",
    onYes: startOver,
  });

  return {
    step, status, keys, hd, unlockedReady, canRecover,
    refresh, addShare, removeShare, addPaths, unlockPaths, removePaths,
    next: () => setStep(2),
    back: () => setStep((s) => (s - 1) as Step),
    confirmRecover, confirmStartOver,
  };
}
