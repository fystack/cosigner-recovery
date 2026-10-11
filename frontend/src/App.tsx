import { useState } from "react";
import "./style.css";
import { Reset, ResetSweep } from "../wailsjs/go/app/App";
import { BrandBar, SecurityBanner } from "./components/BrandBar";
import { ConfirmModal } from "./components/ConfirmModal";
import { Toast, useToast } from "./components/Toast";
import { Home } from "./features/home/Home";
import { RecoverFlow } from "./features/recover/RecoverFlow";
import { SweepFlow } from "./features/sweep/SweepFlow";
import { useZoom } from "./shared/useZoom";
import type { ConfirmRequest, Mode } from "./shared/types";

export default function App() {
  const [mode, setMode] = useState<Mode>("home");
  const [confirm, setConfirm] = useState<ConfirmRequest | null>(null);
  const toast = useToast();
  useZoom((percent) => toast.show(`Zoom ${percent}%`, "info"));

  const showError = (m: string) => {
    const msg = String(m).replace(/^Error:\s*/i, "").trim();
    if (!msg || /cancel/i.test(msg)) return;
    toast.show(msg, "error");
  };

  const goHome = async () => {
    await Reset();
    await ResetSweep();
    setMode("home");
  };

  const askHome = () => setConfirm({
    text: "Go back to the home screen? This wipes all shares and keys from memory.",
    onYes: goHome,
  });

  return (
    <div className="app">
      {mode !== "home" && <BrandBar onHome={askHome} />}

      {mode === "home" && <Home onPick={setMode} />}
      {mode === "recover" && (
        <>
          <SecurityBanner title="Air-gapped recovery">Stay offline · don't screenshot · never share recovered keys.</SecurityBanner>
          <RecoverFlow toast={toast.show} setError={showError} setConfirm={setConfirm} />
        </>
      )}
      {mode === "sweep" && (
        <>
          <SecurityBanner title="Network access">This mode talks to a Solana RPC. Use a machine you trust, and check the destination address.</SecurityBanner>
          <SweepFlow toast={toast.show} setError={showError} setConfirm={setConfirm} />
        </>
      )}

      {confirm && <ConfirmModal request={confirm} onClose={() => setConfirm(null)} />}
      <Toast toast={toast.toast} onDismiss={toast.dismiss} />
    </div>
  );
}
