import { useState } from "react";
import type { ToastKind } from "../shared/types";

type ToastState = { msg: string; kind: ToastKind } | null;

const TOAST_ICON: Record<ToastKind, string> = { success: "✓", info: "i", error: "✕" };

export function useToast() {
  const [toast, setToast] = useState<ToastState>(null);
  const show = (msg: string, kind: ToastKind = "success") => {
    setToast({ msg, kind });
    setTimeout(() => setToast(null), kind === "error" ? 5000 : 2800);
  };
  return { toast, show, dismiss: () => setToast(null) };
}

export function Toast({ toast, onDismiss }: { toast: ToastState; onDismiss: () => void }) {
  if (!toast || !toast.msg.trim()) return null;
  return (
    <div className={`toast toast-${toast.kind}`} onClick={onDismiss} role="status">
      <span className="toast-icon">{TOAST_ICON[toast.kind]}</span>
      <span className="toast-msg">{toast.msg}</span>
    </div>
  );
}
