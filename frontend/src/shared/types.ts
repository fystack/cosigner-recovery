export type Mode = "home" | "recover" | "sweep";
export type ToastKind = "success" | "info" | "error";
export type ToastFn = (msg: string, kind?: ToastKind) => void;
export type ConfirmRequest = { text: string; onYes: () => void };
export type SetConfirm = (c: ConfirmRequest | null) => void;
export type Step = 1 | 2 | 3;
