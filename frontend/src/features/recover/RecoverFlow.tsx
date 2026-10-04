import type { SetConfirm, ToastFn } from "../../shared/types";
import { StepRecover } from "./StepRecover";
import { StepResult } from "./StepResult";
import { StepShares } from "./StepShares";
import { StepDot } from "./Stepper";
import { useRecoverFlow } from "./useRecoverFlow";

export function RecoverFlow({ toast, setError, setConfirm }: {
  toast: ToastFn;
  setError: (msg: string) => void;
  setConfirm: SetConfirm;
}) {
  const flow = useRecoverFlow({ toast, setError, setConfirm });
  const { step } = flow;

  return (
    <>
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
              status={flow.status}
              hd={flow.hd}
              onAdd={flow.addShare}
              onRefresh={flow.refresh}
              onRemove={flow.removeShare}
              setError={setError}
              onAddPaths={flow.addPaths}
              onUnlockPaths={flow.unlockPaths}
              onRemovePaths={flow.removePaths}
            />
          )}
          {step === 2 && <StepRecover status={flow.status} ready={flow.unlockedReady} />}
          {step === 3 && <StepResult keys={flow.keys} hd={flow.hd} toast={toast} setError={setError} setConfirm={setConfirm} />}
        </div>
      </div>

      <div className="footer">
        {step === 2 && <button onClick={flow.back}>Back</button>}
        {step === 3 && <button onClick={flow.confirmStartOver}>Start over</button>}
        <div className="spacer" />
        {step === 1 && <button className="primary" disabled={!flow.canRecover} onClick={flow.next}>Continue</button>}
        {step === 2 && <button className="primary" disabled={!flow.canRecover} onClick={flow.confirmRecover}>Recover keys</button>}
      </div>
    </>
  );
}
