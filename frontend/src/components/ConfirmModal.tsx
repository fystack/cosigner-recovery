import type { ConfirmRequest } from "../shared/types";

export function ConfirmModal({ request, onClose }: { request: ConfirmRequest; onClose: () => void }) {
  const confirm = () => {
    onClose();
    request.onYes();
  };
  return (
    <div className="overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h3>Please confirm</h3>
        <p>{request.text}</p>
        <div className="modal-actions">
          <button onClick={onClose}>Cancel</button>
          <button className="primary" onClick={confirm}>Confirm</button>
        </div>
      </div>
    </div>
  );
}
