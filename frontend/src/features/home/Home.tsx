import { FYSTACK_LOGO_PATH } from "../../shared/constants";
import type { Mode } from "../../shared/types";

export function Home({ onPick }: { onPick: (m: Mode) => void }) {
  return (
    <div className="home">
      <aside className="home-brand">
        <div />
        <div className="home-brand-main">
          <span className="home-logo">
            <svg width="34" height="42" viewBox="0 0 17 21" aria-hidden>
              <path d={FYSTACK_LOGO_PATH} fill="#2563eb" />
            </svg>
          </span>
          <div className="home-brand-text">
            <div className="home-title">Fystack<br /><span>Recovery</span></div>
            <p>Rebuild wallet keys and move funds using the files exported from Fystack.</p>
          </div>
        </div>
        <div className="home-brand-foot">Keys stay on this device.</div>
      </aside>
      <main className="home-tasks">
        <div>
          <h1>What do you want to do?</h1>
          <p className="sub">Choose a task. Both work on the files exported from Fystack.</p>
        </div>
        <div className="home-list">
          <button className="home-card" onClick={() => onPick("recover")}>
            <span className="home-card-main">
              <span className="home-card-head">
                <span className="home-card-title">Recover keys</span>
                <span className="home-card-tag">Offline</span>
              </span>
              <span className="home-card-body">
                Combine key shares to rebuild a wallet's private keys. For HD wallets, also recover every child wallet.
              </span>
            </span>
            <span className="home-card-arrow">→</span>
          </button>
          <button className="home-card" onClick={() => onPick("sweep")}>
            <span className="home-card-main">
              <span className="home-card-head">
                <span className="home-card-title">Transfer / sweep (Solana)</span>
                <span className="home-card-tag online">Needs internet</span>
              </span>
              <span className="home-card-body">
                Move every token and all SOL from recovered Solana wallets to one address. Uses the child keys file exported from Recover keys.
              </span>
            </span>
            <span className="home-card-arrow">→</span>
          </button>
        </div>
      </main>
    </div>
  );
}
