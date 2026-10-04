import { FYSTACK_LOGO_PATH } from "../shared/constants";

export function BrandBar({ onHome }: { onHome: () => void }) {
  return (
    <div className="brandbar">
      <span className="brandmark">
        <svg width="15" height="18.5" viewBox="0 0 17 21" aria-hidden>
          <path d={FYSTACK_LOGO_PATH} fill="#fff" />
        </svg>
      </span>
      <span className="brandname">Fystack <span className="brandsub">Recovery</span></span>
      <div className="spacer" />
      <button className="sm" onClick={onHome}>← Home</button>
    </div>
  );
}

export function SecurityBanner({ title, children }: { title: string; children: string }) {
  return (
    <div className="secbanner">
      <div className="secbanner-icon">⚠</div>
      <div className="secbanner-body">
        <div className="secbanner-title">{title}</div>
        <div className="secbanner-sub">{children}</div>
      </div>
    </div>
  );
}
