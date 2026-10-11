import { FYSTACK_BLUE, FYSTACK_LOGO_PATH, FYSTACK_LOGO_VIEWBOX } from "../shared/constants";

export function BrandBar({ onHome }: { onHome: () => void }) {
  return (
    <div className="brandbar">
      <span className="brandlogo">
        <svg width="20" height="24" viewBox={FYSTACK_LOGO_VIEWBOX} aria-hidden>
          <path d={FYSTACK_LOGO_PATH} fill={FYSTACK_BLUE} />
        </svg>
        Fystack
      </span>
      <span className="brandsub">Recovery</span>
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
