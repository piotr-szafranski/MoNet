import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { X, Loader2 } from 'lucide-react';

// ---- API ----
export class ApiError extends Error {}

export async function api(path, opts = {}) {
  const init = { method: opts.method || 'GET', credentials: 'same-origin', headers: {} };
  if (opts.body instanceof FormData) init.body = opts.body;
  else if (opts.body !== undefined) {
    init.body = JSON.stringify(opts.body);
    init.headers['Content-Type'] = 'application/json';
  }
  const r = await fetch('/api' + path, init);
  if (r.status === 401 && !path.startsWith('/auth')) {
    window.dispatchEvent(new Event('asi-logout'));
  }
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  if (!r.ok) throw new ApiError((data && data.error) || `Błąd ${r.status}`);
  return data;
}

export function useApi(path, deps = [], interval = 0) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    if (!path) return;
    try {
      const d = await api(path);
      setData(d);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, ...deps]);
  useEffect(() => {
    setLoading(true);
    load();
    if (interval > 0) {
      const t = setInterval(load, interval);
      return () => clearInterval(t);
    }
  }, [load, interval]);
  return { data, error, loading, reload: load, setData };
}

// ---- sesja i uprawnienia ----
export const AuthCtx = createContext(null);
export const useAuth = () => useContext(AuthCtx);
export function useCan() {
  const { user } = useAuth();
  return (p) => !!user?.permissions?.includes(p);
}

// ---- powiadomienia ----
const ToastCtx = createContext(() => {});
export const useToast = () => useContext(ToastCtx);
export function ToastProvider({ children }) {
  const [items, setItems] = useState([]);
  const push = useCallback((msg, tone = 'ok') => {
    const id = Math.random();
    setItems((x) => [...x, { id, msg, tone }]);
    setTimeout(() => setItems((x) => x.filter((i) => i.id !== id)), 4200);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="fixed bottom-5 right-5 z-[100] flex flex-col gap-2">
        {items.map((t) => (
          <div key={t.id} className={`rounded-xl border px-4 py-2.5 text-sm ${t.tone === 'err' ? 'border-rose-500/40 bg-rose-950/90 text-rose-100' : 'border-emerald-500/30 bg-emerald-950/90 text-emerald-100'}`}>
            {t.msg}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

// ---- formatowanie ----
export const fmtDate = (s) => {
  if (!s) return '–';
  const d = new Date(s);
  if (isNaN(d)) return s;
  return d.toLocaleString('pl-PL', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
};
export const fmtDur = (ms) => {
  if (!ms && ms !== 0) return '–';
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
};
export const num = (n) => (n ?? 0).toLocaleString('pl-PL');

// ---- komponenty ----
// Przycisk zwijania: zwinięte = trójkątna strzałka w dół, rozwinięte = pozioma kreska (jak „minimalizuj” okna).
// Dwa ramiona strzałki obracają się płynnie do poziomu i z powrotem.
export function CollapseToggle({ open }) {
  const arm = 'absolute top-1/2 h-[2px] w-[9px] rounded-full bg-current transition-transform duration-300 ease-out';
  return (
    <span aria-hidden className={`relative inline-block h-7 w-7 shrink-0 rounded-full border transition-colors ${open ? 'border-accent/50 text-accent' : 'border-white/15 text-slate-300'}`}>
      <span className={`${arm} right-1/2 origin-right`} style={{ transform: `translateY(-50%) ${open ? 'rotate(0deg)' : 'rotate(40deg)'}` }} />
      <span className={`${arm} left-1/2 origin-left`} style={{ transform: `translateY(-50%) ${open ? 'rotate(0deg)' : 'rotate(-40deg)'}` }} />
    </span>
  );
}

export function Card({ title, icon: Icon, actions, children, className = '', pad = true, bodyClass = '', collapsible = false, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  const shown = !collapsible || open;
  const toggle = () => collapsible && setOpen(!open);
  return (
    <section className={`card ${className}`}>
      {(title || actions || collapsible) && (
        <header className={`card-head ${collapsible ? 'cursor-pointer select-none' : ''} ${collapsible && !open ? 'after:hidden' : ''}`} onClick={toggle}
          role={collapsible ? 'button' : undefined} aria-expanded={collapsible ? open : undefined} tabIndex={collapsible ? 0 : undefined}
          onKeyDown={(e) => { if (collapsible && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); toggle(); } }}>
          <h2 className="flex items-center gap-2 text-[13.5px] font-extrabold tracking-[.03em] text-white">
            {Icon && <Icon size={14} strokeWidth={1.8} className="text-accent" />} {typeof title === 'string' ? titleCase(title) : title}
          </h2>
          <div className="flex items-center gap-2" onClick={(e) => collapsible && actions && e.target !== e.currentTarget && e.stopPropagation()}>{actions}{collapsible && <CollapseToggle open={open} />}</div>
        </header>
      )}
      {shown && <div className={`${pad ? 'p-4' : ''} ${bodyClass}`}>{children}</div>}
    </section>
  );
}

const tones = {
  red: 'border-rose-400/40 bg-rose-500/[.06] text-rose-300',
  amber: 'border-amber-400/40 bg-amber-500/[.06] text-amber-200',
  green: 'border-emerald-400/45 bg-emerald-500/[.06] text-emerald-300',
  blue: 'border-sky-300/40 bg-sky-400/[.06] text-sky-200',
  violet: 'border-violet-300/40 bg-violet-400/[.06] text-violet-200',
  slate: 'border-white/15 bg-transparent text-slate-300',
};
export function Badge({ children, tone = 'slate', className = '', title }) {
  return <span title={title} className={`inline-flex items-center gap-1 whitespace-nowrap rounded-sm border px-1.5 py-[1px] font-mono text-[10px] tracking-wide ${tones[tone]} ${className}`}>{children}</span>;
}

export const stateTone = { active: 'green', missing: 'red', unreachable: 'red', unstable: 'amber', gone: 'red', completed: 'green', running: 'blue', paused: 'amber', failed: 'red', cancelled: 'slate', queued: 'blue', importing: 'blue' };
export const stateLabel = { active: 'aktywny', missing: 'niedostępny', unreachable: 'niedostępny', unstable: 'niestabilny', gone: 'niedostępny', completed: 'zakończony', running: 'IN PROG', paused: 'wstrzymany', failed: 'błąd', cancelled: 'anulowany', queued: 'w kolejce', importing: 'import' };
const stateDot = { green: 's-ok', amber: 's-warn', red: 's-err', blue: 's-info', slate: 's-off', violet: 's-warn' };
export const State = ({ s }) => <span className={`status ${stateDot[stateTone[s]] || 's-off'} ${s === 'running' ? 's-run' : ''}`}><i aria-hidden />{stateLabel[s] || s}</span>;

export const flagLabel = {
  'panel-admin': 'panel admina', staging: 'staging', iot: 'IoT', devops: 'devops', 'baza-danych': 'baza danych', cms: 'CMS', artefakt: 'artefakt',
  'cert-wygasly': 'cert wygasł', 'cert-wygasa': 'cert wygasa', 'cert-self-signed': 'self-signed', 'tls-bez-certyfikatu': 'TLS bez certyfikatu (SNI)', 'wolna-odpowiedz': 'wolna odpowiedź', 'http-obok-https': 'HTTP odsłonięty obok HTTPS', 'stary-tls': 'stary TLS',
  'logowanie-bez-tls': 'logowanie bez TLS', 'ujawniona-wersja': 'ujawniona wersja', 'ciasteczko-bez-httponly': 'cookie bez HttpOnly',
  'niestandardowy-port-http': 'niestand. port',
};
const flagTone = { 'http-obok-https': 'amber', 'panel-admin': 'red', staging: 'amber', iot: 'violet', 'baza-danych': 'red', artefakt: 'red', 'cert-wygasly': 'red', 'logowanie-bez-tls': 'red', devops: 'amber' };
export const Flag = ({ f }) => <Badge tone={flagTone[f] || 'slate'}>{flagLabel[f] || f}</Badge>;

// Klasa (ocena priorytetu analitycznego 0–100%): gruby pasek z wartością procentową.
export function Interest({ v, wide = false }) {
  const c = v >= 50 ? 'linear-gradient(90deg,#be123c,#fb7185)' : v >= 25 ? 'linear-gradient(90deg,#b45309,#fcd34d)' : v >= 10 ? 'linear-gradient(90deg,#2f7fd0,#6cb6ff)' : 'linear-gradient(90deg,#334155,#64748b)';
  return (
    <div className="flex items-center gap-2" title={`Klasa ${v}%`}>
      <div className={`h-2 ${wide ? 'w-28' : 'w-16'} overflow-hidden rounded-md bg-white/[.07]`}><div className="h-full" style={{ width: `${Math.max(4, v)}%`, background: c }} /></div>
      <span className="w-9 font-mono text-[11.5px] font-semibold text-slate-300">{v}%</span>
    </div>
  );
}

export function Stat({ label, value, tone = 'text-slate-100', sub, icon: Icon, onClick }) {
  return (
    <button onClick={onClick} disabled={!onClick} className="card stat-card group flex flex-col items-start gap-1 p-4 text-left transition">
      <div className="flex w-full items-center justify-between text-[10px] font-medium uppercase tracking-[.2em] text-slate-500">
        {label} {Icon && <Icon size={13} strokeWidth={1.5} className="text-accent/60 group-hover:text-accent" />}
      </div>
      <div className={`font-mono text-[28px] font-semibold tracking-tight ${tone}`}>{value}</div>
      {sub && <div className="text-[11px] text-slate-500">{sub}</div>}
    </button>
  );
}

export function Modal({ open, onClose, title, children, wide }) {
  useEffect(() => {
    const k = (e) => e.key === 'Escape' && onClose?.();
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, [onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-6" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`card mt-10 w-full ${wide ? 'max-w-4xl' : 'max-w-xl'}`}>
        <header className="card-head px-5 py-3">
          <h3 className="text-[13.5px] font-extrabold tracking-[.03em] text-white">{typeof title === 'string' ? titleCase(title) : title}</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-white"><X size={18} /></button>
        </header>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

export function Drawer({ open, onClose, title, children }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="h-full w-full max-w-3xl overflow-y-auto border-l border-accent/25 shadow-2xl" style={{ background: 'linear-gradient(180deg,#0d1014,#050608)' }}>
        <header className="card-head sticky top-0 z-10 bg-[var(--card)] px-5 py-3">
          <h3 className="truncate font-mono text-sm font-semibold text-slate-100">{title}</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-white"><X size={18} /></button>
        </header>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

export const Spinner = ({ label = 'Ładowanie…' }) => (
  <div className="flex items-center gap-2 p-6 text-sm text-slate-500"><Loader2 size={16} className="animate-spin" /> {label}</div>
);
export const Empty = ({ children }) => <div className="p-8 text-center text-sm text-slate-500">{children}</div>;
export const ErrorBox = ({ msg }) => msg ? <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">{msg}</div> : null;

export function Field({ label, hint, children, className = '' }) {
  return (
    <label className={`block ${className}`}>
      <span className="label">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-[11px] text-slate-500">{hint}</span>}
    </label>
  );
}

export function Toggle({ checked, onChange, label }) {
  return (
    <button type="button" onClick={() => onChange(!checked)} className="flex items-center gap-2 text-sm text-slate-300">
      <span className={`relative h-[18px] w-8 rounded-full border transition ${checked ? 'border-accent/70 bg-accent/25' : 'border-white/15 bg-white/[.04]'}`}>
        <span className={`absolute top-[2px] h-3 w-3 rounded-full transition ${checked ? 'left-[15px] bg-accent shadow-[0_0_8px_#6cb6ff]' : 'left-[2px] bg-slate-400'}`} />
      </span>
      {label}
    </button>
  );
}

export function TagInput({ value = [], onChange, placeholder = 'tag + Enter' }) {
  const [t, setT] = useState('');
  const add = () => {
    const v = t.trim();
    if (v && !value.includes(v)) onChange([...value, v]);
    setT('');
  };
  return (
    <div className="input flex flex-wrap items-center gap-1.5 py-1.5">
      {value.map((x) => (
        <span key={x} className="flex items-center gap-1 rounded bg-white/10 px-1.5 py-0.5 text-xs">
          {x}<button type="button" onClick={() => onChange(value.filter((y) => y !== x))} className="text-slate-400 hover:text-white">×</button>
        </span>
      ))}
      <input value={t} onChange={(e) => setT(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add(); } }} onBlur={add}
        placeholder={placeholder} className="min-w-[80px] flex-1 bg-transparent text-sm outline-none placeholder-slate-600" />
    </div>
  );
}

// Gruby pasek postępu z procentem: cyfry są białe na czarnym tle i stają się czarne dokładnie tam,
// gdzie sięga niebieskie wypełnienie (druga warstwa tekstu przycięta do szerokości wypełnienia).
export function BigProgress({ value, total, tone = 'accent', height = 26 }) {
  const p = total ? Math.min(100, (value / total) * 100) : 0;
  const label = `${Math.floor(p)}%`;
  const fill = tone === 'signal' ? 'linear-gradient(90deg,#1f9d57,#4ade80)' : tone === 'amber' ? 'linear-gradient(90deg,#b7791f,#fcd34d)' : 'linear-gradient(90deg,#2f7fd0,#6cb6ff 70%,#9ccfff)';
  const glow = tone === 'signal' ? 'rgba(74,222,128,.55)' : tone === 'amber' ? 'rgba(252,211,77,.45)' : 'rgba(108,182,255,.6)';
  const txt = 'absolute inset-0 flex items-center justify-center font-mono text-[11px] font-bold tracking-wider';
  return (
    <div className="relative w-full overflow-hidden rounded-full bg-black/80" style={{ height, border: '1px solid rgba(120,170,235,.22)' }}>
      <div className="absolute inset-y-0 left-0 transition-[width] duration-700" style={{ width: `${p}%`, background: fill, boxShadow: `0 0 14px ${glow}` }} />
      <div className={`${txt} text-white`}>{label}</div>
      <div className={`${txt} text-black transition-[clip-path] duration-700`} style={{ clipPath: `inset(0 ${100 - p}% 0 0)` }}>{label}</div>
    </div>
  );
}

export function Progress({ value, total, tone = 'bg-accent' }) {
  const p = total ? Math.min(100, (value / total) * 100) : 0;
  return (
    <div className="h-[3px] w-full overflow-hidden bg-white/[.06]">
      <div className={`h-full ${tone} shadow-[0_0_10px_rgba(108,182,255,.7)] transition-all`} style={{ width: `${p}%` }} />
    </div>
  );
}

// Historia obecności: kwadraty 1/0 z ostatnich skanów.
export function HistoryBar({ h = '' }) {
  return (
    <div className="flex gap-[2px]" title="obecność w kolejnych skanach (od najstarszego)">
      {h.split('').map((c, i) => <span key={i} className={`h-3 w-[5px] ${c === '1' ? 'bg-signal/80' : 'bg-rose-500/45'}`} />)}
    </div>
  );
}

// Proste wykresy SVG (bez zewnętrznych bibliotek).
export function Bars({ data, color = '#6cb6ff', height = 120, valueKey = 'v', labelKey = 'k' }) {
  const max = Math.max(1, ...data.map((d) => d[valueKey]));
  const showLabels = data.length <= 24;
  return (
    <div className="flex w-full min-w-0 items-end gap-[3px] overflow-hidden" style={{ height }}>
      {data.map((d, i) => (
        <div key={i} className="group flex h-full min-w-0 flex-1 flex-col items-center justify-end gap-1" title={`${d[labelKey]}: ${d[valueKey]}`}>
          {showLabels && <span className="font-mono text-[9px] text-slate-500 opacity-0 group-hover:opacity-100">{d[valueKey]}</span>}
          <div className="w-full" style={{ height: `${(d[valueKey] / max) * 85}%`, background: `linear-gradient(180deg, ${color}, ${color}33)`, minHeight: 2, borderTop: `1px solid ${color}` }} />
          {showLabels && <span className="max-w-full truncate font-mono text-[9px] text-slate-600">{d[labelKey]}</span>}
        </div>
      ))}
    </div>
  );
}

const titleCase = (s) => s.replace(/(^|[\s/(-])(\p{L})/gu, (m, p, c) => p + c.toUpperCase());

// Wysoka wersja wykresu słupkowego: rozkłada pozycje na całą wysokość karty, grubsze paski.
export function TallBars({ items, color = 'bg-accent', onClick, spread = true }) {
  const max = Math.max(1, ...items.map((i) => i.v));
  return (
    <div className={`flex flex-col ${spread ? 'h-full justify-between gap-2' : 'gap-3.5'}`}>
      {items.map((i) => (
        <button key={i.k} onClick={() => onClick?.(i.k)} disabled={!onClick} className={`group flex w-full flex-col justify-center gap-1.5 text-left ${spread ? 'flex-1' : ''}`}>
          <span className="flex items-baseline justify-between">
            <span className="text-[13px] font-semibold tracking-wide text-slate-200 group-enabled:group-hover:text-white">{titleCase(i.label || i.k)}</span>
            <span className="font-mono text-[12px] font-semibold text-slate-300">{i.v}</span>
          </span>
          <span className="h-2.5 w-full overflow-hidden rounded-md bg-white/[.06]">
            <span className={`block h-full ${color}`} style={{ width: `${Math.max(2, (i.v / max) * 100)}%`, boxShadow: '0 0 10px rgba(108,182,255,.45)' }} />
          </span>
        </button>
      ))}
    </div>
  );
}

export function HBar({ items, color = 'bg-accent/70', onClick }) {
  const max = Math.max(1, ...items.map((i) => i.v));
  return (
    <div className="space-y-1.5">
      {items.map((i) => (
        <button key={i.k} onClick={() => onClick?.(i.k)} disabled={!onClick} className="group flex w-full items-center gap-2 text-left">
          <span className="w-36 truncate text-[12px] text-slate-300 group-enabled:group-hover:text-white">{i.label || i.k}</span>
          <span className="h-[3px] flex-1 overflow-hidden bg-white/[.06]"><span className={`block h-full ${color}`} style={{ width: `${(i.v / max) * 100}%` }} /></span>
          <span className="w-8 text-right font-mono text-[11px] text-slate-400">{i.v}</span>
        </button>
      ))}
    </div>
  );
}

export function useDebounced(v, ms = 300) {
  const [d, setD] = useState(v);
  const t = useRef();
  useEffect(() => {
    clearTimeout(t.current);
    t.current = setTimeout(() => setD(v), ms);
    return () => clearTimeout(t.current);
  }, [v, ms]);
  return d;
}

export function download(path) {
  const a = document.createElement('a');
  a.href = '/api' + path;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

// Tabela grup usług (ta sama klasa + ten sam zestaw flag w jednym wierszu): dashboard i zakładka Usługi.
// ---- kategorie usług: wg tego, CO wykryto (sygnatury), a nie wg protokołu z nmapa ----
// Kolejność = priorytet: usługa trafia do pierwszej pasującej kategorii (jedna usługa = jedna kategoria).
const parseArr = (v) => { if (Array.isArray(v)) return v; try { return JSON.parse(v || '[]') || []; } catch { return []; } };
export const SVC_CATEGORIES = [
  { k: 'iot', label: 'Urządzenia IoT', desc: 'kamery, drukarki, routery, NAS', test: (c, s) => c.has('iot') || ['rtsp', 'jetdirect', 'ipp', 'upnp', 'mqtt'].includes(s) },
  { k: 'staging', label: 'Środowiska testowe', desc: 'staging, dev, test', test: (c) => c.has('staging') },
  { k: 'admin', label: 'Panele administracyjne', desc: 'logowanie, /admin, konsole', test: (c) => c.has('admin-panel') },
  { k: 'cms', label: 'CMS', desc: 'WordPress, Joomla, Drupal…', test: (c) => c.has('cms') },
  { k: 'devops', label: 'DevOps i monitoring', desc: 'CI/CD, repozytoria, metryki', test: (c) => c.has('devops') },
  { k: 'db', label: 'Bazy danych', desc: 'MySQL, Redis, PostgreSQL, Elasticsearch', test: (c, s) => c.has('database') || ['mysql', 'redis', 'postgresql', 'mongodb', 'ms-sql-s', 'oracle', 'elasticsearch', 'memcache'].includes(s) },
  { k: 'remote', label: 'Zdalny dostęp', desc: 'SSH, RDP, Telnet, VNC', test: (c, s) => ['ssh', 'ms-wbt-server', 'telnet', 'vnc', 'rdp'].includes(s) },
  { k: 'files', label: 'Transfer plików', desc: 'FTP, SMB, NFS', test: (c, s) => ['ftp', 'ftps', 'microsoft-ds', 'netbios-ssn', 'nfs', 'rsync', 'tftp'].includes(s) },
  { k: 'webapp', label: 'Aplikacje webowe', desc: 'frameworki i serwery aplikacyjne', test: (c) => c.has('framework') || c.has('appserver') || c.has('language') },
  { k: 'web', label: 'Serwery WWW', desc: 'strony bez rozpoznanej aplikacji', test: (c, s, o) => o.http_status > 0 || s.startsWith('http') || s === 'ssl' },
  { k: 'other', label: 'Inne usługi', desc: 'pozostałe otwarte porty', test: () => true },
];
export function svcCategory(o) {
  const cats = new Set(parseArr(o.techs).map((t) => t.category));
  const s = (o.service || '').toLowerCase();
  return SVC_CATEGORIES.find((c) => c.test(cats, s, o)).k;
}
const top = (m, n) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([k]) => k);
export function categoryGroups(rows) {
  const g = new Map();
  for (const o of rows) {
    const k = svcCategory(o);
    if (!g.has(k)) g.set(k, { k, hosts: new Set(), count: 0, http: 0, tls: 0, techs: new Map(), flags: new Map(), svcs: new Map(), max: 0 });
    const x = g.get(k);
    x.hosts.add(o.ip); x.count++;
    if (o.http_status > 0) x.http++;
    if (o.tls) x.tls++;
    x.max = Math.max(x.max, o.interest || 0);
    for (const t of parseArr(o.techs)) if (t.category !== 'server' || k === 'web') x.techs.set(t.name, (x.techs.get(t.name) || 0) + 1);
    for (const f of parseArr(o.flags)) x.flags.set(f, (x.flags.get(f) || 0) + 1);
    const sp = `${o.service || '?'}`;
    x.svcs.set(sp, (x.svcs.get(sp) || 0) + 1);
  }
  return SVC_CATEGORIES.filter((c) => g.has(c.k)).map((c) => {
    const x = g.get(c.k);
    return { ...c, hosts: x.hosts.size, count: x.count, http: x.http, tls: x.tls, max: x.max, techs: top(x.techs, 4), flags: top(x.flags, 3), svcs: top(x.svcs, 4) };
  });
}
export function CategoryTable({ rows, onOpen }) {
  const groups = categoryGroups(rows);
  if (!groups.length) return <Empty>Brak usług dla wybranych filtrów.</Empty>;
  return (
    <table className="w-full">
      <thead><tr><th className="th">Hosty</th><th className="th">Kategoria</th><th className="th">Usługi</th><th className="th">HTTP / HTTPS</th><th className="th">Technologie</th><th className="th">Flagi</th><th className="th">Klasa (max)</th></tr></thead>
      <tbody>
        {groups.map((g) => (
          <tr key={g.k} onClick={() => onOpen(g)} className="cursor-pointer border-b hover:bg-white/[.025]">
            <td className="td font-mono text-[22px] font-extrabold text-sky-300">{num(g.hosts)}</td>
            <td className="td"><div className="text-[15px] font-extrabold text-slate-100">{g.label}</div><div className="text-[11px] text-slate-500">{g.desc}</div></td>
            <td className="td font-mono"><div className="text-[15px] font-semibold text-slate-100">{num(g.count)}</div><div className="text-[11px] text-slate-500">{g.svcs.join(', ')}</div></td>
            <td className="td whitespace-nowrap font-mono text-[12px] text-slate-300">{g.http ? <><div className="text-[15px] font-semibold text-slate-100">{num(g.http)}</div><div className="text-[11px] text-slate-500">w tym TLS: {num(g.tls)}</div></> : <span className="text-slate-600">–</span>}</td>
            <td className="td"><div className="flex max-w-[300px] flex-wrap gap-1">{g.techs.length ? g.techs.map((t) => <Badge key={t} tone="blue">{t}</Badge>) : <span className="text-[11px] text-slate-600">–</span>}</div></td>
            <td className="td"><div className="flex max-w-[280px] flex-wrap gap-1">{g.flags.length ? g.flags.map((f) => <Flag key={f} f={f} />) : <span className="text-[11px] text-slate-600">bez flag</span>}</div></td>
            <td className="td"><Interest v={g.max} wide /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
