import { Component, useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { NavLink, Navigate, Route, Routes, useNavigate, useLocation as useLoc } from 'react-router-dom';
import { LayoutDashboard, Crosshair, Radar, Server, Network, GitCompare, Fingerprint, ArrowLeftRight, Shield, LogOut, Lock, Loader2, Cpu, Scale, Sun, Moon, Search, ChevronsUpDown, Plus, PanelLeft, ChevronRight } from 'lucide-react';
import { api, AuthCtx, ToastProvider } from './lib.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Targets from './pages/Targets.jsx';
import Scans, { ScanDetail } from './pages/Scans.jsx';
import Inventory from './pages/Inventory.jsx';
import Hosts from './pages/Hosts.jsx';
import Technologies from './pages/Technologies.jsx';
import Diff from './pages/Diff.jsx';
import Signatures from './pages/Signatures.jsx';
import Rules from './pages/Rules.jsx';
import DataPage from './pages/DataPage.jsx';
import Admin from './pages/Admin.jsx';
import Tour, { tourSeen } from './Tour.jsx';

// nawigacja w sekcjach (układ wg wzoru docs/-15.jpg)
const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, perm: 'results.read', end: true, sec: '' },
  { to: '/diff', label: 'Zmiany', icon: GitCompare, perm: 'results.read', sec: '' },
  { to: '/technologies', label: 'Technologie', icon: Cpu, perm: 'results.read', sec: '' },
  { to: '/targets', label: 'Cele', icon: Crosshair, perm: 'targets.read', sec: 'Skanowanie' },
  { to: '/scans', label: 'Skany', icon: Radar, perm: 'scans.read', sec: 'Skanowanie' },
  { to: '/hosts', label: 'Hosty', icon: Network, perm: 'results.read', sec: 'Skanowanie' },
  { to: '/inventory', label: 'Usługi', icon: Server, perm: 'results.read', sec: 'Skanowanie' },
  { to: '/signatures', label: 'Sygnatury', icon: Fingerprint, perm: 'signatures.read', sec: 'Wykrywanie' },
  { to: '/rules', label: 'Reguły klasy', icon: Scale, perm: 'signatures.read', sec: 'Wykrywanie' },
  { to: '/data', label: 'Import / eksport', icon: ArrowLeftRight, perm: 'data.export', sec: 'System' },
  { to: '/admin', label: 'Administracja', icon: Shield, perm: 'users.manage', sec: 'System' },
];

function Login({ onLogin }) {
  const [u, setU] = useState('');
  const [p, setP] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setErr('');
    try {
      const r = await api('/auth/login', { method: 'POST', body: { username: u, password: p } });
      onLogin(r.user);
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="relative flex min-h-full items-center justify-center overflow-hidden p-6">
      <div className="pointer-events-none absolute inset-0" style={{ background: 'radial-gradient(800px 420px at 50% 15%, rgba(108,182,255,.12), transparent 70%)' }} />
      <form onSubmit={submit} className="card relative w-full max-w-sm p-7">
        <div className="mb-6 flex items-center gap-3">
          <Logo size={44} />
          <div>
            <div className="text-[17px] font-extrabold tracking-wide text-white">Mo<span className="text-accent">Net</span></div>
            <div className="text-xs text-slate-500">Monitoring powierzchni ataku sieci</div>
          </div>
        </div>
        <label className="label">Login</label>
        <input className="input mb-3" value={u} onChange={(e) => setU(e.target.value)} autoFocus autoComplete="username" />
        <label className="label">Hasło</label>
        <input className="input mb-4" type="password" value={p} onChange={(e) => setP(e.target.value)} autoComplete="current-password" />
        {err && <div className="mb-3 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">{err}</div>}
        <button className="btn-primary w-full justify-center py-2.5 text-sm" disabled={busy}>{busy ? <Loader2 size={16} className="animate-spin" /> : <Lock size={15} />} Zaloguj</button>
        <p className="mt-4 text-center text-[11px] text-slate-600">Dostęp wg ról: Administrator · Operator · Analityk · Obserwator</p>
      </form>
    </div>
  );
}

// Bezpiecznik: błąd w jednej stronie nie wywraca całej aplikacji (zamiast czarnego ekranu komunikat).
class PageBoundary extends Component {
  constructor(p) { super(p); this.state = { err: null }; }
  static getDerivedStateFromError(err) { return { err }; }
  componentDidUpdate(prev) { if (prev.resetKey !== this.props.resetKey && this.state.err) this.setState({ err: null }); }
  render() {
    if (this.state.err) {
      return (
        <div className="card p-6">
          <div className="mb-2 text-sm font-semibold text-rose-300">Ta strona napotkała błąd wyświetlania</div>
          <div className="mb-4 font-mono text-[12px] text-slate-400">{String(this.state.err?.message || this.state.err)}</div>
          <button className="btn-ghost" onClick={() => this.setState({ err: null })}>Spróbuj ponownie</button>
        </div>
      );
    }
    return this.props.children;
  }
}

function Routed({ children }) {
  const loc = useLocation();
  return <PageBoundary resetKey={loc.pathname + loc.search}>{children}</PageBoundary>;
}

export default function App() {
  const [user, setUser] = useState(undefined);
  useEffect(() => {
    api('/me').then(setUser).catch(() => setUser(null));
    const out = () => setUser(null);
    window.addEventListener('asi-logout', out);
    return () => window.removeEventListener('asi-logout', out);
  }, []);
  // liczba nowych technologii do zaklasyfikowania (czerwony wykrzyknik przy „Technologie”)
  const [techNew, setTechNew] = useState(0);
  const [tour, setTour] = useState(false);
  useEffect(() => { if (user && (!tourSeen(user.username) || new URLSearchParams(window.location.search).get('tour') === '1')) { const t = setTimeout(() => setTour(true), 800); return () => clearTimeout(t); } return undefined; }, [user]);
  const [railWide, setRailWide] = useState(() => { try { return localStorage.getItem('monet-rail') === 'wide'; } catch { return false; } });
  useEffect(() => {
    if (!user) return undefined;
    const load = () => api('/technologies/review').then((d) => setTechNew(d.count || 0)).catch(() => {});
    load();
    const t = setInterval(load, 30000);
    window.addEventListener('monet-tech-review', load);
    return () => { clearInterval(t); window.removeEventListener('monet-tech-review', load); };
  }, [user]);
  if (user === undefined) return <div className="flex h-full items-center justify-center text-slate-500"><Loader2 className="animate-spin" /></div>;
  if (!user) return <ToastProvider><Login onLogin={setUser} /></ToastProvider>;
  const can = (p) => user.permissions.includes(p);
  const logout = async () => {
    await api('/auth/logout', { method: 'POST' }).catch(() => {});
    setUser(null);
  };
  return (
    <AuthCtx.Provider value={{ user }}>
      <ToastProvider>
        <div className="flex h-full">
          <Rail user={user} can={can} techNew={techNew} logout={logout} wide={railWide} onTour={() => setTour(true)} />
          <Tour user={user.username} open={tour} onClose={() => setTour(false)} />
          <main className="main-panel min-w-0 flex-1 overflow-y-auto">
            <TopBar2 can={can} onToggle={() => { const v = !railWide; setRailWide(v); try { localStorage.setItem('monet-rail', v ? 'wide' : 'narrow'); } catch { /* brak pamięci */ } }} />
            <div className="mx-auto max-w-[1520px] px-6 pb-8 pt-5">
              <Routed><Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/targets" element={<Targets />} />
                <Route path="/scans" element={<Scans />} />
                <Route path="/scans/:id" element={<ScanDetail />} />
                <Route path="/inventory" element={<Inventory />} />
                <Route path="/hosts" element={<Hosts />} />
                <Route path="/technologies" element={<Technologies />} />
                <Route path="/diff" element={<Diff />} />
                <Route path="/signatures" element={<Signatures />} />
                <Route path="/rules" element={<Rules />} />
                <Route path="/data" element={<DataPage />} />
                <Route path="/admin" element={<Admin />} />
                <Route path="*" element={<Navigate to="/" />} />
              </Routes></Routed>
            </div>
          </main>
        </div>
      </ToastProvider>
    </AuthCtx.Provider>
  );
}

// przełącznik motywu: ciemny (domyślny, czysta czerń) / jasny (kremowy, czarne obramowania); zapamiętany w przeglądarce
export function applyTheme(t) {
  document.documentElement.classList.toggle('light', t === 'light');
  try { localStorage.setItem('monet-theme', t); } catch { /* tryb prywatny: tylko na tę sesję */ }
}
function ThemeToggle() {
  const [t, setT] = useState(() => (document.documentElement.classList.contains('light') ? 'light' : 'dark'));
  const flip = () => { const n = t === 'light' ? 'dark' : 'light'; applyTheme(n); setT(n); };
  return (
    <button onClick={flip} className="btn-ghost mb-2 w-full justify-center" title="Przełącz motyw">
      {t === 'light' ? <><Moon size={12} /> Motyw ciemny</> : <><Sun size={12} /> Motyw jasny</>}
    </button>
  );
}

// Układ wg docs/„ui finalne.jpg”: wąski pasek ikon (logo, „+”, sekcje, konto) + górny pasek (okruszki, stan, szukaj).
function Rail({ user, can, techNew, logout, wide, onTour }) {
  const [menu, setMenu] = useState(false);
  const nav = useNavigate();
  const items = NAV.filter((n) => can(n.perm));
  const groups = ['', 'Skanowanie', 'Wykrywanie', 'System'].map((g) => items.filter((n) => n.sec === g)).filter((g) => g.length);
  return (
    <aside className={`rail sidebar ${wide ? 'wide' : ''}`}>
      <div className="rail-logo" title="MoNet"><Logo size={34} />{wide && <span className="rail-brand">Mo<span className="text-accent">Net</span></span>}</div>
      {can('configs.create') && <button className="rail-plus" title="Nowa konfiguracja skanu" aria-label="Nowa konfiguracja skanu" onClick={() => nav('/scans?tab=configs&new=1')}><Plus size={20} strokeWidth={1.75} />{wide && <span className="rail-label">Nowy skan</span>}</button>}
      <nav className="rail-nav">
        {groups.map((g, i) => (
          <div key={i} className="rail-group">
            {wide && g[0].sec && <div className="rail-sec">{g[0].sec}</div>}
            {g.map((n) => (
              <NavLink key={n.to} to={n.to} end={n.end} className={({ isActive }) => `rail-item ${isActive ? 'active' : ''}`} title={n.label} aria-label={n.label}>
                <n.icon size={19} strokeWidth={1.6} />
                {wide && <span className="rail-label">{n.label}</span>}
                {n.to === '/technologies' && techNew > 0 && <span className="rail-badge keep-round" title={`${techNew} nowych technologii`}>!</span>}
                {!wide && <span className="rail-tip">{n.label}</span>}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      <div className="relative" onBlur={(e) => { if (!e.currentTarget.contains(e.relatedTarget)) setMenu(false); }}>
        {menu && (
          <div className="tip absolute bottom-0 left-full z-50 ml-3 flex w-52 flex-col gap-1 p-2">
            <div className="px-2 pb-1 pt-1"><div className="text-[13px] font-semibold text-white">{user.username}</div><div className="text-[11px] text-slate-500">{user.role}</div></div>
            <ThemeToggle />
            <button onClick={() => { setMenu(false); onTour(); }} className="btn-ghost w-full justify-center">Pokaż samouczek</button>
            <PasswordChange />
            <button onClick={logout} className="btn-ghost w-full justify-center"><LogOut size={12} /> Wyloguj</button>
          </div>
        )}
        <button onClick={() => setMenu(!menu)} className="rail-me" aria-haspopup="menu" aria-expanded={menu} title={`${user.username} · ${user.role}`}>
          <span className="rail-avatar keep-round">{user.username.charAt(0)}</span>
          {wide && <span className="min-w-0 text-left leading-tight"><span className="block truncate text-[13.5px] font-semibold text-white">{user.username}</span><span className="block truncate text-[11.5px] text-slate-500">{user.role}</span></span>}
        </button>
      </div>
    </aside>
  );
}

function TopBar2({ can, onToggle }) {
  const loc = useLoc();
  const nav = useNavigate();
  const [running, setRunning] = useState(0);
  useEffect(() => {
    const load = () => api('/scans?limit=20').then((l) => setRunning((l || []).filter((x) => x.status === 'running').length)).catch(() => {});
    load(); const t = setInterval(load, 15000); return () => clearInterval(t);
  }, []);
  const cur = [...NAV].sort((a, b) => b.to.length - a.to.length).find((n) => (n.end ? loc.pathname === n.to : loc.pathname.startsWith(n.to))) || NAV[0];
  return (
    <div className="topbar">
      <button className="topbar-icon" onClick={onToggle} title="Rozwiń / zwiń pasek z podpisami" aria-label="Rozwiń lub zwiń pasek nawigacji"><PanelLeft size={18} strokeWidth={1.6} /></button>
      <nav className="crumbs" aria-label="Okruszki">
        <span className="crumb-dim">{cur.sec || 'MoNet'}</span>
        <ChevronRight size={14} className="crumb-sep" />
        <span className="crumb-cur">{cur.label}</span>
        <span className={`state-pill ${running ? 'run' : 'ok'}`}>{running ? `Skan w toku · ${running}` : 'Gotowy'}</span>
      </nav>
    </div>
  );
}

function Logo({ size = 32 }) {
  // MoNet: grube „MN” obok siebie, przekreślone przez środek białą linią (monitoring + network)
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none">
      <rect x="0.5" y="0.5" width="39" height="39" rx="6" fill="none" stroke="rgba(108,182,255,.55)" />
      <text x="20" y="27.5" textAnchor="middle" fontFamily="Inter, Arial, sans-serif" fontWeight="900" fontSize="19" letterSpacing="-1" fill="var(--logo-fg)">MN</text>
      <rect x="4" y="19.4" width="32" height="2.2" rx="1.1" fill="var(--logo-fg)" />
    </svg>
  );
}

function TopBar() {
  const [now, setNow] = useState(new Date());
  useEffect(() => { const t = setInterval(() => setNow(new Date()), 30000); return () => clearInterval(t); }, []);
  return (
    <div className="sticky top-0 z-20 flex h-8 items-center justify-between bg-black/70 px-6 text-[10px] uppercase tracking-[.2em] text-slate-500 backdrop-blur" style={{ borderBottom: '1px solid rgba(108,182,255,.18)', boxShadow: '0 1px 0 rgba(108,182,255,.06)' }}>
      <span>MoNet · discovery scan · CBI AGH</span>
      <span className="font-mono normal-case tracking-normal text-slate-400">{now.toLocaleDateString('pl-PL')} {now.toLocaleTimeString('pl-PL', { hour: '2-digit', minute: '2-digit' })}</span>
    </div>
  );
}

// ikonka „i” w kółku obok tytułu; opis strony pokazuje się w chmurce po najechaniu myszą (lub fokusie klawiaturą)
export function InfoTip({ text }) {
  return (
    <span className="group relative inline-flex">
      <span tabIndex={0} aria-label={text}
        className="flex h-[18px] w-[18px] cursor-help items-center justify-center rounded-full border border-accent/50 font-display text-[11px] font-extrabold leading-none text-accent outline-none transition hover:bg-accent/10 hover:shadow-[0_0_10px_rgba(108,182,255,.45)] focus-visible:ring-1 focus-visible:ring-accent">i</span>
      <span role="tooltip"
        className="tip pointer-events-none absolute -left-2 top-full z-50 mt-2 w-max max-w-[420px] rounded-xl px-3 py-2 text-[12px] font-normal leading-snug tracking-normal text-slate-200 opacity-0 transition duration-150 group-hover:opacity-100 group-focus-within:opacity-100"
        style={{ background: 'rgba(10,16,30,.96)', border: '1px solid rgba(140,190,255,.35)', boxShadow: '0 10px 30px -10px rgba(0,0,0,.9), 0 0 18px -8px rgba(80,140,255,.7)' }}>
        {text}
      </span>
    </span>
  );
}

function PasswordChange() {
  const [open, setOpen] = useState(false);
  const [f, setF] = useState({ current: '', new: '' });
  const [msg, setMsg] = useState('');
  if (!open) return <button onClick={() => setOpen(true)} className="btn-ghost mb-2 w-full justify-center"><Lock size={12} /> Zmień hasło</button>;
  const save = async () => {
    try { await api('/me/password', { method: 'POST', body: f }); setMsg('Zmieniono. Inne sesje wylogowane.'); setF({ current: '', new: '' }); } catch (e) { setMsg(e.message); }
  };
  return (
    <div className="mb-2 flex flex-col gap-1.5">
      <input className="input" type="password" placeholder="obecne hasło" autoComplete="current-password" value={f.current} onChange={(e) => setF({ ...f, current: e.target.value })} />
      <input className="input" type="password" placeholder="nowe hasło (min. 10 znaków)" autoComplete="new-password" value={f.new} onChange={(e) => setF({ ...f, new: e.target.value })} />
      <button className="btn-primary justify-center" disabled={!f.current || f.new.length < 10} onClick={save}>Zapisz hasło</button>
      {msg && <div className="text-[11px] text-slate-400">{msg}</div>}
    </div>
  );
}

export function PageHeader({ title, sub, children }) {
  return (
    <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
      <h1 className="flex items-center gap-2.5 font-display text-[19px] font-extrabold tracking-[.02em] text-white">{title}{sub && <InfoTip text={sub} />}</h1>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
    </div>
  );
}
