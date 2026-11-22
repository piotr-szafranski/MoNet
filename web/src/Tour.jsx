// Samouczek dla nowego użytkownika (jury): 8 kroków, podświetlenie elementu + dymek. Pokazuje się przy pierwszym
// logowaniu danego użytkownika (zapamiętane w przeglądarce), ponownie z menu konta → „Pokaż samouczek”.
import { useEffect, useLayoutEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

const STEPS = [
  { title: 'MoNet: monitoring powierzchni ataku sieci', text: 'Cyklicznie skanuje duże sieci (ponad 10 000 IP), rozpoznaje usługi i technologie i pokazuje, co się zmieniło. Pokażemy to w 8 krokach.' },
  { route: '/', sel: '.verdict', title: 'Stan sieci w 3 sekundy', text: 'Jedno zdanie mówi, co wymaga uwagi, a cztery liczby to uzasadniają. Przycisk po prawej prowadzi prosto do najważniejszych pozycji.' },
  { route: '/', sel: '.rail-plus', title: 'Nowy skan', text: 'Kreator krok po kroku: cele (IP, CIDR, domeny albo plik CSV/JSON), porty podawane przed skanem, tempo, okno nocne z wznowieniem i doskaner w dzień.' },
  { route: '/scans', sel: '.seg', title: 'Skan pod kontrolą', text: 'Historia i konfiguracje skanów. Postęp na żywo, podgrupy dobierane do tempa, limit pakietów i zapytań HTTP. Skan, który nie zmieści się w oknie, wznawia się w kolejnym od miejsca przerwania.' },
  { route: '/inventory', sel: 'main section.card > header', title: 'Co działa w sieci', text: 'Usługi pogrupowane według rozpoznania (IoT, panele, CMS, bazy, staging…). Kliknięcie kategorii pokazuje usługi, a kliknięcie usługi szczegóły HTTP: tytuł, nagłówki, ciasteczka, TLS i przekierowania.' },
  { route: '/inventory', sel: 'a[href="/signatures"]', title: 'Własne sygnatury bez kodu', text: 'W szczegółach nierozpoznanej usługi przycisk „Naucz system” tworzy sygnaturę w dwóch kliknięciach; kolejny skan rozpozna ją w całej sieci. Sygnatury można też pisać i importować (nuclei, Wappalyzer, CSV) w zakładce Sygnatury.' },
  { route: '/diff', sel: 'main .grid', title: 'Co się zmieniło', text: 'Porównanie dwóch skanów: usługi nowe, znikające, powracające i zmienione, pole po polu. Hosty widoczne tylko w dzień są w zakładce Hosty → Niestabilne.' },
  { route: '/data', sel: 'a[href="/data"]', title: 'Integracje i bezpieczeństwo', text: 'Eksport JSON/CSV i automatyczny import do DefectDojo. Cztery role z uprawnieniami sprawdzanymi po stronie serwera, szyfrowanie danych i dziennik logów w Administracji. Gotowe, możesz zaczynać.' },
];

const key = (u) => `monet-tour-done:${u}`;
export const tourSeen = (u) => { try { return localStorage.getItem(key(u)) === '1'; } catch { return true; } };

export default function Tour({ user, open, onClose }) {
  const [i, setI] = useState(0);
  const [rect, setRect] = useState(null);
  const nav = useNavigate();
  const st = STEPS[i];
  const finish = () => { try { localStorage.setItem(key(user), '1'); } catch { /* brak pamięci */ } setI(0); onClose(); };

  useEffect(() => { if (open && st.route && window.location.pathname !== st.route) nav(st.route); }, [open, i]); // eslint-disable-line
  // znajdź element (strona może się jeszcze ładować) i śledź jego położenie
  useLayoutEffect(() => {
    if (!open) return undefined;
    if (!st.sel) { setRect(null); return undefined; }
    let el = null; let tries = 0; let raf; let prev = null;
    const measure = () => {
      // czekamy, aż router pokaże właściwą stronę (inaczej łapiemy element ze strony poprzedniego kroku)
      if (st.route && window.location.pathname !== st.route) { if (tries++ < 60) raf = setTimeout(measure, 100); return; }
      if (el && !el.isConnected) el = null; // element zniknął po przeładowaniu widoku
      el = el || document.querySelector(st.sel);
      if (el && el.getBoundingClientRect().width === 0) el = null; // jeszcze nie wyrenderowany
      if (el) {
        const r = el.getBoundingClientRect();
        if (r.top < 0 || r.bottom > window.innerHeight) el.scrollIntoView({ block: 'nearest' });
        const n = el.getBoundingClientRect();
        const same = prev && Math.abs(prev.left - n.left) < 1 && Math.abs(prev.top - n.top) < 1 && Math.abs(prev.width - n.width) < 1 && Math.abs(prev.height - n.height) < 1;
        prev = n;
        if (!same) { raf = setTimeout(measure, 120); return; } // czekamy, aż układ się ustabilizuje
        setRect((o) => (o && Math.abs(o.x - n.left) < 1 && Math.abs(o.y - n.top) < 1 && Math.abs(o.w - n.width) < 1 && Math.abs(o.h - n.height) < 1 ? o : { x: n.left, y: n.top, w: n.width, h: n.height }));
      } else if (tries++ < 60) { raf = setTimeout(measure, 100); }
    };
    measure();
    const on = () => measure();
    const tick = setInterval(on, 400); // układ strony zmienia się, gdy dociągają się dane
    window.addEventListener('resize', on);
    window.addEventListener('scroll', on, true);
    return () => { clearTimeout(raf); clearInterval(tick); window.removeEventListener('resize', on); window.removeEventListener('scroll', on, true); };
  }, [open, i]); // eslint-disable-line
  useEffect(() => {
    if (!open) return undefined;
    const k = (e) => {
      if (e.key === 'Escape') finish();
      if (e.key === 'ArrowRight') setI((v) => Math.min(STEPS.length - 1, v + 1));
      if (e.key === 'ArrowLeft') setI((v) => Math.max(0, v - 1));
    };
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, [open]); // eslint-disable-line
  if (!open) return null;

  const pad = 8;
  const W = 380;
  const vw = window.innerWidth, vh = window.innerHeight;
  // krok bez celu = „otwór” zerowej wielkości na środku ekranu (pełne przyciemnienie), żeby ramka mogła płynnie
  // przejechać z/do środka zamiast skakać z rogu
  const hole = rect ? { x: rect.x - pad, y: rect.y - pad, w: rect.w + pad * 2, h: rect.h + pad * 2 } : { x: vw / 2, y: vh / 2, w: 0, h: 0 };
  let pos = { left: (vw - W) / 2, top: vh / 2 - 130 };
  if (rect) {
    const below = rect.y + rect.h + pad + 12;
    const right = rect.x + rect.w + pad + 14;
    if (rect.w < 120 && right + W < vw) pos = { left: right, top: Math.max(16, rect.y - 8) };
    else if (below + 220 < vh) pos = { left: Math.min(Math.max(16, rect.x), vw - W - 16), top: below };
    else pos = { left: Math.min(Math.max(16, rect.x), vw - W - 16), top: Math.max(16, rect.y - 230) };
    pos.top = Math.min(pos.top, vh - 250);
  }
  return (
    <div className="tour" role="dialog" aria-modal="true" aria-label="Samouczek">
      <div className={`tour-hole ${rect ? '' : 'empty'}`} style={{ transform: `translate(${hole.x}px, ${hole.y}px)`, width: hole.w, height: hole.h }} />
      <div className="tour-card" style={{ width: W, transform: `translate(${pos.left}px, ${pos.top}px)` }}>
        <div key={i} className="tour-body">
          <div className="tour-count">{i + 1} / {STEPS.length}</div>
          <h3 className="tour-title">{st.title}</h3>
          <p className="tour-text">{st.text}</p>
        </div>
        <div className="tour-dots">{STEPS.map((_, k) => <button key={k} className={`keep-round ${k === i ? 'on' : ''}`} aria-label={`Krok ${k + 1}`} onClick={() => setI(k)} />)}</div>
        <div className="tour-actions">
          <button className="btn-ghost mr-auto" onClick={finish}>Pomiń</button>
          {i > 0 && <button className="btn-ghost" onClick={() => setI(i - 1)}>← Wstecz</button>}
          {i < STEPS.length - 1
            ? <button className="btn-run" onClick={() => setI(i + 1)}>Dalej →</button>
            : <button className="btn-run" onClick={finish}>Zaczynamy</button>}
        </div>
      </div>
    </div>
  );
}
