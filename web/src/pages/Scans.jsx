import { useEffect, useState } from 'react';
import { useNavigate, useParams, Link } from 'react-router-dom';
import { Radar, Plus, Play, Pencil, Trash2, Square, RotateCcw, Timer, Download, CalendarClock, Gauge, Sparkles, ChevronLeft, Search, Save, Send, History, AlertTriangle, MoreVertical } from 'lucide-react';
import { api, useApi, useCan, useToast, Card, Badge, State, Spinner, ErrorBox, Empty, Modal, Field, TagInput, Toggle, Progress, BigProgress, HistoryBar, Bars, fmtDate, fmtDur, num, download, useDebounced, flagLabel, CategoryTable, svcCategory, SVC_CATEGORIES } from '../lib.jsx';
import { PageHeader, InfoTip } from '../App.jsx';
import { ServicesTable, ServiceDrawer } from './Inventory.jsx';

const DAYS = ['pn', 'wt', 'śr', 'cz', 'pt', 'so', 'nd'];
const EMPTY = { name: '', target_tags: [], ports: '', discovery_ports: '22,80,443,3389,8080', rate: 1000, http_rps: 30, workers: 4, chunk_target_sec: 60,
  host_timeout_sec: 120, retries: 1, retry_unstable: true, http_probe: true, version_intensity: 5, gone_after: 3, excludes: '',
  sched_enabled: false, sched_every_min: 1440, win_start: '22:00', win_end: '06:00', win_days: '1234567',
  retry_enabled: false, retry_win_start: '07:00', retry_win_end: '21:00', retry_batch: 1, retry_every_min: 10, retry_pause_sec: 15,
  dojo_auto: false, dojo_min_interest: 20, auto_add_ports: false };

function PortsField({ value, onChange }) {
  const [presets, setPresets] = useState({});
  const [v, setV] = useState(null);
  const dv = useDebounced(value, 250);
  useEffect(() => { api('/ports/presets').then(setPresets).catch(() => {}); }, []);
  useEffect(() => { api('/ports/validate', { method: 'POST', body: { ports: dv } }).then(setV).catch(() => {}); }, [dv]);
  const labels = { web: 'porty WWW', top100: 'top 100', infra: 'infrastruktura', discover: 'tylko discovery' };
  return (
    <Field label="Porty do skanowania (podawane przed skanem)" hint="Lista i zakresy: 22,80,443,8000-8100. Prefiksy T: / U: dla TCP / UDP (UDP wymaga uprawnień root). Puste = tylko wykrywanie hostów.">
      <textarea className="input font-mono" rows={2} value={value} onChange={(e) => onChange(e.target.value)} placeholder="np. 21,22,80,443,8080,8443" />
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        {Object.entries(presets).map(([k, p]) => (
          <button type="button" key={k} className="btn-ghost py-1" onClick={() => onChange(p.ports)}>{labels[k] || k} <span className="text-slate-500">({p.count})</span></button>
        ))}
        {v && (v.valid
          ? <Badge tone="green">{v.discovery_only ? 'tylko discovery' : `TCP ${v.tcp} · UDP ${v.udp}`}</Badge>
          : <Badge tone="red">{v.error}</Badge>)}
      </div>
    </Field>
  );
}

// „Szacowany czas: GG:MM” liczony na bieżąco z celów reguły i tempa z historii skanów (tylko informacja)
const fmtHM = (sec) => { const m = Math.max(0, Math.round(sec / 60)); return `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`; };
function EstimateInfo({ c }) {
  const [e, setE] = useState(null);
  const key = JSON.stringify([c.id || 0, c.target_tags, c.workers]);
  useEffect(() => {
    const t = setTimeout(() => {
      api('/configs/estimate', { method: 'POST', body: { id: c.id || 0, target_tags: c.target_tags, workers: Number(c.workers) || 4 } }).then(setE).catch(() => setE(null));
    }, 400);
    return () => clearTimeout(t);
  }, [key]); // eslint-disable-line
  return (
    <div className="flex items-center justify-between gap-3 rounded-xl border border-white/[.08] px-4 py-3">
      <span className="flex items-center gap-2 text-[13px] font-bold text-white"><Timer size={14} className="text-accent" /> Szacowany czas skanowania</span>
      <span className="font-mono text-[20px] font-bold text-white">{e ? fmtHM(e.estimated_sec) : '--:--'}</span>
    </div>
  );
}

// kompaktowy szacowany czas obok przycisku „Zapisz”
function EstimateInline({ c }) {
  const [e, setE] = useState(null);
  const key = JSON.stringify([c.id || 0, c.target_tags, c.workers]);
  useEffect(() => {
    const t = setTimeout(() => {
      api('/configs/estimate', { method: 'POST', body: { id: c.id || 0, target_tags: c.target_tags, workers: Number(c.workers) || 4 } }).then(setE).catch(() => setE(null));
    }, 300);
    return () => clearTimeout(t);
  }, [key]); // eslint-disable-line
  return (
    <span className="flex items-center gap-2 text-[13px] text-slate-400" title="szacunek z liczby adresów w celach i tempa z historii skanów">
      <Timer size={14} className="text-accent" /> Szacowany czas: <b className="font-mono text-[15px] font-semibold text-white">{e ? fmtHM(e.estimated_sec) : '--:--'}</b>
    </span>
  );
}

// menu „⋮” w prawym górnym rogu kafelka reguły
function TileMenu({ items }) {
  const [open, setOpen] = useState(false);
  return (
    <span className="relative inline-block" onBlur={(e) => { if (!e.currentTarget.contains(e.relatedTarget)) setOpen(false); }}>
      <button className="flex h-7 w-7 items-center justify-center rounded-full border border-white/10 text-slate-300 transition hover:border-accent/50 hover:text-white" onClick={() => setOpen(!open)} aria-haspopup="menu" aria-expanded={open} title="Więcej">
        <MoreVertical size={15} />
      </button>
      {open && (
        <span role="menu" className="tip absolute right-0 top-full z-50 mt-1.5 flex w-40 flex-col overflow-hidden rounded-xl py-1"
          style={{ background: 'rgba(10,16,30,.97)', border: '1px solid rgba(140,190,255,.35)', boxShadow: '0 10px 30px -10px rgba(0,0,0,.9)' }}>
          {items.map((it) => (
            <button key={it.label} role="menuitem" onClick={() => { setOpen(false); it.onClick(); }}
              className={`flex items-center gap-2 px-3 py-2 text-left text-[12.5px] hover:bg-white/[.06] ${it.danger ? 'text-rose-300' : 'text-slate-200'}`}>
              <it.icon size={13} /> {it.label}
            </button>
          ))}
        </span>
      )}
    </span>
  );
}

// przełącznik w stylu macOS: suwak w pigułce, podpis zmienia się z „Ręczny” na „Automatyczny”
function MacSwitch({ on, onChange, onLabel, offLabel }) {
  return (
    <button type="button" role="switch" aria-checked={on} onClick={() => onChange(!on)} className="group flex items-center gap-3">
      <span className={`w-28 text-right text-[13px] font-extrabold tracking-wide transition-colors ${on ? 'text-emerald-300' : 'text-slate-400'}`}>{on ? onLabel : offLabel}</span>
      <span className={`keep-round relative inline-flex h-[30px] w-[52px] shrink-0 items-center rounded-full border transition-colors duration-200 ${on ? 'mac-on border-emerald-300/60 bg-[#34c759]' : 'border-white/15 bg-white/[.12]'}`}>
        <span className={`keep-round absolute left-[2px] h-[26px] w-[26px] rounded-full bg-white shadow-[0_2px_4px_rgba(0,0,0,.35)] transition-transform duration-200 ease-out ${on ? 'translate-x-[22px]' : 'translate-x-0'}`} />
      </span>
    </button>
  );
}

function ConfigForm({ initial, onClose, onSaved }) {
  const [c, setC] = useState({ ...EMPTY, ...initial });
  const [unit, setUnit] = useState((initial.retry_pause_sec ?? 15) % 60 === 0 ? 'min' : 's');
  const [err, setErr] = useState('');
  const toast = useToast();
  // kreator krok po kroku (domyślnie) albo dawny widok pełny; wybór zapamiętany w przeglądarce
  const [full, setFull] = useState(() => { try { return localStorage.getItem('monet-cfg-view') === 'full'; } catch { return false; } });
  const [step, setStep] = useState(0);
  const setView = (v) => { setFull(v); try { localStorage.setItem('monet-cfg-view', v ? 'full' : 'steps'); } catch { /* brak pamięci */ } };
  const STEPS = ['Podstawy', 'Porty', 'Intensywność', 'Harmonogram i doskaner', 'DefectDojo i zapis'];
  const show = (n) => full || step === n;
  const stepOk = (n) => (n === 0 ? !!c.name.trim() : true);
  const last = STEPS.length - 1;
  const set = (k) => (e) => setC({ ...c, [k]: e?.target ? (e.target.type === 'number' ? Number(e.target.value) : e.target.value) : e });
  const save = async () => {
    setErr('');
    try {
      const r = await api(c.id ? `/configs/${c.id}` : '/configs', { method: c.id ? 'PUT' : 'POST', body: c });
      if (r.policy_clamped?.length) toast(`Zapisano z limitami administratora (Polityka skanera): ${r.policy_clamped.join(', ')}`, 'err');
      onSaved(r);
    } catch (e) { setErr(e.message); }
  };
  const toggleDay = (i) => {
    const d = String(i + 1);
    setC({ ...c, win_days: c.win_days.includes(d) ? c.win_days.replace(d, '') : (c.win_days + d).split('').sort().join('') });
  };
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        {!full ? (
          <ol className="steps" aria-label="Kroki konfiguracji">
            {STEPS.map((t, i) => (
              <li key={t}>
                <button type="button" className={`step ${i === step ? 'on' : i < step ? 'done' : ''}`} onClick={() => (i <= step || stepOk(step)) && setStep(i)} aria-current={i === step ? 'step' : undefined}>
                  <span className="step-n keep-round">{i < step ? '✓' : i + 1}</span><span className="step-t">{t}</span>
                </button>
              </li>
            ))}
          </ol>
        ) : <span className="text-[12px] text-slate-500">Widok pełny: wszystkie ustawienia naraz</span>}
        <div className="seg">
          <button type="button" className={`seg-btn ${!full ? 'on' : ''}`} onClick={() => setView(false)}>Krok po kroku</button>
          <button type="button" className={`seg-btn ${full ? 'on' : ''}`} onClick={() => setView(true)}>Widok pełny</button>
        </div>
      </div>
      {show(0) && <>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <div className="flex items-center justify-between gap-3 rounded-xl border border-white/[.08] px-4 py-3">
          <span className="flex items-center gap-2 text-[13px] font-bold text-white">Tryb uruchamiania <InfoTip text="Automatyczny: skan uruchamia się sam według harmonogramu i okna czasowego. Ręczny: tylko przyciskiem „Uruchom”." /></span>
          <MacSwitch on={!!c.sched_enabled} onChange={(v) => setC({ ...c, sched_enabled: v })} onLabel="Automatyczny" offLabel="Ręczny" />
        </div>
        <EstimateInfo c={c} />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <Field label="Nazwa konfiguracji"><input className="input" value={c.name} onChange={set('name')} placeholder="np. Sieć kampusowa: tygodniowo" /></Field>
        <Field label="Tagi celów (puste = wszystkie aktywne cele)"><TagInput value={c.target_tags} onChange={set('target_tags')} /></Field>
      </div>
      </>}
      {show(1) && <PortsField value={c.ports} onChange={set('ports')} />}
      {show(2) && <div>
        <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400"><Gauge size={13} /> Intensywność i bezpieczeństwo</div>
        <div className="grid grid-cols-4 gap-3">
          <Field label={<span className="inline-flex items-center gap-1.5">Limit pakietów/s <InfoTip text="Twardy górny limit ruchu całego skanu. Dzielony po równo między workery (np. 1000 pkt/s i 4 workery = --max-rate 250 na każdy proces nmapa). Główny „hamulec” chroniący sieć przed przeciążeniem." /></span>} hint="łącznie, dzielony między workery"><input className="input" type="number" value={c.rate} onChange={set('rate')} /></Field>
          <Field label={<span className="inline-flex items-center gap-1.5">Workery (równolegle) <InfoTip text="Liczba równoległych procesów nmapa; każdy skanuje swoją podgrupę adresów. Więcej = szybciej, ale limit pakietów nadal obowiązuje łącznie." /></span>}><input className="input" type="number" value={c.workers} onChange={set('workers')} /></Field>
          <Field label={<span className="inline-flex items-center gap-1.5">Zapytań HTTP/s <InfoTip text="Wspólny limit zapytań HTTP/HTTPS do wszystkich stron (tytuł, nagłówki, favicon, ścieżki sygnatur). Chroni serwery WWW przed zalaniem zapytaniami. Doskaner używa 1/4 tej wartości." /></span>}><input className="input" type="number" value={c.http_rps} onChange={set('http_rps')} /></Field>
          <Field label={<span className="inline-flex items-center gap-1.5">Cel czasu podgrupy (s) <InfoTip text="Ile ma trwać skan jednej podgrupy. Planer mierzy tempo i sam dobiera rozmiar podgrup (wielokrotności bloków po 64 IP). Krótsze podgrupy = częstszy zapis do bazy i dokładniejsze wznowienie po końcu okna." /></span>} hint="planer dobiera rozmiar podgrup"><input className="input" type="number" value={c.chunk_target_sec} onChange={set('chunk_target_sec')} /></Field>
          <Field label={<span className="inline-flex items-center gap-1.5">Timeout hosta (s) <InfoTip text="Maksymalny czas na jeden host (--host-timeout). Host, który odpowiada bardzo wolno albo „wisi”, nie zablokuje całej podgrupy." /></span>}><input className="input" type="number" value={c.host_timeout_sec} onChange={set('host_timeout_sec')} /></Field>
          <Field label={<span className="inline-flex items-center gap-1.5">Ponowienia sond <InfoTip text="Ile razy nmap ponawia sondę bez odpowiedzi (--max-retries). Więcej = mniej przeoczonych portów w zawodnej sieci, ale dłuższy skan i więcej ruchu." /></span>}><input className="input" type="number" value={c.retries} onChange={set('retries')} /></Field>
          <Field label={<span className="inline-flex items-center gap-1.5">Intensywność -sV (0–9) <InfoTip text="Jak dokładnie nmap rozpoznaje usługę i wersję (--version-intensity). 0–2: szybko i ostrożnie, tylko najczęstsze sondy; 7–9: dokładnie, ale więcej zapytań do każdej usługi." /></span>}><input className="input" type="number" value={c.version_intensity} onChange={set('version_intensity')} /></Field>
          <Field label={<span className="inline-flex items-center gap-1.5">„Zniknął” po N skanach <InfoTip text="Po ilu KOLEJNYCH skanach bez odpowiedzi host przestaje być „chwilowo niewidoczny” i staje się trwale niedostępny. Chroni przed fałszywym alarmem po jednym nieudanym skanie." /></span>}><input className="input" type="number" value={c.gone_after} onChange={set('gone_after')} /></Field>
          <Field label={<span className="inline-flex items-center gap-1.5">Porty sond discovery <InfoTip text="Dodatkowe porty dla sond TCP przy wykrywaniu, czy host żyje (-PS/-PA), oprócz stałych (22, 80, 443 i kilku innych). Przydatne, gdy host nie odpowiada na ping, ale ma nietypową usługę." /></span>} className="col-span-2"><input className="input font-mono" value={c.discovery_ports} onChange={set('discovery_ports')} /></Field>
          <Field label={<span className="inline-flex items-center gap-1.5">Wykluczenia (IP/CIDR) <InfoTip text="Adresy i zakresy, które nigdy nie są skanowane, nawet jeśli są w celach (np. brama, krytyczne serwery, urządzenia wrażliwe na skanowanie). Usuwane z listy przed startem skanu." /></span>} className="col-span-2"><input className="input font-mono" value={c.excludes} onChange={set('excludes')} placeholder="10.0.0.1, 10.0.5.0/24" /></Field>
        </div>
        <div className="mt-3 flex flex-wrap gap-6">
          <span className="inline-flex items-center gap-2"><Toggle checked={c.retry_unstable} onChange={set('retry_unstable')} label="ponowny pomiar hostów, które przestały odpowiadać" /> <InfoTip text="W tym samym skanie host, który wcześniej był aktywny, a teraz nie odpowiedział, dostaje od razu drugą, dokładniejszą próbę wykrycia (więcej sond, dłuższe czekanie), zanim zostanie oznaczony jako niewidoczny. Chroni przed chwilowymi błędami sieci. To nie doskaner: działa w trakcie skanu, w sekundach." /></span>
          <span className="inline-flex items-center gap-2"><Toggle checked={c.http_probe} onChange={set('http_probe')} label="fingerprinting HTTP/HTTPS (GET, bez logowania)" /> <InfoTip text="Dla portów webowych pobiera tytuł, kod, nagłówki, ciasteczka, certyfikat TLS, przekierowania, faviconę i ścieżki potrzebne sygnaturom. Tylko zapytania GET: nic nie loguje i nie wysyła formularzy. Wyłączone = sam wynik nmapa." /></span>
          <span className="inline-flex items-center gap-2"><Toggle checked={c.auto_add_ports} onChange={set('auto_add_ports')} label="dopisuj wykryte w sieci porty do listy (tylko z portów zatwierdzonych przez administratora; domyślnie wyłączone)" /> <InfoTip text="Jeśli skan znajdzie otwarty port spoza listy, a jest on na liście portów zatwierdzonych przez administratora, dopisuje go do portów reguły na kolejne skany (w regułach klasy z wagą 0, „do przejrzenia”). Poza tą listą nic nie dzieje się samo." /></span>
        </div>
      </div>
      }
      {show(3) && <>
      {!c.sched_enabled && <div className="rounded-xl border border-white/[.08] px-4 py-3 text-[12.5px] text-slate-400">Tryb <b className="text-white">Ręczny</b>: harmonogram jest wyłączony. Aby skan uruchamiał się sam, przełącz <button type="button" className="text-accent underline-offset-2 hover:underline" onClick={() => setC({ ...c, sched_enabled: true })}>na Automatyczny</button>.</div>}
      {/* Harmonogram: widoczny tylko w trybie automatycznym (płynne rozwinięcie). Wartości zostają w formularzu
          i w bazie także po przełączeniu na „Ręczny”, więc po ponownym włączeniu wszystko wraca bez zmian. */}
      <div className="grid transition-[grid-template-rows,opacity] duration-300 ease-out" style={{ gridTemplateRows: c.sched_enabled ? '1fr' : '0fr', opacity: c.sched_enabled ? 1 : 0 }} aria-hidden={!c.sched_enabled}>
      <div className="min-h-0 overflow-hidden" inert={c.sched_enabled ? undefined : ''}>
        <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400"><CalendarClock size={13} /> Harmonogram i okno czasowe</div>
        <div className="mt-3 grid grid-cols-4 gap-3">
          <Field label="Co ile minut"><input className="input" type="number" value={c.sched_every_min} onChange={set('sched_every_min')} /></Field>
          <Field label="Okno od"><input className="input" type="time" value={c.win_start} onChange={set('win_start')} /></Field>
          <Field label="Okno do" hint="okno może przechodzić przez północ"><input className="input" type="time" value={c.win_end} onChange={set('win_end')} /></Field>
          <Field label="Dni">
            <div className="flex gap-1">{DAYS.map((d, i) => <button type="button" key={d} onClick={() => toggleDay(i)} className={`h-8 w-8 rounded text-[11px] ${c.win_days.includes(String(i + 1)) ? 'border border-accent/60 bg-accent/15 text-accent' : 'border border-white/10 text-slate-500'}`}>{d}</button>)}</div>
          </Field>
        </div>
        <p className="mt-2 text-[11px] text-slate-500">Skan, który nie zmieści się w oknie, zostaje zatrzymany na końcu okna i wznowiony od miejsca przerwania w kolejnym oknie. Wyniki trafiają do bazy na bieżąco, po każdej podgrupie adresów.</p>
      </div>
      </div>
      {/* Doskaner: kafel z przełącznikiem jak „Tryb uruchamiania”; ustawienia widoczne po włączeniu, zachowane po wyłączeniu */}
      <div>
        <div className="flex items-center justify-between gap-3 rounded-xl border border-white/[.08] px-4 py-3">
          <span className="flex items-center gap-2 text-[13px] font-bold text-white"><RotateCcw size={14} className="text-accent" /> Doskaner
            <InfoTip text="Doskaner w ciągu dnia, w swoim oknie czasowym, co ustawiony odstęp skanuje po kolei końcówki, które nie odpowiedziały w skanie głównym: najpierw te, których jeszcze nie sprawdzał, potem kolejne okrążenia. Działa z 1/10 limitu pakietów, wynik trafia od razu do bazy i zasila wykrywanie zależności od pory dnia. Wyłączony: po skanie głównym nic się nie dzieje do następnego skanu." /></span>
          <MacSwitch on={!!c.retry_enabled} onChange={(v) => setC({ ...c, retry_enabled: v })} onLabel="Włączony" offLabel="Wyłączony" />
        </div>
        <div className="grid transition-[grid-template-rows,opacity] duration-300 ease-out" style={{ gridTemplateRows: c.retry_enabled ? '1fr' : '0fr', opacity: c.retry_enabled ? 1 : 0 }} aria-hidden={!c.retry_enabled}>
          <div className="min-h-0 overflow-hidden" inert={c.retry_enabled ? undefined : ''}>
            <div className="grid grid-cols-2 items-start gap-3 pt-3 md:grid-cols-4">
              <Field label="Okno od"><input className="input" type="time" value={c.retry_win_start} onChange={set('retry_win_start')} /></Field>
              <Field label="Okno do"><input className="input" type="time" value={c.retry_win_end} onChange={set('retry_win_end')} /></Field>
              <Field label="Adresów naraz" hint="1 = adres po adresie"><input className="input" type="number" min={1} value={c.retry_batch} onChange={set('retry_batch')} /></Field>
              <Field label="Odstęp" hint="między kolejnymi adresami">
                <div className="flex gap-2">
                  <input className="input min-w-0 flex-1" type="number" min={1} value={unit === 'min' ? Math.round(c.retry_pause_sec / 60) : c.retry_pause_sec}
                    onChange={(e) => setC({ ...c, retry_pause_sec: Math.max(1, Number(e.target.value) || 1) * (unit === 'min' ? 60 : 1) })} />
                  <select className="input w-[76px] flex-none" value={unit} onChange={(e) => { const u = e.target.value; setUnit(u); setC({ ...c, retry_pause_sec: u === 'min' ? Math.max(1, Math.round(c.retry_pause_sec / 60)) * 60 : c.retry_pause_sec }); }}>
                    <option value="s">s</option><option value="min">min</option>
                  </select>
                </div>
              </Field>
            </div>
          </div>
        </div>
      </div>
      </>}
      {show(4) && <div>
        <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400"><Send size={13} /> DefectDojo</div>
        <div className="flex flex-wrap items-end gap-4">
          <Toggle checked={c.dojo_auto} onChange={set('dojo_auto')} label="po zakończeniu skanu automatycznie aktualizuj test w DefectDojo (reimport)" />
          <Field label="Minimalna klasa (%)" className="w-40"><input className="input" type="number" value={c.dojo_min_interest} onChange={set('dojo_min_interest')} /></Field>
        </div>
        <p className="mt-2 text-[11px] text-slate-500">Test „MoNet – nazwa konfiguracji” jest aktualizowany przy każdym skanie: nowe obserwacje dochodzą, a zniknięte są zamykane po stronie DefectDojo.</p>
      </div>}
      {show(4) && !full && (
        <div className="summary">
          <div className="label mb-2">Podsumowanie</div>
          <dl>
            <dt>Nazwa</dt><dd>{c.name || <span className="text-[var(--err)]">brak</span>}</dd>
            <dt>Cele</dt><dd>{c.target_tags.length ? `tagi: ${c.target_tags.join(', ')}` : 'wszystkie aktywne cele'}</dd>
            <dt>Porty</dt><dd className="font-mono">{c.ports || 'tylko wykrywanie hostów'}</dd>
            <dt>Tempo</dt><dd className="font-mono">{c.rate} pkt/s · {c.workers} workery · {c.http_rps} HTTP/s</dd>
            <dt>Tryb</dt><dd>{c.sched_enabled ? `automatyczny · co ${c.sched_every_min} min · ${c.win_start}–${c.win_end}` : 'ręczny'}</dd>
            <dt>Doskaner</dt><dd>{c.retry_enabled ? `włączony · ${c.retry_win_start}–${c.retry_win_end} · co ${c.retry_pause_sec % 60 === 0 ? `${c.retry_pause_sec / 60} min` : `${c.retry_pause_sec} s`}` : 'wyłączony'}</dd>
            <dt>DefectDojo</dt><dd>{c.dojo_auto ? `automatyczny reimport, klasa ≥ ${c.dojo_min_interest}%` : 'bez automatycznej wysyłki'}</dd>
          </dl>
        </div>
      )}
      {err && <ErrorBox msg={err} />}
      <div className="flex items-center justify-end gap-2">
        <button className="btn-ghost mr-auto" onClick={onClose}>Anuluj</button>
        {!full && step > 0 && <button className="btn-ghost" onClick={() => setStep(step - 1)}>← Wstecz</button>}
        {!full && step < last
          ? <button className="btn-primary" disabled={!stepOk(step)} title={stepOk(step) ? '' : 'Podaj nazwę konfiguracji'} onClick={() => setStep(step + 1)}>Dalej →</button>
          : <><EstimateInline c={c} /><button className="btn-primary" onClick={save}><Save size={13} /> Zapisz</button></>}
      </div>
    </div>
  );
}

// ---- przeglądarka skanów: okresy (dziś, wczoraj, ten tydzień, ten miesiąc, miesiące) → daty → skany ----
const MONTHS = ['styczeń', 'luty', 'marzec', 'kwiecień', 'maj', 'czerwiec', 'lipiec', 'sierpień', 'wrzesień', 'październik', 'listopad', 'grudzień'];
const dayKey = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
function periodOf(d, now) {
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const day = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const diff = Math.round((today - day) / 86400000);
  const weekStart = new Date(today); weekStart.setDate(today.getDate() - ((today.getDay() + 6) % 7));
  if (diff === 0) return ['0-today', 'Dziś'];
  if (diff === 1) return ['1-yesterday', 'Wczoraj'];
  if (day >= weekStart) return ['2-week', 'W tym tygodniu'];
  if (d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth()) return ['3-month', 'W tym miesiącu'];
  return [`4-${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`, `${MONTHS[d.getMonth()]} ${d.getFullYear()}`];
}

function ScanBrowser({ scans, renderRow }) {
  const [sel, setSel] = useState('all');
  const list = scans.data || [];
  const now = new Date();
  const periods = {};
  for (const s of list) {
    const d = new Date(s.started_at || s.created_at);
    if (isNaN(d)) continue;
    const [pk, pl] = periodOf(d, now);
    const dk = dayKey(d);
    periods[pk] ||= { label: pl, days: {} };
    (periods[pk].days[dk] ||= []).push(s);
  }
  const pkeys = Object.keys(periods).sort((x, y) => (x.startsWith('4-') && y.startsWith('4-') ? y.localeCompare(x) : x.localeCompare(y)));
  const visibleDays = [];
  for (const pk of pkeys) {
    for (const dk of Object.keys(periods[pk].days).sort().reverse()) {
      if (sel === 'all' || sel === 'p:' + pk || sel === 'd:' + dk) visibleDays.push([dk, periods[pk].days[dk]]);
    }
  }
  const fmtDay = (dk) => new Date(dk + 'T12:00:00').toLocaleDateString('pl-PL', { weekday: 'long', day: '2-digit', month: '2-digit', year: 'numeric' });
  const item = (key, label, count, sub) => (
    <button key={key} onClick={() => setSel(key)} className={`relative flex w-full items-center justify-between rounded-full px-3 py-1.5 text-left transition ${sub ? 'pl-6 text-[12px]' : 'text-[12.5px]'} ${sel === key ? 'bg-accent/[.08] text-white before:absolute before:left-0 before:top-1 before:bottom-1 before:w-[2px] before:bg-accent' : 'text-slate-400 hover:bg-white/[.03] hover:text-slate-200'}`}>
      <span className={sub ? 'font-mono' : ''}>{label}</span><span className="font-mono text-[11px] text-slate-500">{count}</span>
    </button>
  );
  return (
    <div className="grid gap-5 lg:grid-cols-[240px_1fr]">
      <div className="card h-fit p-2">
        <div className="px-3 pb-2 pt-1 text-[9px] uppercase tracking-[.24em] text-slate-600">okresy</div>
        {item('all', 'Wszystkie skany', list.length)}
        <div className="hairline my-2" />
        {pkeys.map((pk) => {
          const days = Object.keys(periods[pk].days).sort().reverse();
          const total = days.reduce((a, d) => a + periods[pk].days[d].length, 0);
          return (
            <div key={pk} className="mb-1">
              {item('p:' + pk, periods[pk].label, total)}
              {days.map((dk) => item('d:' + dk, new Date(dk + 'T12:00:00').toLocaleDateString('pl-PL', { day: '2-digit', month: '2-digit' }) + ' · ' + new Date(dk + 'T12:00:00').toLocaleDateString('pl-PL', { weekday: 'short' }), periods[pk].days[dk].length, true))}
            </div>
          );
        })}
      </div>
      <div className="space-y-5">
        {scans.loading && !scans.data ? <Spinner /> : !visibleDays.length ? <Card><Empty>Brak skanów w wybranym okresie.</Empty></Card> : visibleDays.map(([dk, items]) => (
          <Card key={dk} title={`${fmtDay(dk)} · ${items.length} ${items.length === 1 ? 'skan' : 'skanów'}`} icon={CalendarClock} pad={false}>
            <table className="w-full">
              <thead><tr><th className="th">#</th><th className="th">Nazwa</th><th className="th">Stan</th><th className="th w-64">Postęp</th><th className="th">Hosty / usługi</th><th className="th">Czas trwania</th><th className="th">Start</th><th className="th"></th></tr></thead>
              <tbody>{items.map((s) => renderRow(s))}</tbody>
            </table>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ---- historia skanów: okresy (zawsze Dziś, Wczoraj, W tym tygodniu, W tym miesiącu) → skany z godziną → szczegóły ----
function ScanHistory({ scans, can, act }) {
  const [openP, setOpenP] = useState({ '0-today': true });
  const [openS, setOpenS] = useState({});
  const list = scans.data || [];
  const now = new Date();
  const periods = { '0-today': { label: 'Dziś', items: [] }, '1-yesterday': { label: 'Wczoraj', items: [] }, '2-week': { label: 'W tym tygodniu', items: [] }, '3-month': { label: 'W tym miesiącu', items: [] } };
  for (const s of list) {
    const d = new Date(s.started_at || s.created_at);
    if (isNaN(d)) continue;
    const [pk, pl] = periodOf(d, now);
    (periods[pk] ||= { label: pl, items: [] }).items.push(s);
  }
  const keys = Object.keys(periods).sort((x, y) => (x.startsWith('4-') && y.startsWith('4-') ? y.localeCompare(x) : x.localeCompare(y)));
  const hour = (s) => new Date(s.started_at || s.created_at).toLocaleTimeString('pl-PL', { hour: '2-digit', minute: '2-digit' });
  const day = (s) => new Date(s.started_at || s.created_at).toLocaleDateString('pl-PL', { weekday: 'short', day: '2-digit', month: '2-digit' });
  const Row = ({ k, v }) => <div className="grid grid-cols-[180px_1fr] gap-3 border-b py-2 text-[12.5px]" style={{ borderColor: 'rgba(120,170,235,.07)' }}><span className="text-slate-500">{k}</span><span className="text-slate-200">{v}</span></div>;
  if (scans.loading && !scans.data) return <Spinner />;
  return (
    <div className="space-y-3">
      {keys.map((pk) => {
        const p = periods[pk];
        const open = !!openP[pk];
        return (
          <div key={pk} className="card overflow-hidden">
            <button onClick={() => setOpenP({ ...openP, [pk]: !open })} className="flex w-full items-center justify-between px-5 py-3.5 text-left hover:bg-white/[.02]">
              <span className="flex items-center gap-3">
                <span className={`inline-block text-accent transition-transform ${open ? 'rotate-90' : ''}`}>▸</span>
                <span className="text-[15px] font-extrabold tracking-wide text-white">{p.label}</span>
              </span>
              <span className="font-mono text-[12px] text-slate-400">{p.items.length ? `${p.items.length} ${p.items.length === 1 ? 'skan' : p.items.length < 5 ? 'skany' : 'skanów'}` : 'brak'}</span>
            </button>
            {open && (
              <div className="border-t px-3 pb-3 pt-1" style={{ borderColor: 'rgba(120,170,235,.14)' }}>
                {!p.items.length ? (
                  <div className="m-2 rounded-xl border border-dashed px-4 py-6 text-center text-[13px] text-slate-500" style={{ borderColor: 'rgba(120,170,235,.18)', background: 'rgba(255,255,255,.015)' }}>
                    Brak skanów z {({ 'Dziś': 'Dzisiaj', 'Wczoraj': 'Wczoraj', 'W tym tygodniu': 'Tego Tygodnia', 'W tym miesiącu': 'Tego Miesiąca' })[p.label] || p.label}
                  </div>
                ) : p.items.map((s) => {
                  const so = !!openS[s.id];
                  return (
                    <div key={s.id} className="mt-2 rounded-xl border" style={{ borderColor: so ? 'rgba(108,182,255,.35)' : 'rgba(120,170,235,.10)' }}>
                      <button onClick={() => setOpenS({ ...openS, [s.id]: !so })} className="flex w-full items-center gap-4 px-4 py-2.5 text-left hover:bg-white/[.02]">
                        <span className={`text-accent transition-transform ${so ? 'rotate-90' : ''}`}>▸</span>
                        <span className="w-24 font-mono text-[13px] font-bold text-white">{pk === '0-today' || pk === '1-yesterday' ? hour(s) : `${day(s)} ${hour(s)}`}</span>
                        <span className="flex-1 truncate text-[13px] text-slate-200">{s.rule || (s.kind === 'import' ? 'Import' : '–')}{s.tag && <span className="ml-2 rounded border border-accent/40 bg-accent/[.08] px-1.5 py-0.5 font-mono text-[10.5px] text-accent-soft">{s.tag}</span>}</span>
                        <span className="w-28 text-[11px] uppercase tracking-wider text-slate-500">{s.kind}</span>
                        <State s={s.status} />
                      </button>
                      {so && (
                        <div className="px-5 pb-4 pt-1">
                          <Row k="Postęp" v={<div className="max-w-md"><BigProgress height={22} value={s.done_ips} total={s.total_ips} tone={s.status === 'paused' ? 'amber' : s.status === 'completed' ? 'signal' : 'accent'} /></div>} />
                          <Row k="Adresy" v={<span className="font-mono">{num(s.done_ips)} / {num(s.total_ips)}</span>} />
                          <Row k="Aktywne hosty" v={<span className="font-mono">{num(s.live_hosts)}</span>} />
                          <Row k="Otwarte usługi" v={<span className="font-mono">{num(s.open_services)}</span>} />
                          <Row k="Czas trwania" v={<span className="font-mono">{fmtDur(s.elapsed_ms)}</span>} />
                          <Row k="Start" v=<time>{fmtDate(s.started_at || s.created_at)}</time> />
                          <Row k="Koniec" v={s.finished_at ? fmtDate(s.finished_at) : '–'} />
                          <Row k="Reguła" v={s.rule || '–'} />
                          <Row k="Typ" v={s.kind} />
                          <Row k="Tag" v={s.tag || <span className="text-slate-600">brak (nadaj w szczegółach skanu)</span>} />
                          <Row k="Porty" v={<span className="break-all font-mono text-[11.5px]">{s.ports || 'tylko discovery'}</span>} />
                          <Row k="Uruchomił" v={s.triggered_by || '–'} />
                          {s.error && <Row k="Uwagi" v={<span className="text-rose-300">{s.error}</span>} />}
                          <div className="mt-3 flex flex-wrap gap-2">
                            <Link to={`/scans/${s.id}`} className="btn-primary">Szczegóły i wyniki skanu</Link>
                            {can('scans.run') && s.status === 'running' && <button className="btn-danger" onClick={() => act(s, 'cancel')}><Square size={12} /> Stop</button>}
                            {can('scans.run') && ['paused', 'cancelled', 'failed'].includes(s.status) && s.source !== 'import' && <button className="btn-ghost" onClick={() => act(s, 'resume')}><RotateCcw size={12} /> Wznów</button>}
                            {can('scans.delete') && s.status !== 'running' && <button className="btn-danger" onClick={() => act(s, 'delete')}><Trash2 size={12} /> Usuń</button>}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function ScanHostsTable({ rows, kind }) {
  return (
    <Card title={kind === 'down' ? 'Końcówki, które nie odpowiedziały w tym skanie' : 'Końcówki niestabilne (zmienna dostępność)'} icon={AlertTriangle} pad={false}>
      {!rows.length ? <Empty>{kind === 'down' ? 'Wszystkie znane końcówki odpowiedziały w tym skanie.' : 'Brak niestabilnych końcówek w tym skanie.'}</Empty> : (
        <table className="w-full">
          <thead><tr><th className="th">Końcówka</th><th className="th">W tym skanie</th><th className="th">Stan obecnie</th><th className="th">Ostatnio widziana</th><th className="th">Obecność w skanach</th><th className="th">Pomiar</th></tr></thead>
          <tbody>
            {rows.map((h) => (
              <tr key={h.ip} className="border-b">
                <td className="td"><div className="font-mono text-slate-100">{h.ip}</div>{h.hostname && <div className="text-[11px] text-slate-500">{h.hostname}</div>}</td>
                <td className="td">{h.alive ? <Badge tone="green">odpowiedziała</Badge> : <Badge tone="red">brak odpowiedzi</Badge>}</td>
                <td className="td">{h.state ? <State s={h.state} /> : '–'}</td>
                <td className="td font-mono text-[11px] text-slate-400">{h.last_seen ? fmtDate(h.last_seen) : <span className="text-rose-300/80">nigdy</span>}</td>
                <td className="td"><HistoryBar h={h.history} /></td>
                <td className="td text-[11px] text-slate-500">{h.retried ? 'ponowny pomiar' : ''} {h.reason && <span className="font-mono">{h.reason}</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

function RetryStatus({ c, onToggle, canToggle }) {
  const { data } = useApi(`/configs/${c.id}/retry`, [c.id, c.retry_enabled], 15000);
  return (
    <div className="mt-3 flex items-center justify-between gap-3 rounded-lg border border-white/5 bg-white/[.02] px-3 py-2">
      <div className="text-[12px] text-slate-400">
        <span className={`mr-2 inline-block h-2 w-2 rounded-full ${c.retry_enabled ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]' : 'bg-slate-600'}`} />
        Doskaner <b className="text-slate-200">{c.retry_enabled ? 'włączony' : 'wyłączony'}</b>
        {data && <> · nieosiągnięte: <b className="text-slate-200">{data.pool}</b>, sprawdzone po skanie: <b className="text-emerald-300">{data.checked_since_scan}</b></>}
        {c.retry_enabled && c.retry_next && <> · następny: <time>{fmtDate(c.retry_next)}</time></>}
      </div>
      {canToggle && <Toggle checked={c.retry_enabled} onChange={onToggle} />}
    </div>
  );
}

export default function Scans() {
  const [tab, setTab] = useState(() => { const q = new URLSearchParams(window.location.search); return q.get('tab') === 'configs' || q.get('new') ? 'configs' : 'history'; });
  const configs = useApi('/configs');
  const scans = useApi('/scans', [], 4000);
  const can = useCan();
  const toast = useToast();
  const nav = useNavigate();
  const [form, setForm] = useState(() => (new URLSearchParams(window.location.search).get('new') ? {} : null));

  const run = async (c) => {
    try {
      const r = await api(`/configs/${c.id}/run`, { method: 'POST', body: {} });
      toast(`Uruchomiono skan #${r.scan_id}`);
      nav(`/scans/${r.scan_id}`);
    } catch (e) { toast(e.message, 'err'); }
  };

  const toggleRetry = async (c) => {
    try {
      await api(`/configs/${c.id}`, { method: 'PUT', body: { ...c, retry_enabled: !c.retry_enabled } });
      toast(c.retry_enabled ? 'Doskaner wyłączony' : 'Doskaner włączony: ruszy w swoim oknie czasowym');
      configs.reload();
    } catch (e) { toast(e.message, 'err'); }
  };
  const retry = async (c) => {
    try {
      const cand = await api(`/configs/${c.id}/retry`);
      if (!cand.count) { toast('Brak nieosiągniętych końcówek do doskanowania'); return; }
      toast(`Doskanowuję ${Math.min(cand.count, c.retry_batch)} z ${cand.count} nieosiągniętych końcówek (najdawniej sprawdzane)…`);
      const r = await api(`/configs/${c.id}/retry`, { method: 'POST', body: {} });
      toast(`Sprawdzono ${r.checked}, odpowiedziało ${r.found?.length || 0}`);
      scans.reload();
    } catch (e) { toast(e.message, 'err'); }
  };
  const delCfg = async (c) => {
    if (!confirm(`Usunąć konfigurację „${c.name}”?`)) return;
    await api(`/configs/${c.id}`, { method: 'DELETE' });
    configs.reload();
  };
  const act = async (s, what) => {
    try {
      if (what === 'delete') {
        if (!confirm(`Usunąć skan #${s.id} i jego wyniki?`)) return;
        await api(`/scans/${s.id}`, { method: 'DELETE' });
      } else await api(`/scans/${s.id}/${what}`, { method: 'POST', body: {} });
      scans.reload();
    } catch (e) { toast(e.message, 'err'); }
  };

  return (
    <div>
      <PageHeader title="Skany" sub="Historia przebiegów i konfiguracje reguł (porty, intensywność, harmonogram, doskanowanie)">
        {can('configs.create') && tab === 'configs' && <button className="btn-primary" onClick={() => setForm({})}><Plus size={13} /> Nowa konfiguracja</button>}
      </PageHeader>

      <div className="seg mb-5">
        {[['history', 'Historia Skanów', History], ['configs', 'Konfiguracje', Gauge]].map(([k, l, I]) => (
          <button key={k} onClick={() => { setTab(k); window.history.replaceState(null, '', k === 'history' ? window.location.pathname : `?tab=${k}`); }}
            className={`seg-btn ${tab === k ? 'on' : ''}`}>
            <I size={14} strokeWidth={1.5} /> {l}
          </button>
        ))}
      </div>

      {tab === 'configs' && (
      <div className="mb-6 grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
        {configs.loading && !configs.data ? <Spinner /> : (configs.data || []).length === 0 ? <Card><Empty>Utwórz konfigurację skanu i podaj porty.</Empty></Card> : configs.data.map((c) => (
          <div key={c.id} className="card p-4">
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="font-medium text-slate-100">{c.name}</div>
                <div className="mt-0.5 text-[11px] text-slate-500">{c.target_tags.length ? `cele z tagami: ${c.target_tags.join(', ')}` : 'wszystkie aktywne cele'}</div>
              </div>
              <div className="flex items-center gap-2">
                {c.sched_enabled ? <Badge tone="blue">co {c.sched_every_min} min · {c.win_start}–{c.win_end}</Badge> : <Badge>ręcznie</Badge>}
                {(can('configs.update') || can('configs.delete')) && <TileMenu items={[
                  can('configs.update') && { label: 'Edytuj', icon: Pencil, onClick: () => setForm(c) },
                  can('configs.delete') && { label: 'Usuń', icon: Trash2, danger: true, onClick: () => delCfg(c) },
                ].filter(Boolean)} />}
              </div>
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5 text-[11px]">
              <Badge>{c.rate} pkt/s</Badge><Badge>{c.workers} workerów</Badge><Badge>{c.http_rps} HTTP/s</Badge><Badge>podgrupa ~{c.chunk_target_sec}s</Badge>
              {c.sched_enabled && c.next_run && <Badge tone="violet">następny: <time>{fmtDate(c.next_run)}</time></Badge>}
              {c.retry_enabled && <Badge tone="amber">doskaner {c.retry_win_start}–{c.retry_win_end} · {c.retry_batch} adr. co {c.retry_pause_sec % 60 === 0 ? `${c.retry_pause_sec / 60} min` : `${c.retry_pause_sec} s`}</Badge>}
              {c.dojo_auto && <Badge tone="violet">auto DefectDojo ≥ {c.dojo_min_interest}</Badge>}
            </div>
            <RetryStatus c={c} onToggle={() => toggleRetry(c)} canToggle={can('configs.update')} />
            <div className="mt-3 flex flex-wrap gap-2">
              {can('scans.run') && <button className="btn-run" onClick={() => run(c)}><Play size={14} fill="currentColor" /> Uruchom</button>}
              {can('scans.run') && <button className="btn-ghost" onClick={() => retry(c)}><RotateCcw size={13} /> Doskanuj teraz</button>}
            </div>
          </div>
        ))}
      </div>

      )}
      {tab === 'history' && <ScanHistory scans={scans} can={can} act={act} />}

      <Modal open={!!form} onClose={() => setForm(null)} title={form?.id ? <>Konfiguracja skanu · {form.name}</> : <>Konfiguracja nowego skanu</>} wide>
        {form && <ConfigForm initial={form} onClose={() => setForm(null)} onSaved={() => { setForm(null); configs.reload(); toast('Zapisano konfigurację'); }} />}
      </Modal>
    </div>
  );
}

export function ScanDetail() {
  const { id } = useParams();
  const can = useCan();
  const toast = useToast();
  const { data, error, loading, reload } = useApi(`/scans/${id}`, [id], 3000);
  const [q, setQ] = useState('');
  const [flag, setFlag] = useState('');
  const [minI, setMinI] = useState(0);
  const dq = useDebounced(q);
  const running = data?.scan?.status === 'running';
  const obs = useApi(`/scans/${id}/observations?q=${encodeURIComponent(dq)}&flag=${flag}&min_interest=${minI}`, [id, dq, flag, minI, running ? Math.floor(Date.now() / 10000) : 0]);
  const [sel, setSel] = useState(null);
  const [name, setName] = useState(null);
  const [stab, setStab] = useState('results');
  const [cat, setCat] = useState(null);
  const shosts = useApi(`/scans/${id}/hosts`, [id, running ? Math.floor(Date.now() / 15000) : 0]);
  if (loading && !data) return <Spinner />;
  if (error) return <ErrorBox msg={error} />;
  const s = data.scan;
  const jobs = data.jobs || [];
  const saveName = async () => {
    await api(`/scans/${id}`, { method: 'PUT', body: { tag: name.name, note: name.note } }).catch((e) => toast(e.message, 'err'));
    setName(null);
    reload();
  };
  const push = async () => {
    try {
      const r = await api('/dojo/push', { method: 'POST', body: { scan_id: Number(id), min_interest: 20 } });
      toast(`Wysłano ${r.sent} obserwacji do DefectDojo`);
    } catch (e) { toast(e.message, 'err'); }
  };
  return (
    <div>
      <Link to="/scans" className="mb-3 inline-flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300"><ChevronLeft size={14} /> Skany</Link>
      <PageHeader title={<span className="flex items-center gap-3">{s.label} <State s={s.status} /></span>} sub={`${s.tag ? `${s.rule || ''} · ` : ''}${s.kind}${s.source === 'import' ? '' : ' · porty: ' + (s.ports || 'tylko discovery')}${s.note ? ' · ' + s.note : ''}`}>
        {can('scans.update') && <button className="btn-ghost" onClick={() => setName({ name: s.tag || '', note: s.note })}><Pencil size={13} /> Tag / notatka</button>}
        {can('data.export') && <><button className="btn-ghost" onClick={() => download(`/export/scan/${id}?format=csv`)}><Download size={13} /> CSV</button><button className="btn-ghost" onClick={() => download(`/export/scan/${id}?format=json`)}><Download size={13} /> JSON</button></>}
        {can('dojo.push') && <button className="btn-ghost" onClick={push}><Send size={13} /> DefectDojo</button>}
        {can('scans.run') && running && <button className="btn-danger" onClick={() => api(`/scans/${id}/cancel`, { method: 'POST' }).then(reload)}><Square size={13} /> Stop</button>}
      </PageHeader>

      <div className="mb-5 grid grid-cols-2 gap-4 lg:grid-cols-5">
        <div className="card p-4 lg:col-span-2">
          <div className="label">Postęp</div>
          <div className="mb-2 font-mono text-2xl font-bold text-white">{s.total_ips ? Math.round((s.done_ips / s.total_ips) * 100) : 0}%</div>
          <BigProgress value={s.done_ips} total={s.total_ips} tone={s.status === 'completed' ? 'signal' : 'accent'} height={28} />
          <div className="mt-1 font-mono text-[11px] text-slate-500">{num(s.done_ips)} / {num(s.total_ips)} adresów{data.eta_sec > 0 && ` · ETA ${fmtDur(data.eta_sec * 1000)}`}</div>
        </div>
        <div className="card p-4"><div className="label">Czas trwania</div><div className="font-mono text-2xl font-bold">{fmtDur(s.elapsed_ms)}</div></div>
        <div className="card p-4"><div className="label">Aktywne hosty</div><div className="font-mono text-2xl font-bold text-sky-300">{num(s.live_hosts)}</div></div>
        <div className="card p-4"><div className="label">Otwarte usługi</div><div className="font-mono text-2xl font-bold text-rose-300">{num(s.open_services)}</div></div>
      </div>

      {jobs.length > 0 && (
        <Card title="Podgrupy: adaptacyjny podział adresów (rozmiar i czas trwania)" icon={Gauge} className="mb-5">
          <div className="grid grid-cols-2 gap-6 [&>div]:min-w-0">
            <div><div className="mb-2 text-[11px] text-slate-500">rozmiar podgrupy (IP)</div><Bars data={jobs.slice(-60).map((j, i) => ({ k: i + 1, v: j.ips }))} color="#6cb6ff" height={100} /></div>
            <div><div className="mb-2 text-[11px] text-slate-500">czas podgrupy (s) · cel {data.config?.chunk_target_sec}s</div><Bars data={jobs.slice(-60).map((j, i) => ({ k: i + 1, v: Math.round(j.duration_ms / 1000) }))} color="#4ade80" height={100} /></div>
          </div>
        </Card>
      )}
      {s.error && <div className="mb-5"><ErrorBox msg={s.error} /></div>}

      <div className="seg mb-4">
        {[['results', 'Wyniki Skanu'], ['down', `Niedostępne${shosts.data ? ` (${shosts.data.filter((h) => !h.alive).length})` : ''}`], ['unstable', `Niestabilne${shosts.data ? ` (${shosts.data.filter((h) => h.state === 'unstable').length})` : ''}`]].map(([k, l]) => (
          <button key={k} onClick={() => setStab(k)} className={`seg-btn ${stab === k ? 'on' : ''}`}>{l}</button>
        ))}
      </div>
      {stab !== 'results' ? <ScanHostsTable rows={(shosts.data || []).filter((h) => (stab === 'down' ? !h.alive : h.state === 'unstable'))} kind={stab} /> : (
      <Card title={cat ? `Wyniki skanu · ${SVC_CATEGORIES.find((c) => c.k === cat)?.label}` : 'Wyniki skanu · kategorie'} icon={Sparkles} pad={false}
        actions={cat && <button className="btn-ghost" onClick={() => setCat(null)}><ChevronLeft size={13} /> Wszystkie kategorie</button>}>
        <div className="flex flex-wrap gap-2 border-b border-white/5 p-3">
          <div className="relative min-w-[240px] flex-1"><Search size={14} className="absolute left-3 top-2.5 text-slate-500" /><input className="input pl-8" placeholder="Szukaj…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
          <select className="input w-48" value={flag} onChange={(e) => setFlag(e.target.value)}><option value="">wszystkie flagi</option>{Object.entries(flagLabel).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
          <select className="input w-40" value={minI} onChange={(e) => setMinI(Number(e.target.value))}>{[0, 10, 25, 50].map((v) => <option key={v} value={v}>klasa ≥ {v}%</option>)}</select>
        </div>
        {obs.loading && !obs.data ? <Spinner /> : !cat
          ? <><p className="px-4 pt-3 text-[11px] text-slate-500">Jeden wiersz = jedna kategoria, wg tego, co rozpoznano na usłudze (sygnatury), a nie wg protokołu. Np. panel kamery IP po HTTP trafia do „Urządzenia IoT”. Kliknij wiersz, aby zobaczyć usługi.</p><CategoryTable rows={obs.data || []} onOpen={(g) => setCat(g.k)} /></>
          : <ServicesTable rows={(obs.data || []).filter((o) => svcCategory(o) === cat)} onOpen={setSel} showState={false} />}
      </Card>
      )}
      <ServiceDrawer id={sel} onClose={() => setSel(null)} />
      <Modal open={!!name} onClose={() => setName(null)} title="Tag i notatka skanu">
        {name && <div className="space-y-3">
          <Field label="Tag (pusty = automatycznie: reguła i data)"><input className="input" value={name.name} onChange={(e) => setName({ ...name, name: e.target.value })} /></Field>
          <Field label="Notatka (szyfrowana)"><textarea className="input" rows={3} value={name.note} onChange={(e) => setName({ ...name, note: e.target.value })} /></Field>
          <button className="btn-primary" onClick={saveName}><Save size={13} /> Zapisz</button>
        </div>}
      </Modal>
    </div>
  );
}
