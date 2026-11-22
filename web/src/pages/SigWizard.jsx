// Kreator „Naucz system tej usługi”: tworzy własną sygnaturę z cech nierozpoznanej usługi (tytuł, nagłówki,
// favicon, ciasteczka, baner nmapa). Sygnatura działa od kolejnego skanu; przed zapisem można ją sprawdzić na wynikach.
import { useEffect, useMemo, useState } from 'react';
import { Wand2, Save, FlaskConical } from 'lucide-react';
import { api, useToast, Modal, Field, Badge } from '../lib.jsx';

const CATS = [
  ['admin-panel', 'Panel administracyjny', 25], ['iot', 'Urządzenie IoT', 25], ['staging', 'Środowisko testowe', 30],
  ['cms', 'CMS', 15], ['devops', 'DevOps / monitoring', 20], ['database', 'Baza danych', 20], ['appserver', 'Serwer aplikacyjny', 10],
  ['framework', 'Framework', 10], ['server', 'Serwer WWW', 5], ['proxy', 'Proxy', 10], ['interesting', 'Ciekawy artefakt', 20], ['other', 'Inne', 10],
];
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const q = (s) => `'${String(s).replace(/'/g, "''")}'`;
const slug = (s) => s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/ł/g, 'l').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'usluga';

// Cechy usługi, z których można zbudować sygnaturę (tylko bezpieczne: odpowiedzi, które skaner już pobrał).
function candidates(o) {
  const h = o.data?.http;
  const out = [];
  if (h?.title) out.push({ k: 'title', label: `Tytuł strony: „${h.title}”`, yaml: `{type: title, regex: ${q('^' + esc(h.title.trim()) + '$')}, weight: 0.9}`, on: true });
  const sv = h?.headers?.server?.[0];
  if (sv) { const base = sv.split('/')[0]; out.push({ k: 'server', label: `Nagłówek Server: ${base}`, yaml: `{type: header, name: server, regex: ${q('^' + esc(base))}, weight: 0.4}`, on: !h?.title }); }
  const pb = h?.headers?.['x-powered-by']?.[0];
  if (pb) out.push({ k: 'xpb', label: `Nagłówek X-Powered-By: ${pb}`, yaml: `{type: header, name: x-powered-by, regex: ${q(esc(pb.split('/')[0]))}, weight: 0.5}`, on: false });
  if (h?.favicon_hash != null) out.push({ k: 'fav', label: `Favicon (mmh3): ${h.favicon_hash}`, yaml: `{type: favicon, hashes: [${h.favicon_hash}], weight: 0.9}`, on: true });
  for (const c of h?.cookies || []) out.push({ k: 'c:' + c.name, label: `Ciasteczko: ${c.name}`, yaml: `{type: cookie, name: ${q('^' + esc(c.name) + '$')}, weight: 0.6}`, on: false });
  const prod = [o.data?.banner?.product].filter(Boolean)[0];
  if (prod) out.push({ k: 'banner', label: `Baner nmapa: ${prod}`, yaml: `{type: banner, regex: ${q(esc(prod))}, weight: 0.6}`, on: !h });
  return out;
}

export function SigWizard({ o, open, onClose, onSaved }) {
  const toast = useToast();
  const cands = useMemo(() => (o ? candidates(o) : []), [o?.id]); // eslint-disable-line
  const [name, setName] = useState('');
  const [cat, setCat] = useState('admin-panel');
  const [interest, setInterest] = useState(25);
  const [pick, setPick] = useState(null);
  const [test, setTest] = useState(null);
  const [path, setPath] = useState('');
  const [pathText, setPathText] = useState('');
  const sel = pick || Object.fromEntries(cands.map((c) => [c.k, c.on]));
  useEffect(() => {
    // domyślna nazwa: tytuł strony albo produkt z nmapa
    if (open && o) { setName(o.data?.http?.title || o.product || `${o.service} ${o.port}`); setPick(null); setTest(null); setPath(''); setPathText(''); }
  }, [open, o?.id]); // eslint-disable-line
  const pathOk = /^\/[\w\-./%~]*$/.test(path.trim());
  const chosen = cands.filter((c) => sel[c.k]);
  if (pathOk) chosen.push({ k: 'path', yaml: `{type: path, path: ${q(path.trim())}, status: [200]${pathText.trim() ? `, regex: ${q(esc(pathText.trim()))}` : ''}, weight: ${pathText.trim() ? 0.9 : 0.5}}` });
  const yaml = `- id: wlasna-${slug(name)}
  name: ${q(name || 'Nowa usługa')}
  category: ${cat}
  interest: ${Number(interest) || 0}
  matchers:
${chosen.map((c) => '    - ' + c.yaml).join('\n')}
`;
  const close = () => onClose();
  const runTest = async () => {
    try {
      const r = await api('/signatures/test', { method: 'POST', body: { body: yaml } });
      setTest(r.valid === false ? { error: r.error } : { n: (r.hits || []).length, sample: (r.hits || []).slice(0, 5) });
    } catch (e) { setTest({ error: e.message }); }
  };
  const save = async () => {
    try {
      await api('/signatures', { method: 'POST', body: { body: yaml } });
      toast(`Zapisano sygnaturę „${name}”. Zadziała od kolejnego skanu.`);
      onSaved?.();
      close();
    } catch (e) { toast(e.message, 'err'); }
  };
  return (
    <Modal open={open} onClose={close} title="Naucz system tej usługi">
      {o && <div className="space-y-4">
        <p className="text-[12px] text-slate-400">Tworzy własną sygnaturę z cech tej usługi. Od kolejnego skanu każda usługa z tymi cechami będzie rozpoznana pod podaną nazwą, kategorią i klasą. Sygnatury tylko porównują odpowiedzi; nic nie logują i nie eksploatują.</p>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Nazwa produktu" className="col-span-2"><input className="input" value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="Kategoria"><select className="input" value={cat} onChange={(e) => { setCat(e.target.value); setInterest(CATS.find((c) => c[0] === e.target.value)[2]); }}>{CATS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></Field>
          <Field label="Waga do klasy (0–100)"><input className="input" type="number" value={interest} onChange={(e) => setInterest(e.target.value)} /></Field>
        </div>
        <div>
          <div className="label mb-2">Po czym rozpoznawać</div>
          {!cands.length ? <div className="text-[12px] text-rose-300">Ta usługa nie ma cech, z których można zbudować sygnaturę.</div> : (
            <div className="space-y-1.5">{cands.map((c) => (
              <label key={c.k} className="flex cursor-pointer items-center gap-2 text-[13px] text-slate-200">
                <input type="checkbox" checked={!!sel[c.k]} onChange={(e) => { setPick({ ...sel, [c.k]: e.target.checked }); setTest(null); }} /> {c.label}
              </label>))}
            </div>)}
        </div>
        <div className="rounded-lg border border-white/5 bg-white/[.02] p-3">
          <div className="label mb-1">Rozpoznaj po ścieżce (opcjonalnie)</div>
          <p className="mb-2 text-[11px] text-slate-500">Dla usług bez tytułu i favicony (API, dashboardy pod podścieżką, strona główna 404). Skaner wykona jedno zapytanie GET pod tę ścieżkę, bez logowania, od kolejnego skanu.</p>
          <div className="grid grid-cols-2 gap-2">
            <input className="input font-mono" placeholder="/api/version" value={path} onChange={(e) => { setPath(e.target.value); setTest(null); }} />
            <input className="input" placeholder="tekst w odpowiedzi, np. Codename" value={pathText} onChange={(e) => { setPathText(e.target.value); setTest(null); }} />
          </div>
          {path && !pathOk && <div className="mt-1 text-[11px] text-rose-300">Ścieżka musi zaczynać się od „/” i nie zawierać spacji.</div>}
        </div>
        <pre className="max-h-48 overflow-auto rounded-lg border border-white/5 bg-black/40 p-3 font-mono text-[11px] text-slate-300">{yaml}</pre>
        {test && (test.error ? <div className="text-[12px] text-rose-300">Błąd: {test.error}</div> : (
          <div className="text-[12px] text-slate-300">{pathOk && <div className="mb-1 text-[11px] text-amber-200/80">Dopasowanie po ścieżce zadziała od kolejnego skanu (ścieżka nie była jeszcze odpytywana).</div>}Pasuje do <Badge tone={test.n ? 'green' : 'amber'}>{test.n}</Badge> usług w bieżących wynikach{test.sample.length > 0 && <>: <span className="font-mono text-slate-400">{test.sample.map((x) => `${x.ip}:${x.port}`).join(', ')}{test.n > 5 && ' …'}</span></>}</div>))}
        <div className="flex gap-2">
          <button className="btn-ghost" disabled={!chosen.length} onClick={runTest}><FlaskConical size={13} /> Sprawdź na wynikach</button>
          <button className="btn-primary" disabled={!chosen.length || !name.trim()} onClick={save}><Save size={13} /> Zapisz sygnaturę</button>
        </div>
      </div>}
    </Modal>
  );
}

export const WizardIcon = Wand2;
