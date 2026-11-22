import { useRef, useState } from 'react';
import { Fingerprint, Plus, Save, FlaskConical, Trash2, Search, Upload, Download, AlertTriangle } from 'lucide-react';
import { api, useApi, useCan, useToast, Card, Badge, Spinner, ErrorBox, Empty, Toggle, Modal, download } from '../lib.jsx';
import { PageHeader, InfoTip } from '../App.jsx';

const TEMPLATE = `# Zmień wartości poniżej (objaśnienia w panelu obok)
id: moja-aplikacja        # identyfikator
name: Moja aplikacja      # nazwa w wynikach
category: admin-panel     # rodzaj znaleziska
interest: 20              # waga w klasie (0–100)
match: any                # any / all
matchers:
  - {type: title, regex: 'Moja Aplikacja', weight: 0.6}
  - {type: header, name: server, regex: 'MojaApp/(?P<version>[\\d.]+)', weight: 0.8}
  - {type: cookie, name: '^MOJAAPP_SESSION$', weight: 0.5}
  - {type: path, path: /version, status: [200], regex: '"version"', weight: 0.7}
`;

// objaśnienie pól sygnatury (panel obok edytora)
const FIELDS = [
  ['id', 'Unikalny identyfikator sygnatury, np. moja-aplikacja. Tylko małe litery, cyfry i myślniki.'],
  ['name', 'Nazwa produktu, która pojawi się przy usłudze, w kategoriach i w zakładce Technologie.'],
  ['category', 'Rodzaj znaleziska. Decyduje o kategorii usługi i fladze, np. admin-panel → „panel admina”, iot → „IoT”, staging, cms, database, interesting (ciekawy artefakt).'],
  ['interest', 'Waga w klasie ważności usługi (0–100). Im wyżej, tym wyżej usługa na liście „wysokiej klasy”.'],
  ['match', 'any: wystarczy, że pasuje jeden warunek. all: muszą pasować wszystkie warunki.'],
  ['matchers', 'Lista warunków. Każdy ma typ, wzorzec i wagę 0–1. Suma wag pasujących warunków = pewność wykrycia (max 100%).'],
];
const TYPES = [
  ['title', 'tytuł strony (<title>)', "regex: 'Grafana'"],
  ['header', 'nagłówek HTTP o nazwie name', "name: server, regex: 'nginx'"],
  ['cookie', 'nazwa ciasteczka', "name: '^PHPSESSID$'"],
  ['body', 'fragment kodu strony (HTML)', "regex: 'wp-content'"],
  ['path', 'GET na podaną ścieżkę (bez logowania)', "path: /admin, status: [200]"],
  ['favicon', 'hash favicony (mmh3, jak w Shodan)', 'hashes: [116323821]'],
  ['banner', 'baner usługi rozpoznany przez nmap', "regex: 'OpenSSH'"],
  ['service', 'nazwa usługi z nmapa', "regex: '^ssh$'"],
  ['cert', 'treść certyfikatu TLS (CN, wystawca, SAN)', "regex: 'staging'"],
  ['hostname', 'nazwa hosta', "regex: '^dev-'"],
  ['status', 'kod odpowiedzi HTTP', 'status: [401]'],
  ['port', 'numer portu', 'ports: [8080]'],
];
function SigHelp() {
  return (
    <aside className="sig-help">
      <div className="sig-help-h">Co jest czym</div>
      <dl className="sig-fields">{FIELDS.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>
      <div className="sig-help-h mt-4">Typy warunków (type)</div>
      <table className="sig-types"><tbody>{TYPES.map(([t, d, ex]) => <tr key={t}><td className="font-mono">{t}</td><td>{d}<div className="font-mono text-[11px] text-slate-500">{ex}</div></td></tr>)}</tbody></table>
      <div className="sig-help-h mt-4">Dobrze wiedzieć</div>
      <ul className="sig-tips">
        <li><b>regex</b> to wyrażenie regularne; wielkość liter ma znaczenie, chyba że dodasz <span className="font-mono">(?i)</span> na początku.</li>
        <li><b>Wersja:</b> fragment <span className="font-mono">(?P&lt;version&gt;…)</span> w regex wyciąga numer wersji, np. 1.25.3.</li>
        <li><b>Bezpieczeństwo:</b> sygnatury tylko porównują odpowiedzi i wykonują GET; nic nie logują i nie wysyłają formularzy.</li>
        <li><b>Najpierw testuj:</b> „Testuj na zebranych wynikach” pokazuje, do których usług pasuje sygnatura, zanim ją zapiszesz.</li>
        <li>Szybciej: w szczegółach usługi przycisk <b>„Naucz system”</b> zbuduje sygnaturę za Ciebie.</li>
      </ul>
    </aside>
  );
}

export default function Signatures() {
  const { data, error, loading, reload } = useApi('/signatures');
  const can = useCan();
  const toast = useToast();
  const [ed, setEd] = useState(null);
  const [test, setTest] = useState(null);
  const [q, setQ] = useState('');
  const [cat, setCat] = useState('');
  const [imp, setImp] = useState(null);
  const save = async () => {
    try {
      await api(ed.id ? `/signatures/${ed.id}` : '/signatures', { method: ed.id ? 'PUT' : 'POST', body: { body: ed.body, enabled: ed.enabled } });
      toast('Zapisano sygnaturę. Działa od następnego skanu (albo „Przelicz sygnatury” w skanie).');
      setEd(null);
      reload();
    } catch (e) { toast(e.message, 'err'); }
  };
  const runTest = async () => {
    try { setTest(await api('/signatures/test', { method: 'POST', body: { body: ed.body } })); } catch (e) { toast(e.message, 'err'); }
  };
  const toggle = async (s) => { await api(`/signatures/${s.id}`, { method: 'PUT', body: { enabled: !s.enabled } }).catch((e) => toast(e.message, 'err')); reload(); };
  const del = async (s) => { if (confirm(`Usunąć sygnaturę ${s.sid}?`)) { await api(`/signatures/${s.id}`, { method: 'DELETE' }).catch((e) => toast(e.message, 'err')); reload(); } };
  const list = (data || []).filter((s) => (!cat || s.category === cat) && (!q || (s.sid + s.name).toLowerCase().includes(q.toLowerCase())));
  const cats = [...new Set((data || []).map((s) => s.category))].sort();
  return (
    <div>
      <PageHeader title="Sygnatury detekcyjne" sub="Bezpieczna detekcja obecności cech: nagłówki, ciasteczka, HTML, favicon, ścieżki (tylko GET, bez logowania), banery. Nigdy nie eksploatują podatności.">
        <button className="btn-ghost" onClick={() => download('/signatures/export?format=yaml')}><Download size={13} /> Eksport YAML</button>
        <button className="btn-ghost" onClick={() => download('/signatures/export?format=json')}><Download size={13} /> Eksport JSON</button>
        {can('signatures.create') && <button className="btn-ghost" onClick={() => setImp({})}><Upload size={13} /> Importuj z pliku</button>}
        {can('signatures.create') && <button className="btn-primary" onClick={() => { setEd({ body: TEMPLATE, enabled: true }); setTest(null); }}><Plus size={13} /> Nowa sygnatura</button>}
      </PageHeader>
      <Card pad={false}>
        <div className="flex flex-wrap gap-2 border-b border-white/5 p-3">
          <div className="relative min-w-[240px] flex-1"><Search size={14} className="absolute left-3 top-2.5 text-slate-500" /><input className="input pl-8" placeholder="Szukaj…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
          <select className="input w-48" value={cat} onChange={(e) => setCat(e.target.value)}><option value="">wszystkie kategorie</option>{cats.map((c) => <option key={c}>{c}</option>)}</select>
        </div>
        {loading && !data ? <Spinner /> : error ? <ErrorBox msg={error} /> : !list.length ? <Empty>Brak sygnatur.</Empty> : (
          <table className="w-full">
            <thead><tr className="border-b border-white/5"><th className="th">Sygnatura</th><th className="th">Kategoria</th><th className="th">Źródło</th><th className="th">Włączona</th><th className="th"></th></tr></thead>
            <tbody>
              {list.map((s) => (
                <tr key={s.id} className="border-b border-white/[.03] hover:bg-white/[.02]">
                  <td className="td"><div className="text-slate-100">{s.name}</div><div className="font-mono text-[11px] text-slate-500">{s.sid}</div></td>
                  <td className="td"><Badge tone="blue">{s.category}</Badge></td>
                  <td className="td">{s.builtin ? <Badge>wbudowana</Badge> : <Badge tone="violet">własna · {s.created_by}</Badge>}</td>
                  <td className="td"><Toggle checked={s.enabled} onChange={() => can('signatures.update') && toggle(s)} /></td>
                  <td className="td whitespace-nowrap text-right">
                    <button className="btn-ghost" onClick={() => { setEd({ ...s }); setTest(null); }}>{can('signatures.update') ? 'Edytuj' : 'Podgląd'}</button>{' '}
                    {can('signatures.delete') && !s.builtin && <button className="btn-danger" onClick={() => del(s)}><Trash2 size={12} /></button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <ImportModal open={!!imp} onClose={() => { setImp(null); reload(); }} />
      <Modal open={!!ed} onClose={() => setEd(null)} title={ed?.id ? `Sygnatura ${ed.sid}` : 'Nowa sygnatura'} wide>
        {ed && (
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-[12px] text-slate-400">Treść sygnatury (format YAML) <InfoTip text="Sygnatura opisuje, po czym rozpoznać produkt lub znalezisko w odpowiedzi usługi. Edytuj wartości w szablonie; objaśnienie każdego pola i typu warunku jest w panelu obok." /></div>
            <textarea wrap="off" className="input h-[420px] overflow-x-auto whitespace-pre font-mono text-[12px] leading-relaxed" value={ed.body} onChange={(e) => setEd({ ...ed, body: e.target.value })} spellCheck={false} aria-label="Treść sygnatury w YAML" />
            <div className="flex flex-wrap items-center gap-3">
              {(ed.id ? can('signatures.update') : can('signatures.create')) && <button className="btn-primary" onClick={save}><Save size={13} /> Zapisz</button>}
              <span className="inline-flex items-center gap-1.5"><button className="btn-ghost" onClick={runTest}><FlaskConical size={13} /> Testuj na zebranych wynikach</button><InfoTip text="Sprawdza sygnaturę na już zebranych wynikach (bez skanowania). Pokazuje, do których usług pasuje i z jaką pewnością. Nic nie zapisuje." /></span>
              <span className="inline-flex items-center gap-1.5"><Toggle checked={ed.enabled} onChange={(v) => setEd({ ...ed, enabled: v })} label="włączona" /><InfoTip text="Wyłączona sygnatura zostaje zapisana, ale nie jest używana w kolejnych skanach." /></span>
            </div>
            {test && (test.valid === false ? <ErrorBox msg={test.error} /> : (
              <div className="rounded-lg border border-white/5 bg-white/[.02] p-3 text-[12px]">
                <div className="mb-2 text-slate-300">Sprawdzono {test.tested} usług · dopasowań: <b className="text-emerald-300">{test.hits.length}</b> {test.note && <span className="text-slate-500">({test.note})</span>}</div>
                <div className="max-h-48 space-y-1 overflow-y-auto">{test.hits.slice(0, 100).map((h, i) => <div key={i} className="font-mono text-[11px] text-slate-400">{h.ip}:{h.port} → {h.detection.name} {h.detection.version} ({h.detection.confidence}%) · {h.detection.evidence.join('; ')}</div>)}</div>
              </div>
            ))}
          </div>
          <SigHelp />
          </div>
        )}
      </Modal>
    </div>
  );
}

function ImportModal({ open, onClose }) {
  const toast = useToast();
  const fileRef = useRef();
  const [file, setFile] = useState(null);
  const [prev, setPrev] = useState(null);
  const [mode, setMode] = useState('skip');
  const [busy, setBusy] = useState(false);
  const send = async (m, f = file) => {
    const fd = new FormData();
    fd.append('file', f);
    fd.append('mode', m);
    fd.append('on_conflict', mode);
    setBusy(true);
    try {
      const r = await api('/signatures/import', { method: 'POST', body: fd });
      setPrev(r);
      if (m === 'import') toast(`Import: dodano ${r.added}, nadpisano ${r.updated}, pominięto ${r.skipped}`);
    } catch (e) { toast(e.message, 'err'); setPrev(null); }
    setBusy(false);
  };
  const close = () => { setFile(null); setPrev(null); onClose(); };
  const FMT = { 'asi-yaml': 'MoNet (YAML)', 'asi-json': 'MoNet (JSON)', nuclei: 'szablony nuclei', wappalyzer: 'Wappalyzer (technologies.json)', csv: 'CSV' };
  return (
    <Modal open={open} onClose={close} title="Import sygnatur z pliku" wide>
      <p className="mb-3 text-[12px] leading-relaxed text-slate-400">
        Obsługiwane formaty (rozpoznawane automatycznie): <b>MoNet</b> YAML/JSON, <b>szablony nuclei</b> (importowane są tylko bezpieczne zapytania GET bez payloadów),
        <b> Wappalyzer</b> (technologies.json: nagłówki, ciasteczka, HTML, meta, skrypty) i <b>CSV</b> (kolumny: name, type, pattern, opcjonalnie category, interest, header, path, status, weight).
        Najpierw zobaczysz podgląd z ostrzeżeniami, a zapis nastąpi dopiero po zatwierdzeniu.
      </p>
      <input ref={fileRef} type="file" accept=".yaml,.yml,.json,.csv,.txt" className="hidden" onChange={(e) => { const f = e.target.files[0]; if (f) { setFile(f); send('preview', f); } e.target.value = ''; }} />
      <div className="flex flex-wrap items-center gap-2">
        <button className="btn-primary" onClick={() => fileRef.current.click()} disabled={busy}><Upload size={13} /> Wybierz plik</button>
        {file && <span className="font-mono text-[12px] text-slate-400">{file.name}</span>}
      </div>
      {prev && (
        <div className="mt-4 space-y-3">
          <div className="flex flex-wrap items-center gap-2 text-[12px] text-slate-300">
            <Badge tone="blue">format: {FMT[prev.format] || prev.format}</Badge>
            <Badge tone="green">sygnatur: {prev.items.length}</Badge>
            {prev.unsupported > 0 && <Badge tone="amber">pominięte (nieobsługiwane): {prev.unsupported}</Badge>}
            {prev.items.some((i) => i.conflict) && <Badge tone="amber">konflikty id: {prev.items.filter((i) => i.conflict).length}</Badge>}
          </div>
          <div className="max-h-64 overflow-y-auto rounded border border-white/10">
            <table className="w-full">
              <thead><tr><th className="th">ID</th><th className="th">Nazwa</th><th className="th">Kategoria</th><th className="th">Matchery</th><th className="th">Ścieżki GET</th><th className="th">Stan</th></tr></thead>
              <tbody>{prev.items.map((i) => (
                <tr key={i.id} className="border-b"><td className="td font-mono text-[11px]">{i.id}</td><td className="td">{i.name}</td><td className="td"><Badge tone="blue">{i.category}</Badge></td>
                  <td className="td font-mono">{i.matchers}</td><td className="td font-mono">{i.paths}</td><td className="td text-[11px]">{i.status || (i.conflict ? <span className="text-amber-300">istnieje</span> : <span className="text-emerald-300">nowa</span>)}</td></tr>
              ))}</tbody>
            </table>
          </div>
          {prev.warnings?.length > 0 && (
            <details className="rounded border border-amber-400/20 bg-amber-500/[.04] p-2 text-[11px] text-amber-200/90">
              <summary className="cursor-pointer"><AlertTriangle size={12} className="mr-1 inline" />Ostrzeżenia ({prev.warnings.length})</summary>
              <ul className="mt-1 list-disc pl-5">{prev.warnings.slice(0, 60).map((w, i) => <li key={i}>{w}</li>)}</ul>
            </details>
          )}
          <div className="flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-2 text-[12px] text-slate-300">Gdy sygnatura o tym id już istnieje:
              <select className="input w-44 py-1" value={mode} onChange={(e) => setMode(e.target.value)}><option value="skip">pomiń</option><option value="overwrite">nadpisz</option></select>
            </label>
            <button className="btn-ok" disabled={busy || !prev.items.length} onClick={() => send('import')}>Importuj {prev.items.length} sygnatur</button>
          </div>
        </div>
      )}
    </Modal>
  );
}
