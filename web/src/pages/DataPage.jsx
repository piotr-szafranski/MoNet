import { useRef, useState, useEffect } from 'react';
import { Upload, Download, Send, Settings, PlugZap, FileDown, History } from 'lucide-react';
import { api, useApi, useCan, useToast, Card, Field, Toggle, ErrorBox, download, Badge, Empty, fmtDate, num } from '../lib.jsx';
import { PageHeader } from '../App.jsx';
import { useNavigate } from 'react-router-dom';

export default function DataPage() {
  const can = useCan();
  const toast = useToast();
  const nav = useNavigate();
  const fileRef = useRef();
  const [name, setName] = useState('');
  const [res, setRes] = useState(null);
  const scans = useApi('/scans');
  const [scanId, setScanId] = useState('');
  const [minI, setMinI] = useState(20);
  const [reimport, setReimport] = useState(true);
  const upload = async (f) => {
    if (!f) return;
    const fd = new FormData();
    fd.append('file', f);
    fd.append('name', name);
    try {
      const r = await api('/import/results', { method: 'POST', body: fd });
      setRes(r);
      toast(`Zaimportowano ${r.hosts} hostów i ${r.services} usług (${r.format})`);
    } catch (e) { toast(e.message, 'err'); }
    fileRef.current.value = '';
  };
  const done = (scans.data || []).filter((s) => s.status === 'completed');
  return (
    <div>
      <PageHeader title="Import i eksport danych" sub="Import wyników (XML nmapa, JSON/CSV w formacie MoNet), eksport do JSON/CSV i integracja z DefectDojo" />
      <div className="grid gap-5 lg:grid-cols-2">
        {can('results.create') && (
          <Card title="Import wyników skanu" icon={Upload}>
            <p className="mb-3 text-[12px] leading-relaxed text-slate-400">Obsługiwane formaty (rozpoznawane automatycznie): <b>XML nmapa</b> (<code className="text-accent-soft">-oX</code>), <b>JSON MoNet</b> (dokument eksportu lub tablica rekordów), <b>CSV</b> z kolumną <code className="text-accent-soft">ip</code> (opcjonalnie port, proto, service, product, version, http_status, title, server). Zaimportowane wyniki przechodzą przez te same sygnatury, ocenę ciekawości, stany hostów i diff.</p>
            <Field label="Nazwa skanu (opcjonalnie)"><input className="input" value={name} onChange={(e) => setName(e.target.value)} /></Field>
            <input ref={fileRef} type="file" accept=".xml,.json,.csv" className="hidden" onChange={(e) => upload(e.target.files[0])} />
            <button className="btn-primary mt-3" onClick={() => fileRef.current.click()}><Upload size={13} /> Wybierz plik</button>
            {res && <div className="mt-3 rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 text-[12px] text-emerald-200">Utworzono skan #{res.scan_id} ({res.format}): {res.hosts} hostów, {res.services} usług. <button className="underline" onClick={() => nav(`/scans/${res.scan_id}`)}>Otwórz</button></div>}
          </Card>
        )}
        <Card title="Eksport" icon={Download}>
          <div className="space-y-3">
            <div className="flex items-center justify-between rounded-lg border border-white/5 p-3"><div><div className="text-sm text-slate-200">Bieżący inwentarz usług</div><div className="text-[11px] text-slate-500">ostatnia obserwacja każdej usługi + tagi i notatki</div></div><div className="flex gap-2"><button className="btn-ghost" onClick={() => download('/export/services?format=csv')}>CSV</button><button className="btn-ghost" onClick={() => download('/export/services?format=json')}>JSON</button></div></div>
            <div className="flex items-center justify-between rounded-lg border border-white/5 p-3"><div><div className="text-sm text-slate-200">Cele skanowania</div></div><div className="flex gap-2"><button className="btn-ghost" onClick={() => download('/export/targets?format=csv')}>CSV</button><button className="btn-ghost" onClick={() => download('/export/targets?format=json')}>JSON</button></div></div>
            <div className="rounded-lg border border-white/5 p-3">
              <div className="mb-2 text-sm text-slate-200">Wybrany skan</div>
              <div className="flex gap-2">
                <select className="input" value={scanId} onChange={(e) => setScanId(e.target.value)}><option value="">wybierz skan…</option>{(scans.data || []).map((s) => <option key={s.id} value={s.id}>#{s.id} · {s.name}</option>)}</select>
                <button className="btn-ghost" disabled={!scanId} onClick={() => download(`/export/scan/${scanId}?format=csv`)}>CSV</button>
                <button className="btn-ghost" disabled={!scanId} onClick={() => download(`/export/scan/${scanId}?format=json`)}>JSON</button>
              </div>
            </div>
          </div>
        </Card>
        {can('dojo.push') && (
          <Card title="Eksport do DefectDojo" icon={Send}>
            <p className="mb-3 text-[12px] text-slate-400">Wybrane obserwacje trafiają do DefectDojo jako findingi informacyjne (severity Info) z dowodami: nagłówki, technologie, certyfikat. Format: <i>Generic Findings Import</i>, endpoint <code className="text-accent-soft">/api/v2/import-scan/</code>.</p>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Skan (puste = bieżący inwentarz)"><select className="input" value={scanId} onChange={(e) => setScanId(e.target.value)}><option value="">bieżący inwentarz</option>{done.map((s) => <option key={s.id} value={s.id}>#{s.id} · {s.name}</option>)}</select></Field>
              <Field label="Minimalna klasa (%)"><input className="input" type="number" value={minI} onChange={(e) => setMinI(Number(e.target.value))} /></Field>
            </div>
            <div className="mt-3"><Toggle checked={reimport} onChange={setReimport} label="aktualizuj stały test (reimport: nowe dochodzą, zniknięte są zamykane)" /></div>
            <div className="mt-3 flex flex-wrap gap-2">
              <button className="btn-primary" onClick={async () => { try { const r = await api('/dojo/push', { method: 'POST', body: { scan_id: Number(scanId) || 0, min_interest: minI, reimport } }); toast(`Wysłano ${r.sent} findingów do DefectDojo`); } catch (e) { toast(e.message, 'err'); } }}><Send size={13} /> Wyślij do DefectDojo</button>
              <button className="btn-ghost" onClick={() => download(`/dojo/preview?scan_id=${scanId || 0}&min_interest=${minI}&download=1`)}><FileDown size={13} /> Pobierz plik do ręcznego importu</button>
            </div>
          </Card>
        )}
        {can('settings.manage') && <DojoSettings />}
      </div>
      <DojoHistory />
    </div>
  );
}

function DojoSettings() {
  const toast = useToast();
  const { data } = useApi('/settings/dojo');
  const [s, setS] = useState(null);
  const [test, setTest] = useState(null);
  useEffect(() => { if (data) setS({ ...data.settings, token: '' }); }, [data]);
  if (!s) return null;
  const save = async () => { try { await api('/settings/dojo', { method: 'PUT', body: s }); toast('Zapisano ustawienia DefectDojo (token szyfrowany w bazie)'); } catch (e) { toast(e.message, 'err'); } };
  return (
    <Card title="Ustawienia DefectDojo" icon={Settings}>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Adres instancji" className="col-span-2"><input className="input" value={s.url} onChange={(e) => setS({ ...s, url: e.target.value })} placeholder="https://defectdojo.example.org" /></Field>
        <Field label={`Token API ${data.has_token ? '(zapisany, wpisz aby zmienić)' : ''}`} className="col-span-2"><input className="input" type="password" value={s.token} onChange={(e) => setS({ ...s, token: e.target.value })} /></Field>
        <Field label="Produkt"><input className="input" value={s.product} onChange={(e) => setS({ ...s, product: e.target.value })} placeholder="MoNet discovery" /></Field>
        <Field label="Engagement"><input className="input" value={s.engagement} onChange={(e) => setS({ ...s, engagement: e.target.value })} placeholder="MoNet 2026-11" /></Field>
        <Toggle checked={s.verify_tls} onChange={(v) => setS({ ...s, verify_tls: v })} label="weryfikuj certyfikat TLS" />
      </div>
      <div className="mt-3 flex gap-2">
        <button className="btn-primary" onClick={save}>Zapisz</button>
        <button className="btn-ghost" onClick={async () => setTest(await api('/dojo/test', { method: 'POST' }).catch((e) => ({ ok: false, error: e.message })))}><PlugZap size={13} /> Test połączenia</button>
      </div>
      {test && (test.ok ? <div className="mt-2 text-[12px] text-emerald-300">Połączenie działa.</div> : <div className="mt-2"><ErrorBox msg={test.error} /></div>)}
    </Card>
  );
}

function DojoHistory() {
  const { data, reload } = useApi('/dojo/history', [], 15000);
  const can = useCan();
  const toast = useToast();
  const [busy, setBusy] = useState(0);
  const retry = async (id) => {
    setBusy(id);
    try { const x = await api(`/dojo/retry/${id}`, { method: 'POST', body: {} }); toast(`Ponowiono: wysłano ${x.sent} findingów`); } catch (e) { toast(e.message, 'err'); }
    setBusy(0); reload();
  };
  const rows = data || [];
  return (
    <Card title={<>Historia Importowania do DefectDojo ({rows.length})</>} icon={History} pad={false} className="mt-5" collapsible>
      <p className="px-4 pt-3 text-[11px] text-slate-500">Co zmieniło się po stronie DefectDojo przy każdej wysyłce: nowe, zamknięte i przywrócone findingi.</p>
      {!rows.length ? <Empty>Brak wysyłek.</Empty> : (
        <table className="w-full">
          <thead><tr><th className="th">Czas</th><th className="th">Kto</th><th className="th">Tryb</th><th className="th">Test DefectDojo</th><th className="th">Skan</th><th className="th">Wysłano</th>
            <th className="th">Bez zmian</th><th className="th">Nowe</th><th className="th">Zamknięte</th><th className="th">Przywrócone</th><th className="th">Wynik</th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-b">
                <td className="td whitespace-nowrap font-mono text-[11px] text-slate-400"><time>{fmtDate(r.ts)}</time></td>
                <td className="td text-[12px]">{r.user}</td>
                <td className="td"><Badge tone={r.mode.startsWith('reimport') ? 'violet' : 'blue'}>{r.mode}</Badge></td>
                <td className="td text-[12px] text-slate-300">{r.test_title}{r.test_id > 0 && <span className="text-slate-500"> · #{r.test_id}</span>}</td>
                <td className="td font-mono text-[12px] text-slate-400">{r.scan_id || 'inwentarz'}</td>
                <td className="td font-mono text-[13px] font-semibold text-slate-100">{num(r.sent)}</td>
                <td className="td font-mono text-[12px] text-slate-300">{num(r.untouched)}</td>
                <td className="td font-mono text-[12px] text-emerald-300">{num(r.created)}</td>
                <td className="td font-mono text-[12px] text-rose-300">{num(r.closed)}</td>
                <td className="td font-mono text-[12px] text-amber-300">{num(r.reactivated)}</td>
                <td className="td text-[11px]">{r.error ? <span className="text-rose-300">{r.error.slice(0, 80)}{can('dojo.push') && !rows.some((x) => x.id > r.id && !x.error && x.test_title === r.test_title) && <button className="btn-ghost ml-2" disabled={busy === r.id} onClick={() => retry(r.id)}>{busy === r.id ? 'Wysyłanie…' : 'Ponów'}</button>}</span> : <span className="text-emerald-300">OK</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}
