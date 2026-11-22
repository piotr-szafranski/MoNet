import { useRef, useState } from 'react';
import { Crosshair, Plus, Upload, Download, Trash2, Pencil, Save, X, FileJson } from 'lucide-react';
import { api, useApi, useCan, useToast, Card, Badge, Spinner, ErrorBox, Empty, Field, TagInput, Toggle, download, num, fmtDate } from '../lib.jsx';
import { PageHeader } from '../App.jsx';

export default function Targets() {
  const { data, error, loading, reload } = useApi('/targets');
  const can = useCan();
  const toast = useToast();
  const [text, setText] = useState('');
  const [tags, setTags] = useState([]);
  const [note, setNote] = useState('');
  const [fileTags, setFileTags] = useState([]);
  const [result, setResult] = useState(null);
  const [edit, setEdit] = useState(null);
  const [filter, setFilter] = useState('');
  const fileRef = useRef();

  const add = async () => {
    try {
      const r = await api('/targets', { method: 'POST', body: { text, tags, note } });
      setResult(r);
      toast(`Dodano ${r.added}, duplikaty ${r.duplicates}, błędne ${r.invalid}`);
      setText('');
      reload();
    } catch (e) { toast(e.message, 'err'); }
  };
  const upload = async (f) => {
    if (!f) return;
    const fd = new FormData();
    fd.append('file', f);
    fd.append('tags', fileTags.join(','));
    try {
      const r = await api('/targets/import', { method: 'POST', body: fd });
      setResult(r);
      toast(`Plik ${f.name}: dodano ${r.added} z ${r.rows} wierszy`);
      reload();
    } catch (e) { toast(e.message, 'err'); }
    fileRef.current.value = '';
  };
  const save = async () => {
    try {
      await api(`/targets/${edit.id}`, { method: 'PUT', body: { value: edit.value, tags: edit.tags, note: edit.note, enabled: edit.enabled } });
      toast('Zapisano cel');
      setEdit(null);
      reload();
    } catch (e) { toast(e.message, 'err'); }
  };
  const toggle = async (t) => {
    await api(`/targets/${t.id}`, { method: 'PUT', body: { enabled: !t.enabled } }).catch((e) => toast(e.message, 'err'));
    reload();
  };
  const del = async (t) => {
    if (!confirm(`Usunąć cel ${t.value}?`)) return;
    await api(`/targets/${t.id}`, { method: 'DELETE' }).catch((e) => toast(e.message, 'err'));
    reload();
  };
  const list = (data?.targets || []).filter((t) => !filter || (t.value + ' ' + t.tags.join(' ') + ' ' + t.note).toLowerCase().includes(filter.toLowerCase()));

  return (
    <div>
      <PageHeader title="Cele skanowania" sub="Adresy IP, zakresy CIDR (np. 10.0.0.0/16), zakresy od-do (10.0.0.1-50) i domeny. Wpis ręczny i import są przetwarzane tak samo.">
        {can('data.export') && <>
          <button className="btn-ghost" onClick={() => download('/export/targets?format=csv')}><Download size={13} /> CSV</button>
          <button className="btn-ghost" onClick={() => download('/export/targets?format=json')}><Download size={13} /> JSON</button>
        </>}
      </PageHeader>

      {can('targets.create') && (
        <div className="mb-5 grid gap-5 lg:grid-cols-2">
          <Card title="Wprowadzenie ręczne" icon={Plus}>
            <Field label="Cele (jeden na linię albo po przecinku)">
              <textarea className="input font-mono" rows={5} value={text} onChange={(e) => setText(e.target.value)} placeholder={'10.66.0.0/18\n192.168.10.1-50\nportal.uczelnia.pl'} />
            </Field>
            <div className="mt-3 grid grid-cols-2 gap-3">
              <Field label="Tagi"><TagInput value={tags} onChange={setTags} /></Field>
              <Field label="Notatka (szyfrowana)"><input className="input" value={note} onChange={(e) => setNote(e.target.value)} /></Field>
            </div>
            <button className="btn-primary mt-3" onClick={add} disabled={!text.trim()}><Plus size={13} /> Dodaj cele</button>
          </Card>
          <Card title="Import z pliku CSV / JSON" icon={Upload}>
            <p className="mb-3 text-[12px] leading-relaxed text-slate-400">
              <b>CSV</b>: kolumna <code className="text-accent-soft">value</code> (lub ip / cidr / domain / target), opcjonalnie <code className="text-accent-soft">tags</code> (rozdzielone |) i <code className="text-accent-soft">note</code>; bez nagłówka pierwsza kolumna to cel.<br />
              <b>JSON</b>: <code className="text-accent-soft">["10.0.0.1", …]</code> albo <code className="text-accent-soft">[{'{'}"value": "10.0.0.0/24", "tags": ["dmz"]{'}'}]</code>.
            </p>
            <Field label="Tagi dla wszystkich celów z pliku"><TagInput value={fileTags} onChange={setFileTags} /></Field>
            <input ref={fileRef} type="file" accept=".csv,.json,.txt" className="hidden" onChange={(e) => upload(e.target.files[0])} />
            <button className="btn-primary mt-3" onClick={() => fileRef.current.click()}><FileJson size={13} /> Wybierz plik</button>
            {result && (
              <div className="mt-3 rounded-lg border border-white/5 bg-white/[.02] p-3 text-[12px]">
                <span className="text-emerald-300">dodano {result.added}</span> · <span className="text-slate-400">duplikaty {result.duplicates}</span> · <span className="text-amber-300">błędne {result.invalid}</span>
                {result.warnings?.length > 0 && <ul className="mt-1 list-disc pl-4 text-amber-300/80">{result.warnings.slice(0, 8).map((e, i) => <li key={i}>{e}</li>)}</ul>}
                {result.errors?.length > 0 && <ul className="mt-1 list-disc pl-4 text-rose-300/80">{result.errors.slice(0, 8).map((e, i) => <li key={i}>{e}</li>)}</ul>}
              </div>
            )}
          </Card>
        </div>
      )}

      <Card title={`Lista celów · ${num(data?.total_addresses)} adresów w aktywnych celach`} icon={Crosshair} pad={false}
        actions={<input className="input w-60" placeholder="filtruj…" value={filter} onChange={(e) => setFilter(e.target.value)} />}>
        {loading && !data ? <Spinner /> : error ? <div className="p-3"><ErrorBox msg={error} /></div> : !list.length ? <Empty>Brak celów.</Empty> : (
          <table className="w-full">
            <thead><tr className="border-b border-white/5"><th className="th">Cel</th><th className="th">Typ</th><th className="th">Adresów</th><th className="th">Tagi</th><th className="th">Notatka</th><th className="th">Dodano / zmieniono</th><th className="th">Aktywny</th><th className="th"></th></tr></thead>
            <tbody>
              {list.map((t) => edit?.id === t.id ? (
                <tr key={t.id} className="border-b border-white/[.03] bg-white/[.02]">
                  <td className="td"><input className="input font-mono" value={edit.value} onChange={(e) => setEdit({ ...edit, value: e.target.value })} /></td>
                  <td className="td" colSpan={2}><Badge>{t.kind}</Badge></td>
                  <td className="td"><TagInput value={edit.tags} onChange={(v) => setEdit({ ...edit, tags: v })} /></td>
                  <td className="td"><input className="input" value={edit.note} onChange={(e) => setEdit({ ...edit, note: e.target.value })} /></td>
                  <td className="td" />
                  <td className="td"><Toggle checked={edit.enabled} onChange={(v) => setEdit({ ...edit, enabled: v })} /></td>
                  <td className="td whitespace-nowrap"><button className="btn-primary" onClick={save}><Save size={12} /></button> <button className="btn-ghost" onClick={() => setEdit(null)}><X size={12} /></button></td>
                </tr>
              ) : (
                <tr key={t.id} className={`border-b border-white/[.03] ${t.enabled ? '' : 'opacity-50'}`}>
                  <td className="td font-mono text-slate-100">{t.value}</td>
                  <td className="td"><Badge tone="blue">{t.kind}</Badge></td>
                  <td className="td font-mono text-[12px] text-slate-400">{num(t.addresses)}</td>
                  <td className="td"><div className="flex flex-wrap gap-1">{t.tags.map((x) => <Badge key={x} tone="violet">{x}</Badge>)}</div></td>
                  <td className="td max-w-[220px] truncate text-[12px] text-slate-400">{t.note}</td>
                  <td className="td whitespace-nowrap font-mono text-[11px] leading-relaxed text-slate-400"><div><span className="text-slate-600">dodano </span><time>{fmtDate(t.created_at)}</time>{t.created_by && <span className="text-slate-600"> · {t.created_by}</span>}</div><div><span className="text-slate-600">zmiana </span><time>{fmtDate(t.updated_at)}</time></div><div className="text-slate-600">{t.source}</div></td>
                  <td className="td"><Toggle checked={t.enabled} onChange={() => can('targets.update') && toggle(t)} /></td>
                  <td className="td whitespace-nowrap text-right">
                    {can('targets.update') && <button className="btn-ghost" onClick={() => setEdit({ ...t })}><Pencil size={12} /></button>}{' '}
                    {can('targets.delete') && <button className="btn-danger" onClick={() => del(t)}><Trash2 size={12} /></button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
