import { useEffect, useState } from 'react';
import { Scale, Plus, Trash2, Check, RefreshCw, ShieldCheck, Search } from 'lucide-react';
import { api, useApi, useCan, useToast, Card, Badge, Spinner, ErrorBox, Empty, Toggle, Field, num, fmtDate } from '../lib.jsx';
import { PageHeader } from '../App.jsx';

const KIND = { signature: ['sygnatura', 'blue'], heuristic: ['reguła ogólna', 'violet'], port: ['port', 'amber'] };
const TABS = [['all', 'Wszystkie'], ['signature', 'Sygnatury'], ['heuristic', 'Reguły ogólne'], ['port', 'Porty'], ['new', 'Nowe do oceny']];

function WeightInput({ rule, onSave, disabled }) {
  const [v, setV] = useState(rule.weight);
  useEffect(() => setV(rule.weight), [rule.weight]);
  return (
    <input type="number" min={0} max={100} value={v} disabled={disabled} onChange={(e) => setV(e.target.value)}
      onBlur={() => Number(v) !== rule.weight && onSave(Number(v))} onKeyDown={(e) => e.key === 'Enter' && e.currentTarget.blur()}
      className="input w-20 py-1 text-center font-mono" />
  );
}

export default function Rules() {
  const { data, error, loading, reload } = useApi('/rules');
  const can = useCan();
  const toast = useToast();
  const [tab, setTab] = useState('all');
  const [q, setQ] = useState('');
  const [np, setNp] = useState({ port: '', proto: 'tcp', weight: 10, name: '' });
  const allowed = useApi('/settings/allowed-ports');
  const [ap, setAp] = useState('');
  useEffect(() => { if (allowed.data) setAp(allowed.data.ports || ''); }, [allowed.data]);
  const upd = async (r, body, msg) => {
    try { const res = await api(`/rules/${r.id}`, { method: 'PUT', body }); toast(`${msg} · przeliczono klasę ${num(res.rescored)} wyników`); reload(); } catch (e) { toast(e.message, 'err'); }
  };
  const del = async (r) => {
    if (!confirm(`Usunąć regułę ${r.name}?`)) return;
    try { await api(`/rules/${r.id}`, { method: 'DELETE' }); reload(); } catch (e) { toast(e.message, 'err'); }
  };
  const add = async () => {
    try { await api('/rules', { method: 'POST', body: { port: Number(np.port), proto: np.proto, weight: Number(np.weight), name: np.name } }); toast('Dodano regułę portu'); setNp({ ...np, port: '', name: '' }); reload(); } catch (e) { toast(e.message, 'err'); }
  };
  const saveAllowed = async () => {
    try { const r = await api('/settings/allowed-ports', { method: 'PUT', body: { ports: ap } }); setAp(r.ports); toast('Zapisano porty zatwierdzone'); } catch (e) { toast(e.message, 'err'); }
  };
  if (loading && !data) return <Spinner />;
  if (error) return <ErrorBox msg={error} />;
  const rules = data.rules.filter((r) => (tab === 'all' || (tab === 'new' ? r.auto && !r.reviewed : r.kind === tab)) && (!q || (r.name + ' ' + r.key).toLowerCase().includes(q.toLowerCase())));
  const newCount = data.rules.filter((r) => r.auto && !r.reviewed).length;
  return (
    <div>
      <PageHeader title="Reguły klasy" sub="Klasa usługi = suma wag dopasowanych reguł (maks. 100%). Zmiana wagi od razu przelicza klasę wszystkich zapisanych wyników, bez ponownego skanowania.">
        {can('signatures.update') && <button className="btn-ghost" onClick={async () => { const r = await api('/rules/rescore', { method: 'POST' }); toast(`Przeliczono ${num(r.rescored)} wyników`); }}><RefreshCw size={13} /> Przelicz klasy</button>}
      </PageHeader>

      <div className="mb-5 grid gap-4 lg:grid-cols-4">
        {[['Aktywne reguły', data.enabled], ['Sygnatury', data.rules.filter((r) => r.kind === 'signature').length], ['Reguły ogólne', data.rules.filter((r) => r.kind === 'heuristic').length], ['Porty (w tym nowe)', `${data.rules.filter((r) => r.kind === 'port').length} · ${newCount} nowych`]].map(([l, v]) => (
          <div key={l} className="card p-4"><div className="label">{l}</div><div className="font-mono text-2xl font-semibold text-slate-100">{v}</div></div>
        ))}
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-1">
        {TABS.map(([k, l]) => <button key={k} onClick={() => setTab(k)} className={tab === k ? 'btn-primary' : 'btn-ghost'}>{l}{k === 'new' && newCount > 0 && <span className="ml-1 rounded-sm bg-amber-400/20 px-1 text-amber-200">{newCount}</span>}</button>)}
        <div className="relative ml-auto"><Search size={13} className="absolute left-2.5 top-2.5 text-slate-500" /><input className="input w-56 py-1.5 pl-7" placeholder="szukaj reguły…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[1fr_340px]">
        <Card title={`Reguły · ${rules.length}`} icon={Scale} pad={false}>
          {!rules.length ? <Empty>Brak reguł w tym widoku.</Empty> : (
            <table className="rules-table w-full">
              <thead><tr><th className="th">Reguła</th><th className="th">Rodzaj</th><th className="th">Waga (pkt)</th><th className="th">Dopasowania</th><th className="th">Aktywna</th><th className="th"></th></tr></thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id} className={`border-b ${r.enabled ? '' : 'opacity-45'}`}>
                    <td className="td"><div className="text-slate-100">{r.name}</div><div className="font-mono text-[10px] text-slate-600">{r.key}{r.auto && ` · wykryty ${fmtDate(r.created_at)}`}</div></td>
                    <td className="td whitespace-nowrap"><span className="inline-flex flex-nowrap items-center gap-1.5"><Badge tone={KIND[r.kind][1]}>{KIND[r.kind][0]}</Badge>{r.auto && !r.reviewed && <Badge tone="amber">nowa · do oceny</Badge>}</span></td>
                    <td className="td"><WeightInput rule={r} disabled={!can('signatures.update')} onSave={(w) => upd(r, { weight: w }, `Waga „${r.name}”: ${w}`)} /></td>
                    <td className="td font-mono text-[12px] text-slate-300">{num(r.matches)}</td>
                    <td className="td"><Toggle checked={r.enabled} onChange={(v) => can('signatures.update') && upd(r, { enabled: v }, v ? 'Reguła włączona' : 'Reguła wyłączona')} /></td>
                    <td className="td whitespace-nowrap text-right">
                      {r.auto && !r.reviewed && can('signatures.update') && <button className="btn-ok" onClick={() => upd(r, { reviewed: true }, 'Oznaczono jako ocenioną')}><Check size={12} /> Ocenione</button>}{' '}
                      {r.kind === 'port' && can('signatures.delete') && <button className="btn-danger" onClick={() => del(r)}><Trash2 size={12} /></button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <div className="space-y-5">
          {can('signatures.create') && (
            <Card title="Dodaj regułę portu" icon={Plus}>
              <div className="grid grid-cols-[1fr_90px] gap-2">
                <Field label="Port"><input className="input font-mono" type="number" value={np.port} onChange={(e) => setNp({ ...np, port: e.target.value })} placeholder="np. 3389" /></Field>
                <Field label="Protokół"><select className="input" value={np.proto} onChange={(e) => setNp({ ...np, proto: e.target.value })}><option value="tcp">tcp</option><option value="udp">udp</option></select></Field>
                <Field label="Nazwa (opcjonalnie)" className="col-span-2"><input className="input" value={np.name} onChange={(e) => setNp({ ...np, name: e.target.value })} placeholder="np. Pulpit zdalny wystawiony" /></Field>
                <Field label="Waga (pkt)" className="col-span-2"><input className="input font-mono" type="number" value={np.weight} onChange={(e) => setNp({ ...np, weight: e.target.value })} /></Field>
              </div>
              <button className="btn-primary mt-3" onClick={add} disabled={!np.port}><Plus size={13} /> Dodaj</button>
            </Card>
          )}
          <Card title="Jak liczona jest klasa" icon={Scale}>
            <ul className="space-y-1.5 text-[12px] leading-relaxed text-slate-400">
              <li><b className="text-slate-200">Sygnatura:</b> waga × pewność wykrycia (połowa dla każdej + połowa najwyższej).</li>
              <li><b className="text-slate-200">Reguła ogólna:</b> pełna waga, gdy warunek spełniony (np. wygasły certyfikat).</li>
              <li><b className="text-slate-200">Port:</b> pełna waga, gdy port jest otwarty. Nowe porty dopisują się same z wagą 0 i znacznikiem „do oceny”, więc nie zmieniają klasy, dopóki ich nie ocenisz.</li>
              <li>Przy usłudze widać też pokrycie: ile reguł trafiła z wszystkich aktywnych.</li>
            </ul>
          </Card>
          <Card title="Porty zatwierdzone (auto-rozszerzanie)" icon={ShieldCheck}>
            <p className="mb-2 text-[12px] leading-relaxed text-slate-400">Konfiguracja skanu z włączoną (domyślnie wyłączoną) opcją „dopisuj wykryte porty” może dodać do swojej listy tylko porty z tego zakresu. Puste pole = nic nie jest dopisywane.</p>
            <input className="input font-mono" value={ap} onChange={(e) => setAp(e.target.value)} disabled={!can('settings.manage')} placeholder="np. 1-1024,3000,8000-8999" />
            {can('settings.manage') && <button className="btn-primary mt-2" onClick={saveAllowed}>Zapisz</button>}
          </Card>
        </div>
      </div>
    </div>
  );
}
