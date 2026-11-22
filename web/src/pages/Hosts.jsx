import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Search, Network, Clock, Save, Tag } from 'lucide-react';
import { api, useApi, useCan, useToast, Card, Badge, State, Spinner, ErrorBox, Empty, Drawer, HistoryBar, Field, TagInput, fmtDate, useDebounced, Interest } from '../lib.jsx';
import { PageHeader } from '../App.jsx';
import { ServicesTable, ServiceDrawer } from './Inventory.jsx';

const VIEWS = [
  ['active', 'Aktywne', 'Hosty widziane w skanie w ciągu ostatnich 24 godzin.'],
  ['unstable', 'Niestabilne', 'Hosty widziane w ciągu ostatnich 24 godzin, ale niewidoczne w skanach nocnych (22:00–06:00): pojawiają się tylko w oknie dziennym (np. stacje robocze, urządzenia wyłączane na noc).'],
  ['down', 'Niedostępne', 'Hosty niewidziane w skanie dłużej niż 48 godzin (albo nigdy). Doskaner sprawdza je w ciągu dnia po kolei.'],
];
const DAY = 86400000;
const ago = (iso) => {
  const t = Date.parse(iso || '');
  if (isNaN(t)) return null;
  const m = Math.floor((Date.now() - t) / 60000);
  return m < 60 ? `${m} min temu` : m < 1440 ? `${Math.floor(m / 60)} h temu` : `${Math.floor(m / 1440)} dni temu`;
};

export default function Hosts() {
  const [sp, setSp] = useSearchParams();
  const [q, setQ] = useState('');
  const view = VIEWS.some(([k]) => k === sp.get('view')) ? sp.get('view') : 'active';
  const dq = useDebounced(q);
  const { data, error, loading } = useApi(`/hosts?view=${view}&q=${encodeURIComponent(dq)}`, [view, dq], 20000);
  const counts = useApi('/hosts-views', [], 20000).data || {};
  const [sel, setSel] = useState(null);
  const [limit, setLimit] = useState(300);
  return (
    <div>
      <PageHeader title="Hosty" sub="Aktywne, niestabilne (tylko w dzień) i niedostępne (ponad 48 h) hosty z historią obecności i profilem pory dnia" />
      <Card pad={false}>
        <div className="flex flex-wrap items-center gap-2 border-b border-white/5 p-3">
          <div className="relative min-w-[240px] flex-1">
            <Search size={14} className="absolute left-3 top-2.5 text-slate-500" />
            <input className="input pl-8" placeholder="IP, nazwa hosta, tag…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <div className="flex gap-1">
            {VIEWS.map(([k, l]) => <button key={k} onClick={() => setSp({ view: k })} className={`${view === k ? 'btn-primary' : 'btn-ghost'} px-4 text-[13px] font-extrabold tracking-wide`}>{l}{counts[k] != null && ` (${counts[k]})`}</button>)}
          </div>
        </div>
        <p className="px-4 pt-3 text-[11px] text-slate-500">{VIEWS.find(([k]) => k === view)[2]}</p>
        {loading && !data ? <Spinner /> : error ? <div className="p-3"><ErrorBox msg={error} /></div> : !data.length ? <Empty>{view === 'down' ? 'Wszystkie znane hosty były widziane w ciągu ostatnich 48 godzin.' : view === 'unstable' ? 'Brak hostów widocznych tylko w dzień (potrzebny co najmniej jeden skan nocny).' : 'Brak hostów widzianych w ciągu ostatnich 24 godzin.'}</Empty> : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead><tr className="border-b border-white/5"><th className="th">Host</th><th className="th">Stan</th><th className="th">Obecność w skanach</th><th className="th">Dodano / ostatnio widziany</th><th className="th">Usługi</th><th className="th">Max ciekawość</th>{view === 'unstable' ? <><th className="th">Noc (odp./pomiary)</th><th className="th">Dzień (odp./pomiary)</th></> : <th className="th">Pora dnia</th>}</tr></thead>
              <tbody>
                {data.slice(0, limit).map((h) => (
                  <tr key={h.ip} onClick={() => setSel(h.ip)} className="cursor-pointer border-b border-white/[.03] hover:bg-white/[.025]">
                    <td className="td"><div className="flex items-center gap-2 font-mono text-slate-100">{view === 'down' && <span title="niewidziany ponad 48 h" className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-rose-400/70 bg-rose-500/15 font-sans font-bold text-rose-300 shadow-[0_0_10px_rgba(244,63,94,.5)]">!</span>}{h.ip}</div>{h.hostname && <div className="text-[11px] text-slate-500">{h.hostname}</div>}
                      {h.annotation?.tags?.length > 0 && <div className="mt-1 flex gap-1">{h.annotation.tags.map((t) => <Badge key={t} tone="violet">{t}</Badge>)}</div>}</td>
                    <td className="td"><State s={h.state} />{h.miss_streak > 0 && <div className="mt-1 text-[10px] text-slate-500">{h.miss_streak}× bez odp.</div>}</td>
                    <td className="td"><HistoryBar h={h.history} /><div className="mt-1 text-[10px] text-slate-500">{h.seen_count}/{h.scan_count} skanów</div></td>
                    <td className="td text-[12px] text-slate-400"><time>{fmtDate(h.first_seen)}</time><br />{h.last_seen ? <><time>{fmtDate(h.last_seen)}</time>{view === 'down' && <div className="text-[10px] text-rose-300">{ago(h.last_seen)}</div>}</> : <span className="text-rose-300/80">nigdy</span>}{h.last_checked && h.last_checked !== h.last_seen && <div className="text-[10px] text-slate-600">sprawdzono <time>{fmtDate(h.last_checked)}</time></div>}</td>
                    <td className="td font-mono text-sm">{h.services}</td>
                    <td className="td"><Interest v={h.max_interest} /></td>
                    {view === 'unstable' ? <>
                      <td className="td font-mono text-[12px] font-bold text-rose-300">{h.night_scanned ? `${h.night_seen}/${h.night_scanned}` : '–'}</td>
                      <td className="td font-mono text-[12px] font-bold text-emerald-300">{h.day_scanned ? `${h.day_seen}/${h.day_scanned}` : '–'}</td>
                    </> : <td className="td text-[11px] text-slate-500">{h.day_pattern && <span className="flex items-center gap-1 text-sky-300"><Clock size={11} /> {h.day_pattern.split(';')[0].replace('odpowiada w godzinach: ', '')}</span>}</td>}
                  </tr>
                ))}
              </tbody>
            </table>
            {data.length > limit && <div className="p-3 text-center"><button className="btn-ghost" onClick={() => setLimit(limit + 500)}>Pokaż więcej ({data.length - limit})</button></div>}
            <div className="px-3 py-2 text-right text-[11px] text-slate-600">{data.length} hostów</div>
          </div>
        )}
      </Card>
      <HostDrawer ip={sel} onClose={() => setSel(null)} />
    </div>
  );
}

function HourChart({ seen = [], scanned = [] }) {
  if (scanned.length !== 24) return null;
  return (
    <div>
      <div className="flex h-20 items-end gap-[3px]">
        {scanned.map((s, h) => {
          const r = s ? seen[h] / s : null;
          return (
            <div key={h} className="flex h-full flex-1 flex-col justify-end" title={`${h}:00 · widoczny ${seen[h]}/${s}`}>
              <div className={`w-full rounded-t ${r === null ? 'bg-white/5' : r >= 0.75 ? 'bg-emerald-400/80' : r <= 0.25 ? 'bg-rose-500/60' : 'bg-amber-400/70'}`} style={{ height: r === null ? '6%' : `${Math.max(8, r * 100)}%` }} />
            </div>
          );
        })}
      </div>
      <div className="mt-1 flex justify-between font-mono text-[9px] text-slate-600"><span>00</span><span>06</span><span>12</span><span>18</span><span>23</span></div>
    </div>
  );
}

function HostDrawer({ ip, onClose }) {
  const { data, error, loading, reload } = useApi(ip ? `/hosts/${ip}` : null, [ip]);
  const can = useCan();
  const toast = useToast();
  const [svc, setSvc] = useState(null);
  const [ann, setAnn] = useState(null);
  const h = data?.host;
  if (h && !ann) setTimeout(() => setAnn({ tags: h.annotation?.tags || [], note: h.annotation?.note || '', owner: h.annotation?.owner || '', criticality: h.annotation?.criticality || 0 }));
  const save = async () => {
    try {
      await api('/annotations', { method: 'PUT', body: { entity: `host:${h.ip}`, ...ann, criticality: Number(ann.criticality) } });
      toast('Zapisano adnotację hosta');
      reload();
    } catch (e) { toast(e.message, 'err'); }
  };
  return (
    <Drawer open={!!ip} onClose={() => { setAnn(null); onClose(); }} title={`Host ${ip || ''}`}>
      {loading && !h ? <Spinner /> : error ? <ErrorBox msg={error} /> : h && (
        <div className="space-y-5">
          <div className="grid grid-cols-4 gap-3">
            <div className="card p-3"><div className="label">Stan</div><State s={h.state} /></div>
            <div className="card p-3"><div className="label">Wykryty</div><div className="font-mono text-sm">{h.seen_count}/{h.scan_count}</div></div>
            <div className="card p-3"><div className="label">Pierwszy raz</div><div className="text-[12px]"><time>{fmtDate(h.first_seen)}</time></div></div>
            <div className="card p-3"><div className="label">Ostatnio</div><div className="text-[12px]"><time>{fmtDate(h.last_seen)}</time></div></div>
          </div>
          <Card title="Obecność wg godziny (zależność od pory dnia)" icon={Clock}>
            <HourChart seen={h.hours_seen} scanned={h.hours_scanned} />
            <div className="mt-2 text-[12px] text-slate-400">{h.day_pattern || 'Brak wyraźnej zależności od pory dnia (potrzeba skanów o różnych godzinach).'}</div>
            <div className="mt-3"><HistoryBar h={h.history} /></div>
          </Card>
          <Card title={`Usługi (${data.services.length})`} icon={Network} pad={false}><ServicesTable rows={data.services} onOpen={setSvc} /></Card>
          <Card title="Przebiegi skanów" pad={false}>
            <table className="w-full"><tbody>
              {data.scans.map((s) => (
                <tr key={s.scan_id} className="border-b border-white/[.03]"><td className="td font-mono text-[11px] text-slate-500">#{s.scan_id}</td><td className="td text-[12px]"><time>{fmtDate(s.started_at)}</time></td>
                  <td className="td">{s.alive ? <Badge tone="green">odpowiada</Badge> : <Badge tone="red">brak odp.</Badge>} {s.retried && <Badge tone="violet">ponowny pomiar</Badge>}</td><td className="td font-mono text-[11px] text-slate-500">{s.reason}</td></tr>
              ))}
            </tbody></table>
          </Card>
          {ann && (
            <Card title="Adnotacja hosta" icon={Tag}>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Tagi" className="col-span-2"><TagInput value={ann.tags} onChange={(t) => setAnn({ ...ann, tags: t })} /></Field>
                <Field label="Właściciel"><input className="input" value={ann.owner} onChange={(e) => setAnn({ ...ann, owner: e.target.value })} /></Field>
                <Field label="Ważność (0–5)"><input className="input" type="number" value={ann.criticality} onChange={(e) => setAnn({ ...ann, criticality: e.target.value })} /></Field>
                <Field label="Notatka" className="col-span-2"><textarea className="input" rows={2} value={ann.note} onChange={(e) => setAnn({ ...ann, note: e.target.value })} /></Field>
              </div>
              {can('results.update') && <button className="btn-primary mt-3" onClick={save}><Save size={13} /> Zapisz</button>}
            </Card>
          )}
        </div>
      )}
      <ServiceDrawer id={svc} onClose={() => setSvc(null)} />
    </Drawer>
  );
}
