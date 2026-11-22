import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { GitCompare, Download, Info } from 'lucide-react';
import { useApi, useCan, Card, Badge, Spinner, ErrorBox, Empty, download, fmtDate, Interest } from '../lib.jsx';
import { PageHeader } from '../App.jsx';
import { ChangeIcon } from './Dashboard.jsx';
import { ServiceDrawer } from './Inventory.jsx';

const KIND = { new: ['nowa', 'green'], returned: ['wróciła', 'blue'], gone: ['zniknęła', 'red'], changed: ['zmieniona', 'amber'] };

const KIND_LABEL = { harmonogram: 'harmonogram', doskanowanie: 'doskanowanie', 'ręczny': 'ręczny', import: 'import' };
const TILES = [['hosts_new', 'nowe hosty', 'text-emerald-300'], ['hosts_returned', 'powróciły hosty', 'text-sky-300'], ['hosts_gone', 'zniknęły hosty', 'text-rose-300'], ['services_new', 'nowe usługi', 'text-emerald-300', 'new'], ['services_returned', 'powracające usługi', 'text-sky-300', 'returned'], ['services_gone', 'znikające usługi', 'text-rose-300', 'gone'], ['services_changed', 'zmienione usługi', 'text-amber-300', 'changed']];
const isToday = (iso) => { const t = new Date(iso || ''); const n = new Date(); return !isNaN(t) && t.toDateString() === n.toDateString(); };
const optLabel = (s) => `${s.label} · ${KIND_LABEL[s.kind] || s.kind}${s.kind === 'doskanowanie' && isToday(s.started_at || s.created_at) ? ' · trwa dziś (najświeższe rekordy)' : ''}`;

export default function Diff() {
  const [sp, setSp] = useSearchParams();
  const scans = useApi('/scans', [], 15000);
  const can = useCan();
  const all = (scans.data || []).filter((s) => s.status === 'completed' || s.kind === 'doskanowanie');
  // w wyborze tylko reguły, które nadal istnieją; skany usuniętych reguł są dostępne w „wszystkie reguły” z dopiskiem (usunięta)
  const rules = [...new Map(all.filter((s) => s.config_id && !s.rule_deleted).map((s) => [String(s.config_id), s.rule])).entries()];
  const [rule, setRule] = useState(sp.get('rule') || '');
  const [a, setA] = useState(sp.get('a') || '');
  const [b, setB] = useState(sp.get('b') || '');
  const [kind, setKind] = useState('');
  const [sel, setSel] = useState(null);
  const list = rule ? all.filter((s) => String(s.config_id) === rule) : all;
  // domyślnie: najnowsza reguła; B = najnowszy skan (trwające doskanowanie, jeśli jest), A = poprzedni skan tej reguły
  useEffect(() => {
    if (!a && !b && all.length) {
      const r = rule || String((all.find((x) => !x.rule_deleted) || all[0]).config_id || '');
      const l = all.filter((s) => !r || String(s.config_id) === r);
      if (l.length >= 2) { setRule(r); setB(String(l[0].id)); setA(String(l[1].id)); }
    }
  }, [all.length]); // eslint-disable-line
  useEffect(() => { if (a && b) setSp({ ...(rule ? { rule } : {}), a, b }, { replace: true }); }, [a, b, rule]); // eslint-disable-line
  const sa = all.find((s) => String(s.id) === a), sb = all.find((s) => String(s.id) === b);
  const live = [sa, sb].some((s) => s && s.kind === 'doskanowanie' && isToday(s.started_at || s.created_at));
  const d = useApi(a && b ? `/diff?a=${a}&b=${b}` : null, [a, b, live], live ? 15000 : 0);
  const r = d.data ? { ...d.data, hosts: d.data.hosts || [], services: d.data.services || [], notes: d.data.notes || [], summary: d.data.summary || {} } : null;
  const pick = (setter) => (e) => setter(e.target.value);
  return (
    <div>
      <PageHeader title="Zmiany" sub="Co zmieniło się między dwoma skanami: nowe, znikające, powracające i zmienione usługi oraz hosty. Porównywane są tylko adresy i porty objęte oboma skanami.">
        {r && can('data.export') && <><button className="btn-ghost" onClick={() => download(`/export/diff?a=${a}&b=${b}&format=csv`)}><Download size={13} /> CSV</button><button className="btn-ghost" onClick={() => download(`/export/diff?a=${a}&b=${b}&format=json`)}><Download size={13} /> JSON</button></>}
      </PageHeader>

      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
        {TILES.map(([k, l, t, kk]) => (
          <button key={k} onClick={() => kk && setKind(kind === kk ? '' : kk)} className={`card p-3 text-left ${kind && kind === kk ? 'ring-1 ring-accent/60' : ''}`}>
            <div className={`font-mono text-2xl font-bold ${t}`}>{r ? (r.summary[k] || 0) : '–'}</div><div className="text-[10px] uppercase tracking-wider text-slate-500">{l}</div>
          </button>
        ))}
      </div>

      <Card className="mb-5">
        <div className="grid grid-cols-1 items-end gap-4 lg:grid-cols-[minmax(180px,.7fr)_1fr_auto_1fr]">
          <label><span className="label">Reguła</span>
            <select className="input" value={rule} onChange={(e) => { setRule(e.target.value); setA(''); setB(''); }}>
              <option value="">wszystkie reguły</option>{rules.map(([id, n]) => <option key={id} value={id}>{n}</option>)}
            </select></label>
          <label><span className="label">Skan bazowy (A)</span><select className="input" value={a} onChange={pick(setA)}><option value="">wybierz…</option>{list.map((s) => <option key={s.id} value={s.id}>{optLabel(s)}</option>)}</select></label>
          <GitCompare className="mb-2 hidden text-slate-500 lg:block" size={20} />
          <label><span className="label">Skan porównywany (B)</span><select className="input" value={b} onChange={pick(setB)}><option value="">wybierz…</option>{list.map((s) => <option key={s.id} value={s.id}>{optLabel(s)}</option>)}</select></label>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3 text-[11px] text-slate-500">
          {r && <span>Porównano <b className="text-slate-300">{r.compared_ips}</b> adresów · porty: <span className="font-mono">{r.compared_ports || 'wszystkie'}</span></span>}
          {live && <span className="flex items-center gap-1.5 text-emerald-300"><span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400 shadow-[0_0_8px_#4ade80]" /> na żywo: doskanowanie trwa, porównanie z najświeższymi rekordami, odświeżane co 15 s</span>}
        </div>
      </Card>

      {rule && <Timeline rule={rule} a={a} b={b} onPick={(x, y) => { setA(String(x)); setB(String(y)); }} />}

      {!a || !b ? <Card><Empty>Wybierz regułę i dwa skany do porównania.</Empty></Card> : d.loading && !r ? <Spinner /> : d.error ? <ErrorBox msg={d.error} /> : r && (
        <>
          {r.notes?.length > 0 && <div className="mb-4 space-y-1">{r.notes.map((n, i) => <div key={i} className="flex items-center gap-2 rounded-lg border border-sky-500/20 bg-sky-500/5 px-3 py-2 text-[12px] text-sky-200"><Info size={13} /> {n}</div>)}</div>}
          <div className="grid gap-5 xl:grid-cols-3">
            <Card title="Zmiany usług" icon={GitCompare} pad={false} className="xl:col-span-2">
              {!r.services.length ? <Empty>Brak zmian usług.</Empty> : (
                <table className="w-full">
                  <thead><tr className="border-b border-white/5"><th className="th"></th><th className="th">Usługa</th><th className="th">Produkt / tytuł</th><th className="th">Szczegóły zmiany</th><th className="th">Ciekawość</th></tr></thead>
                  <tbody>
                    {r.services.filter((c) => !kind || c.kind === kind).map((c, i) => (
                      <tr key={i} onClick={() => setSel(c.obs_id)} className="cursor-pointer border-b border-white/[.03] hover:bg-white/[.02]">
                        <td className="td"><ChangeIcon kind={c.kind} /></td>
                        <td className="td whitespace-nowrap"><div className="font-mono text-slate-100">{c.ip}:{c.port}/{c.proto}</div><Badge tone={KIND[c.kind][1]}>{KIND[c.kind][0]}</Badge></td>
                        <td className="td"><div className="text-[12px] text-slate-300">{c.product || c.service}</div><div className="max-w-[240px] truncate text-[11px] text-slate-500">{c.title}</div></td>
                        <td className="td">{(c.changes || []).map((x, j) => <div key={j} className="text-[11px]"><span className="text-slate-500">{x.field}:</span> <span className="text-rose-300/80 line-through">{x.before || '∅'}</span> → <span className="text-emerald-300">{x.after || '∅'}</span></div>)}</td>
                        <td className="td"><Interest v={c.interest} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
            <Card title="Zmiany hostów" pad={false}>
              {!r.hosts.length ? <Empty>Brak zmian hostów.</Empty> : (
                <div className="divide-y divide-white/[.04]">
                  {r.hosts.map((h, i) => <div key={i} className="flex items-center gap-3 px-4 py-2"><ChangeIcon kind={h.kind} /><span className="font-mono text-[12px] text-slate-200">{h.ip}</span><span className="text-[11px] text-slate-500">{h.kind === 'new' ? 'nowy host' : h.kind === 'returned' ? 'wrócił (widziany wcześniej)' : 'przestał odpowiadać'}</span></div>)}
                </div>
              )}
            </Card>
          </div>
        </>
      )}
      <ServiceDrawer id={sel} onClose={() => setSel(null)} />
    </div>
  );
}

// Oś czasu zmian reguły: jeden słupek = różnica między dwoma kolejnymi skanami (nowe, powracające, zmienione, znikające).
const TL = [['services_new', 'nowe', 'var(--ok, #10B981)'], ['services_returned', 'powracające', '#38bdf8'], ['services_changed', 'zmienione', 'var(--warn, #F59E0B)'], ['services_gone', 'znikające', 'var(--bad, #EF4444)']];
function Timeline({ rule, a, b, onPick }) {
  const t = useApi(`/diff/timeline?config=${rule}&n=12`, [rule]);
  const pts = t.data || [];
  if (pts.length < 2) return null;
  const tot = (p) => TL.reduce((n, [k]) => n + (p.summary[k] || 0), 0);
  const peak = Math.max(1, ...pts.map(tot));
  return (
    <Card title="Oś Czasu Zmian" icon={GitCompare} className="mb-5" actions={<div className="flex gap-3 text-[11px] text-slate-400">{TL.map(([k, l, c]) => <span key={k} className="flex items-center gap-1"><span className="inline-block h-2 w-2" style={{ background: c }} />{l}</span>)}</div>}>
      <div className="flex h-28 items-end gap-2">
        {pts.map((p) => {
          const sel = String(p.a) === a && String(p.b) === b;
          return (
            <button key={p.b} onClick={() => onPick(p.a, p.b)} title={`#${p.a} → #${p.b}: ${TL.map(([k, l]) => `${l} ${p.summary[k] || 0}`).join(', ')}`}
              className={`flex h-full min-w-0 flex-1 flex-col items-stretch justify-end ${sel ? 'outline outline-1 outline-offset-2 outline-[color:var(--accent)]' : ''}`}>
              <span className="mb-1 text-center font-mono text-[11px] text-slate-400" title={p.compared_ips ? '' : 'Skany nie mają wspólnych adresów (inny zakres celów): porównanie niemiarodajne'}>{p.compared_ips ? tot(p) : '≠ zakres'}</span>
              <span className="flex flex-col-reverse" style={{ height: `${Math.max(2, (tot(p) / peak) * 80)}%` }}>
                {TL.map(([k, , c]) => (p.summary[k] ? <span key={k} style={{ background: c, flexGrow: p.summary[k] }} /> : null))}
                {!tot(p) && <span className="h-[2px] bg-slate-600" />}
              </span>
              <span className="mt-1 truncate text-center text-[10px] text-slate-500">{fmtDate(p.at)}</span>
            </button>
          );
        })}
      </div>
    </Card>
  );
}
