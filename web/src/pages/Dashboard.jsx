import { useNavigate } from 'react-router-dom';
import { Activity, AlertTriangle, GitCompare, Radar, Server, Network, Sparkles, Clock, Waves, Layers, Plus, Minus, RefreshCw, Undo2 } from 'lucide-react';
import { useApi, CategoryTable, Card, Stat, Badge, Flag, Interest, State, Spinner, ErrorBox, Empty, HBar, TallBars, Bars, Progress, BigProgress, HistoryBar, fmtDate, fmtDur, num, flagLabel } from '../lib.jsx';
import { useState } from 'react';
import { ServiceDrawer } from './Inventory.jsx';

export default function Dashboard() {
  const { data: d, error, loading } = useApi('/dashboard', [], 10000);
  const svcs = useApi('/services?hide_fp=1', [], 30000);
  const review = useApi('/technologies/review', [], 30000);
  const nav = useNavigate();
  const [svc, setSvc] = useState(null);
  if (loading && !d) return <Spinner />;
  if (error) return <ErrorBox msg={error} />;
  const hs = d.host_states || {};
  const ss = d.service_states || {};
  const hv = d.host_views || {};
  const activeHosts = hv.active != null ? (hv.active || 0) + (hv.unstable || 0) : (hs.active || 0) + (hs.unstable || 0) + (hs.missing || 0);
  const diff = d.latest_diff ? { ...d.latest_diff, hosts: d.latest_diff.hosts || [], services: d.latest_diff.services || [], summary: d.latest_diff.summary || {} } : null;
  const flags = Object.entries(d.flags || {}).map(([k, v]) => ({ k, v, label: flagLabel[k] || k })).sort((a, b) => b.v - a.v).slice(0, 10);
  const cats = Object.entries(d.categories || {}).map(([k, v]) => ({ k, v })).sort((a, b) => b.v - a.v).slice(0, 10);
  const techs = Object.entries(d.technologies || {}).map(([k, v]) => ({ k, v })).sort((a, b) => b.v - a.v).slice(0, 12);
  const interesting = d.interesting_count ?? 0;

  return (
    <div>

      {(d.active_scans || []).length > 0 && (
        <Card title="Skanowanie…" icon={Radar} className="mb-5">
          <div className="space-y-3">
            {d.active_scans.map((s) => (
              <button key={s.id} onClick={() => nav(`/scans/${s.id}`)} className="block w-full text-left">
                <div className="mb-1 flex items-center justify-between text-sm">
                  <span className="flex items-center gap-2 text-slate-200"><State s={s.status} /> {s.label || s.name}</span>
                  <span className="font-mono text-xs text-slate-500">{num(s.done_ips)} / {num(s.total_ips)} IP · {fmtDur(s.elapsed_ms)} · {s.live.rate_ips ? `${s.live.rate_ips.toFixed(1)} IP/s/worker` : ''}</span>
                </div>
                <BigProgress value={s.done_ips} total={s.total_ips} tone={s.status === 'paused' ? 'amber' : 'accent'} />
              </button>
            ))}
          </div>
        </Card>
      )}

      <VerdictBar
        high={(svcs.data || []).filter((o) => (o.interest || 0) >= 50).length}
        fresh={diff ? ['hosts_new', 'hosts_returned', 'hosts_gone', 'services_new', 'services_returned', 'services_gone', 'services_changed'].reduce((n, k) => n + (diff.summary[k] || 0), 0) : 0}
        techNew={review.data?.count || 0}
        down={hv.down || 0}
        hosts={activeHosts} services={(ss.active || 0) + (ss.unstable || 0) + (ss.missing || 0)} unstable={hv.unstable || 0}
        loading={!svcs.data} nav={nav} />

      <div className="grid gap-5 xl:grid-cols-3">
        <Card title="Ostatnie zmiany" icon={GitCompare} className="xl:col-span-2" actions={diff && <button className="btn-ghost" onClick={() => nav(`/diff?a=${diff.a.id}&b=${diff.b.id}`)}>Pełne porównanie</button>}>
          {!diff ? <Empty>Porównanie pojawi się po dwóch zakończonych skanach.</Empty> : (
            <>
              <div className="mb-3 text-[10px] font-medium uppercase tracking-[.2em] text-slate-400" title="Porównanie dwóch ostatnich skanów">Wykryte różnice</div>
              <div className="mb-4 grid grid-cols-3 gap-2 xl:grid-cols-6">
                {[['hosts_new', 'nowe hosty', 'text-emerald-300'], ['hosts_gone', 'zniknęły', 'text-rose-300'], ['services_new', 'nowe usługi', 'text-emerald-300'], ['services_returned', 'powróciły', 'text-sky-300'], ['services_gone', 'znikające usługi', 'text-rose-300'], ['services_changed', 'zmienione', 'text-amber-300']].map(([k, l, t]) => (
                  <div key={k} className="rounded-xl border border-white/5 bg-white/[.02] p-3">
                    <div className={`font-mono text-2xl font-semibold ${diff.summary[k] ? t : "text-slate-500"}`}>{diff.summary[k] || 0}</div>
                    <div className="text-[10px] uppercase tracking-wider text-slate-500">{l}</div>
                  </div>
                ))}
              </div>
              <div className="max-h-72 space-y-1 overflow-y-auto">
                {diff.services.map((c, i) => (
                  <button key={i} onClick={() => setSvc(c.obs_id)} className="flex w-full items-center gap-3 rounded-lg px-2 py-1.5 text-left hover:bg-white/[.03]">
                    <ChangeIcon kind={c.kind} />
                    <span className="w-44 font-mono text-[12px] text-slate-200">{c.ip}:{c.port}/{c.proto}</span>
                    <span className="flex-1 truncate text-[12px] text-slate-400">{c.product || c.service} {c.title && <span className="text-slate-500">· {c.title}</span>}</span>
                    {c.changes && <span className="truncate text-[11px] text-amber-300/80">{c.changes.map((x) => `${x.field}: ${x.before || '∅'} → ${x.after || '∅'}`).join('; ')}</span>}
                  </button>
                ))}
                {diff.hosts.map((h, i) => (
                  <div key={'h' + i} className="flex items-center gap-3 px-2 py-1.5">
                    <ChangeIcon kind={h.kind} /><span className="font-mono text-[12px] text-slate-300">host {h.ip}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </Card>

        <Card title="Aktywne flagi" icon={AlertTriangle} className="flex flex-col" bodyClass="flex-1">
          {flags.length ? <TallBars items={flags} color="bg-gradient-to-r from-[#2f7fd0] to-[#6cb6ff]" onClick={(f) => nav(`/inventory?flag=${f}`)} /> : <Empty>Brak danych</Empty>}
        </Card>

        <Card title="Usługi · kategorie" icon={Sparkles} className="xl:col-span-3" pad={false}>
          {!svcs.data ? <Spinner /> : !svcs.data.length ? <Empty>Brak wyników: uruchom skan.</Empty> : (
            <CategoryTable rows={svcs.data} onOpen={(g) => nav(`/inventory?cat=${g.k}`)} />
          )}
        </Card>



      </div>
      <ServiceDrawer id={svc} onClose={() => setSvc(null)} />
    </div>
  );
}

// Pasek werdyktu (DESIGN.md: znak rozpoznawczy): jedno zdanie decyzji + 4 liczby, które ją uzasadniają, + jedna akcja.
// Kolor tylko dla znaczenia: czerwony kwadrat = wymaga działania, liczba 0 = neutralna.
function VerdictBar({ high, fresh, techNew, down, hosts, services, unstable, loading, nav }) {
  const urgent = high > 0 || techNew > 0;
  const verdict = loading ? 'Liczenie…'
    : urgent ? `Wymaga uwagi: ${high} ${high === 1 ? 'usługa' : 'usług'} wysokiej klasy${techNew ? `, ${techNew} nowych technologii do oceny` : ''}`
      : fresh ? `Bez pilnych zagrożeń · ${fresh} zmian od ostatniego skanu` : 'Bez pilnych zagrożeń i bez zmian od ostatniego skanu';
  const cells = [
    { label: 'Usługi wysokiej klasy (≥ 50%)', v: high, alert: high > 0, go: '/inventory?cat=all&min=50' },
    { label: 'Zmiany od ostatniego skanu', v: fresh, alert: false, go: '/diff' },
    { label: 'Nowe technologie do oceny', v: techNew, alert: techNew > 0, go: '/technologies' },
    { label: 'Hosty niewidziane > 48 h', v: down, alert: false, go: '/hosts?view=down' },
  ];
  return (
    <section className="verdict mb-6">
      <div className="verdict-head">
        <div>
          <div className="verdict-kicker">Stan sieci</div>
          <h1 className="verdict-title">{verdict}</h1>
          <div className="verdict-ctx"><span>{num(hosts)}</span> aktywnych hostów · <span>{num(services)}</span> usług · <span>{num(unstable)}</span> widocznych tylko w dzień</div>
        </div>
        <button className="btn-run" onClick={() => nav(urgent ? (high ? '/inventory?cat=all&min=50' : '/technologies') : '/diff')}>
          {urgent ? (high ? 'Przejrzyj usługi wysokiej klasy' : 'Oceń nowe technologie') : 'Zobacz zmiany'} →
        </button>
      </div>
      <div className="verdict-cells">
        {cells.map((c) => (
          <button key={c.label} className="verdict-cell" onClick={() => nav(c.go)}>
            <span className="verdict-num">{c.alert && <i className="verdict-mark" aria-hidden />}{num(c.v)}</span>
            <span className="verdict-label">{c.label}{c.alert && <span className="sr-only"> (wymaga działania)</span>}</span>
          </button>
        ))}
      </div>
    </section>
  );
}

export function ChangeIcon({ kind }) {
  if (kind === 'new') return <span className="flex h-5 w-5 items-center justify-center rounded bg-emerald-500/15 text-emerald-300"><Plus size={12} /></span>;
  if (kind === 'returned') return <span className="flex h-5 w-5 items-center justify-center rounded bg-sky-500/15 text-sky-300"><Undo2 size={12} /></span>;
  if (kind === 'gone') return <span className="flex h-5 w-5 items-center justify-center rounded bg-rose-500/15 text-rose-300"><Minus size={12} /></span>;
  return <span className="flex h-5 w-5 items-center justify-center rounded bg-amber-500/15 text-amber-300"><RefreshCw size={11} /></span>;
}
