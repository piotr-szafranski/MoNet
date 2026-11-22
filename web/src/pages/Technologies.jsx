import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Layers, Cpu, Search, CalendarRange, Sparkles, AlertTriangle, CheckCircle2, Eye, EyeOff, ChevronLeft } from 'lucide-react';
import { api, useApi, useCan, useToast, Card, Badge, Spinner, ErrorBox, Empty, TallBars, num, fmtDate } from '../lib.jsx';
import { PageHeader } from '../App.jsx';

const CAT_LABEL = {
  server: 'Serwery WWW', appserver: 'Serwery aplikacyjne', 'admin-panel': 'Panele administracyjne', cms: 'CMS', iot: 'Urządzenia IoT',
  database: 'Bazy danych', devops: 'Narzędzia DevOps', staging: 'Środowiska testowe', interesting: 'Ciekawe artefakty',
  framework: 'Frameworki', language: 'Języki', proxy: 'Proxy / CDN', security: 'Bezpieczeństwo', other: 'Inne',
};

const today = () => new Date().toISOString().slice(0, 10);
const weekAgo = () => new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10);

const plural = (n) => (n === 1 ? 'nową technologię' : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 12 || n % 100 > 14) ? 'nowe technologie' : 'nowych technologii');

export default function Technologies() {
  const review = useApi('/technologies/review', [], 30000);
  const [reviewing, setReviewing] = useState(false);
  const pending = review.data?.count || 0;
  if (reviewing) return <TechReview data={review.data} reload={review.reload} onBack={() => setReviewing(false)} />;
  return <TechOverview pending={pending} onReview={() => setReviewing(true)} />;
}

// czerwony pasek na całą szerokość: „Wykryto N nowych technologii” → klik = klasyfikacja
function ReviewBanner({ n, onClick }) {
  if (!n) return null;
  return (
    <button onClick={onClick} className="mb-5 flex w-full items-center gap-3 rounded-2xl border border-rose-400/60 px-5 py-3.5 text-left transition hover:brightness-125"
      style={{ background: 'linear-gradient(90deg, rgba(244,63,94,.22), rgba(244,63,94,.08))', boxShadow: '0 0 24px -8px rgba(244,63,94,.7)' }}>
      <AlertTriangle size={18} className="shrink-0 text-rose-300" />
      <span className="font-display text-[15px] font-extrabold text-rose-200">Wykryto {n} {plural(n)}</span>
      <span className="text-[12px] text-rose-200/80">Kliknij, aby zaklasyfikować każdą z nich. Nic nie może zostać na później.</span>
      <span className="ml-auto rounded-full border border-rose-300/60 px-3 py-1 text-[12px] font-bold text-rose-100">Klasyfikuj →</span>
    </button>
  );
}

// tryb klasyfikacji: tylko nowe technologie, każda wymaga decyzji
function TechReview({ data, reload, onBack }) {
  const can = useCan();
  const toast = useToast();
  const [busy, setBusy] = useState('');
  const items = data?.items || [];
  const decide = async (t, decision) => {
    setBusy(t.id);
    try {
      await api(`/technologies/${encodeURIComponent(t.id)}/classify`, { method: 'POST', body: { decision } });
      toast(`${t.name}: ${decision === 'znana' ? 'znana' : decision === 'obserwuj' ? 'do obserwacji' : 'zignorowana'}`);
      window.dispatchEvent(new Event('monet-tech-review'));
      await reload();
    } catch (e) { toast(e.message, 'err'); }
    setBusy('');
  };
  return (
    <div>
      <PageHeader title="Nowe technologie do zaklasyfikowania" sub="Technologie, które pojawiły się w sieci po stanie wyjściowym. Każdą trzeba ocenić: znana (w porządku), do obserwacji (wymaga uwagi) albo ignoruj (szum). Decyzja trafia do dziennika logów.">
        <button className="btn-ghost" onClick={onBack}><ChevronLeft size={13} /> Wszystkie technologie</button>
      </PageHeader>
      {!items.length ? (
        <Card><div className="flex flex-col items-center gap-2 py-10 text-center"><CheckCircle2 size={34} className="text-emerald-300" /><div className="font-display text-[16px] font-extrabold text-white">Wszystko zaklasyfikowane</div><div className="text-[12px] text-slate-500">Nie ma nowych technologii czekających na decyzję.</div><button className="btn-primary mt-3" onClick={onBack}>Wróć do technologii</button></div></Card>
      ) : (
        <div className="space-y-3">
          <div className="text-[12px] text-slate-400">Zostało do zaklasyfikowania: <b className="text-rose-300">{items.length}</b></div>
          {items.map((t, i) => (
            <Card key={t.id} pad={false}>
              <div className="flex flex-wrap items-center gap-4 p-4">
                <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-rose-400/60 font-mono text-[12px] font-bold text-rose-300">{i + 1}</span>
                <div className="min-w-[240px] flex-1">
                  <div className="flex items-center gap-2"><span className="font-display text-[15px] font-extrabold text-white">{t.name}</span><Badge tone="blue">{CAT_LABEL[t.category] || t.category}</Badge><Badge>{t.source}</Badge></div>
                  <div className="mt-1 text-[11.5px] text-slate-400">Pierwszy raz: <b className="text-slate-200"><time>{fmtDate(t.first_seen)}</time></b>{t.first_scan_label && <> · skan <span className="text-slate-200">{t.first_scan_label}</span> (#{t.first_scan_id})</>}</div>
                  <div className="mt-0.5 font-mono text-[11px] text-slate-500">{t.services ? `teraz na ${t.services} ${t.services === 1 ? 'usłudze' : 'usługach'}: ${t.where.join(', ')}${t.services > t.where.length ? ' …' : ''}` : 'obecnie na żadnej aktywnej usłudze'}</div>
                </div>
                {can('results.update') ? (
                  <div className="flex flex-wrap gap-2">
                    <button disabled={busy === t.id} className="btn-ok" onClick={() => decide(t, 'znana')}><CheckCircle2 size={13} /> Znana</button>
                    <button disabled={busy === t.id} className="btn-ghost text-amber-200" onClick={() => decide(t, 'obserwuj')}><Eye size={13} /> Do obserwacji</button>
                    <button disabled={busy === t.id} className="btn-ghost" onClick={() => decide(t, 'ignoruj')}><EyeOff size={13} /> Ignoruj</button>
                  </div>
                ) : <span className="text-[11px] text-slate-500">Klasyfikacja wymaga roli z prawem edycji wyników.</span>}
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function TechOverview({ pending, onReview }) {
  const nav = useNavigate();
  const [cat, setCat] = useState('');
  const [q, setQ] = useState('');
  // zakres: Wszystkie (bieżący stan) albo Od–Do po dacie lub po skanach; „tylko nowe” = pierwszy raz w tym zakresie
  const [range, setRange] = useState('all');
  const [by, setBy] = useState('date');
  const [dFrom, setDFrom] = useState(weekAgo());
  const [dTo, setDTo] = useState(today());
  const [sFrom, setSFrom] = useState('');
  const [sTo, setSTo] = useState('');
  const [onlyNew, setOnlyNew] = useState(false);
  const scans = useApi(range === 'range' && by === 'scans' ? '/scans' : null, [range, by]);
  const scanList = (scans.data || []).filter((s) => s.status === 'completed' || s.kind === 'doskanowanie');
  let path = '/technologies';
  if (range === 'range') {
    if (by === 'date') path = `/technologies?mode=date&from=${dFrom}&to=${dTo}${onlyNew ? '&only_new=1' : ''}`;
    else path = sFrom && sTo ? `/technologies?mode=scans&from=${sFrom}&to=${sTo}${onlyNew ? '&only_new=1' : ''}` : null;
  }
  const { data, error, loading } = useApi(path, [path], 30000);
  const rangeBar = (
    <Card className="mb-5" pad={false}>
      <div className="flex flex-wrap items-end gap-3 p-4">
        <div>
          <span className="label">Zakres</span>
          <div className="flex gap-1">
            {[['all', 'Wszystkie'], ['range', 'Od – Do']].map(([k, l]) => <button key={k} onClick={() => setRange(k)} className={`${range === k ? 'btn-primary' : 'btn-ghost'} px-4 font-extrabold`}>{l}</button>)}
          </div>
        </div>
        {range === 'range' && <>
          <div>
            <span className="label">Według</span>
            <div className="flex gap-1">
              {[['date', 'Data'], ['scans', 'Skany']].map(([k, l]) => <button key={k} onClick={() => setBy(k)} className={`${by === k ? 'btn-primary' : 'btn-ghost'} px-4 font-extrabold`}>{l}</button>)}
            </div>
          </div>
          {by === 'date' ? <>
            <label><span className="label">Od</span><input type="date" className="input w-44" value={dFrom} max={dTo} onChange={(e) => setDFrom(e.target.value)} /></label>
            <label><span className="label">Do</span><input type="date" className="input w-44" value={dTo} min={dFrom} onChange={(e) => setDTo(e.target.value)} /></label>
          </> : <>
            <label><span className="label">Od skanu</span><select className="input w-72" value={sFrom} onChange={(e) => setSFrom(e.target.value)}><option value="">wybierz…</option>{[...scanList].reverse().map((s) => <option key={s.id} value={s.id}>{s.label} · {s.kind}</option>)}</select></label>
            <label><span className="label">Do skanu</span><select className="input w-72" value={sTo} onChange={(e) => setSTo(e.target.value)}><option value="">wybierz…</option>{scanList.map((s) => <option key={s.id} value={s.id}>{s.label} · {s.kind}</option>)}</select></label>
          </>}
          <label className="ml-auto flex cursor-pointer select-none items-center gap-2 rounded-full border border-accent/40 px-4 py-2 text-[12.5px] font-bold text-slate-200 hover:bg-accent/10">
            <input type="checkbox" className="h-4 w-4 accent-[#6cb6ff]" checked={onlyNew} onChange={(e) => setOnlyNew(e.target.checked)} />
            <Sparkles size={13} className="text-accent" /> Pokaż tylko nowe technologie
          </label>
        </>}
      </div>
      <p className="px-4 pb-3 text-[11px] text-slate-500">
        {range === 'all' ? 'Bieżący stan: technologie na wszystkich aktualnych usługach.'
          : onlyNew ? 'Tylko technologie, które pojawiły się pierwszy raz w wybranym okresie (katalog technologii pamięta pierwsze wystąpienie każdej z nich).'
            : 'Technologie wykryte na usługach w wybranym okresie (najnowsza obserwacja każdej usługi). Nowe w tym okresie są oznaczone.'}
      </p>
    </Card>
  );
  if (range === 'range' && by === 'scans' && (!sFrom || !sTo)) return <div><PageHeader title="Technologie" sub="Technologie wykryte w sieci: bieżący stan albo wybrany okres (data lub zakres skanów), z możliwością pokazania tylko nowych" /><ReviewBanner n={pending} onClick={onReview} />{rangeBar}<Card><Empty>Wybierz skan od i do.</Empty></Card></div>;
  if (loading && !data) return <div><PageHeader title="Technologie" sub="" /><ReviewBanner n={pending} onClick={onReview} />{rangeBar}<Spinner /></div>;
  if (error) return <div><PageHeader title="Technologie" sub="" /><ReviewBanner n={pending} onClick={onReview} />{rangeBar}<ErrorBox msg={error} /></div>;
  const cats = data.categories.map((c) => ({ k: c.category, v: c.count, label: CAT_LABEL[c.category] || c.category }));
  const techs = data.technologies.filter((t) => (!cat || t.category === cat) && (!q || t.name.toLowerCase().includes(q.toLowerCase())));
  return (
    <div className="tech-page">
      <PageHeader title="Technologie" sub={`Technologie wykryte w ${num(data.services)} usługach (${range === 'all' ? 'bieżący stan' : 'wybrany okres'}), z rozkładem wersji. Katalog pamięta pierwsze wystąpienie każdej technologii (${num(data.catalog_size)} w katalogu).`} />
      <ReviewBanner n={pending} onClick={onReview} />
      {rangeBar}
      <div className="grid gap-5 xl:grid-cols-[340px_1fr]">
        <Card title="Kategorie" icon={Layers} className="h-fit xl:sticky xl:top-4">
          {cats.length ? (
            <>
              <button onClick={() => setCat('')} className={`mb-3 w-full rounded-full px-3 py-1.5 text-left text-[12px] ${!cat ? 'bg-accent/[.08] text-white' : 'text-slate-400 hover:text-slate-200'}`}>Wszystkie kategorie</button>
              <TallBars spread={false} items={cats} color="bg-gradient-to-r from-[#1f9d57] to-[#4ade80]" onClick={(k) => setCat(k === cat ? '' : k)} />
            </>
          ) : <Empty>Brak danych</Empty>}
        </Card>
        <Card title={`${cat ? `Technologie · ${CAT_LABEL[cat] || cat}` : onlyNew && range === 'range' ? 'Nowe technologie' : 'Wszystkie technologie'} (${techs.length})`} icon={Cpu} pad={false} className="min-w-0" bodyClass="overflow-x-auto"
          actions={<div className="relative"><Search size={13} className="absolute left-2.5 top-2.5 text-slate-500" /><input className="input w-56 py-1.5 pl-7" placeholder="szukaj technologii…" value={q} onChange={(e) => setQ(e.target.value)} /></div>}>
          {!techs.length ? <Empty>{onlyNew && range === 'range' ? 'W tym okresie nie pojawiła się żadna nowa technologia.' : 'Brak technologii.'}</Empty> : (
            <table className="tech-table w-full">
              <thead><tr><th className="th">Technologia</th><th className="th">Pierwszy raz</th><th className="th">Kategoria</th><th className="th">Usługi</th><th className="th">Hosty</th><th className="th">Pewność</th><th className="th">Wersje (liczba usług)</th></tr></thead>
              <tbody>
                {techs.map((t) => (
                  <tr key={t.id} onClick={() => nav(`/inventory?tech=${encodeURIComponent(t.id)}`)} className="cursor-pointer border-b hover:bg-white/[.025]">
                    <td className="td w-[210px] max-w-[230px]"><div className="flex flex-wrap items-center gap-2 tech-name text-white">{t.name}{t.new && <Badge tone="green">nowa</Badge>}{t.status === 'new' && <Badge tone="red">do zaklasyfikowania</Badge>}{t.decision === 'obserwuj' && <Badge tone="amber">do obserwacji</Badge>}{t.decision === 'ignoruj' && <Badge>zignorowana</Badge>}</div><div className="font-mono text-[10px] text-slate-600">{t.id}</div></td>
                    <td className="td whitespace-nowrap text-[11.5px] text-slate-400">{t.first_seen ? fmtDate(t.first_seen) : '–'}{t.first_scan_id > 0 && <div className="font-mono text-[10px] text-slate-600">skan #{t.first_scan_id}</div>}</td>
                    <td className="td whitespace-nowrap"><Badge tone="blue">{CAT_LABEL[t.category] || t.category}</Badge></td>
                    <td className="td font-mono text-[13px] font-semibold text-slate-200">{num(t.count)}</td>
                    <td className="td font-mono text-[12px] text-slate-400">{num(t.hosts)}</td>
                    <td className="td font-mono text-[12px] text-slate-400">{t.avg_confidence}%</td>
                    <td className="td">
                      <div className="flex min-w-[290px] flex-wrap gap-x-3 gap-y-0.5 font-mono text-[11.5px] leading-5 text-slate-300">
                        {t.versions.slice(0, 6).map((v) => <span key={v.version} className="whitespace-nowrap"><b className="font-semibold text-slate-100">{v.version === '?' ? 'nieznana' : v.version}</b><span className="text-slate-500"> ×{v.count}</span></span>)}
                        {t.versions.length > 6 && <span className="whitespace-nowrap text-slate-500">+{t.versions.length - 6}</span>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </div>
  );
}
