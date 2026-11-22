import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Search, Server, Download, Sparkles, ChevronLeft, Pencil, Save, Lock, Globe, Cookie, FileCode, History, Tag, Fingerprint } from 'lucide-react';
import { api, useApi, useCan, useToast, CategoryTable, svcCategory, SVC_CATEGORIES, Card, Badge, Flag, Interest, State, Spinner, ErrorBox, Empty, Drawer, Field, TagInput, Toggle, fmtDate, download, useDebounced, flagLabel } from '../lib.jsx';
import { PageHeader, InfoTip } from '../App.jsx';
import { SigWizard, WizardIcon } from './SigWizard.jsx';

// Te same widoki co w zakładce Hosty: usługi według stanu hosta, na którym działają.
const SVC_VIEWS = [
  ['active', 'Aktywne', 'Usługi hostów widzianych w skanie w ciągu ostatnich 24 godzin.'],
  ['unstable', 'Niestabilne', 'Usługi hostów widzianych w ciągu 24 godzin, ale niewidocznych w skanach nocnych (22:00–06:00): działają tylko w oknie dziennym.'],
  ['down', 'Niedostępne', 'Usługi hostów niewidzianych w skanie dłużej niż 48 godzin (ostatnia obserwacja). Doskaner sprawdza je w ciągu dnia po kolei.'],
];

export default function Inventory() {
  // Usługi: domyślnie kategorie (jak w szczegółach skanu) → klik = usługi z kategorii; „Wszystkie usługi” = pełna lista.
  const [sp, setSp] = useSearchParams();
  const [q, setQ] = useState(sp.get('q') || '');
  const [flag, setFlag] = useState(sp.get('flag') || '');
  const [tech, setTech] = useState(sp.get('tech') || '');
  const [minI, setMinI] = useState(Number(sp.get('min') || 0));
  const [hideFp, setHideFp] = useState(true);
  const [sortBy, setSortBy] = useState('interest');
  const [cat, setCat] = useState(sp.get('cat') || (sp.get('flag') || sp.get('q') ? 'all' : ''));
  const [hv, setHv] = useState(['active', 'unstable', 'down'].includes(sp.get('hosts')) ? sp.get('hosts') : 'active');
  const hvCounts = useApi(`/services-views${hideFp ? '?hide_fp=1' : ''}`, [hideFp], 20000).data || {};
  const [sel, setSel] = useState(null);
  const can = useCan();
  const dq = useDebounced(q);
  const qs = new URLSearchParams({ q: dq, flag, tech, min_interest: String(minI), hide_fp: hideFp ? '1' : '', ...(hv ? { host_view: hv } : {}) }).toString();
  const { data, error, loading } = useApi(`/services?${qs}`, [qs]);
  useEffect(() => {
    const p = Object.fromEntries(Object.entries({ q: dq, flag, tech, min: minI || '', cat, hosts: hv }).filter(([, v]) => v !== '' && v !== 0));
    setSp(p, { replace: true });
  }, [dq, flag, tech, minI, cat, hv]); // eslint-disable-line
  const rows = data || [];
  const shown = cat === 'all' ? rows : rows.filter((o) => svcCategory(o) === cat);
  const catLabel = cat === 'all' ? 'Wszystkie usługi' : SVC_CATEGORIES.find((c) => c.k === cat)?.label;

  return (
    <div>
      <PageHeader title="Usługi" sub="Bieżący inwentarz wystawionych usług pogrupowany w kategorie (ostatnia obserwacja każdej usługi + adnotacje analityków)">
        {can('data.export') && <>
          <button className="btn-ghost" onClick={() => download('/export/services?format=csv')}><Download size={13} /> CSV</button>
          <button className="btn-ghost" onClick={() => download('/export/services?format=json')}><Download size={13} /> JSON</button>
        </>}
      </PageHeader>
      <Card title={cat ? `Usługi · ${catLabel}` : 'Usługi · kategorie'} icon={Sparkles} pad={false}
        actions={cat ? <button className="btn-ghost" onClick={() => setCat('')}><ChevronLeft size={13} /> Wszystkie kategorie</button>
          : <button className="btn-ghost" onClick={() => setCat('all')}><Server size={13} /> Wszystkie usługi ({rows.length})</button>}>
        <div className="flex flex-wrap items-center gap-2 border-b border-white/5 p-3">
          <div className="flex gap-2" role="group" aria-label="Stan hostów">
            {SVC_VIEWS.map(([k, l]) => (
              <button key={k} onClick={() => setHv(k)} className={`${hv === k ? 'btn-primary' : 'btn-ghost'} px-4 text-[13px] font-extrabold tracking-wide`}>
                {l}{hvCounts[k] != null && ` (${hvCounts[k]})`}
              </button>
            ))}
          </div>
          <div className="relative min-w-[260px] flex-1">
            <Search size={14} className="absolute left-3 top-2.5 text-slate-500" />
            <input className="input pl-8" placeholder="Szukaj: IP, port, produkt, tytuł, technologia, tag…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <select className="input w-48" value={flag} onChange={(e) => setFlag(e.target.value)}>
            <option value="">wszystkie flagi</option>
            {Object.entries(flagLabel).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <input className="input w-44" placeholder="technologia" value={tech} onChange={(e) => setTech(e.target.value)} />
          <select className="input w-40" value={minI} onChange={(e) => setMinI(Number(e.target.value))}>
            {[0, 10, 25, 50].map((v) => <option key={v} value={v}>klasa ≥ {v}%</option>)}
          </select>
          {cat && <select className="input w-48" value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
            <option value="interest">sortuj: klasa</option>
            <option value="ip">sortuj: adres IP</option>
            <option value="last">sortuj: ostatnio widziane</option>
            <option value="first">sortuj: najnowsze usługi</option>
          </select>}
          <span className="inline-flex items-center gap-2"><Toggle checked={hideFp} onChange={setHideFp} label="ukryj fałszywe alarmy" /> <InfoTip text="Fałszywy alarm to wykrycie, które analityk sprawdził i uznał za nietrafne, np. sygnatura rozpoznała kamerę, a to zwykły serwer WWW. Skaner nigdy sam niczego nie ukrywa: oznaczenie ustawia człowiek w szczegółach usługi (Adnotacje → fałszywy alarm). Oznaczona usługa zostaje w bazie i w historii, ale znika z domyślnego widoku, nie podnosi liczb na dashboardzie i nie trafia do DefectDojo. Oznaczenie obowiązuje także w kolejnych skanach, a odznaczyć je można w każdej chwili." /></span>
        </div>
        <p className="px-4 pt-3 text-[12px] text-slate-400">{(SVC_VIEWS.find(([k]) => k === hv) || SVC_VIEWS[0])[2]}</p>
        {loading && !data ? <Spinner /> : error ? <div className="p-3"><ErrorBox msg={error} /></div> : !cat ? (
          <><p className="px-4 pt-3 text-[11px] text-slate-500">Jeden wiersz = jedna kategoria, wg tego, co rozpoznano na usłudze (sygnatury), a nie wg protokołu. Kliknij wiersz, aby zobaczyć usługi.</p>
            <CategoryTable rows={rows} onOpen={(g) => setCat(g.k)} /></>
        ) : <ServicesTable rows={sortRows(shown, sortBy)} onOpen={setSel} />}
      </Card>
      <ServiceDrawer id={sel} onClose={() => setSel(null)} />
    </div>
  );
}

function sortRows(rows, by) {
  const r = [...rows];
  if (by === 'ip') r.sort((a, b) => ipNum(a.ip) - ipNum(b.ip) || a.port - b.port);
  else if (by === 'last') r.sort((a, b) => (b.last_seen || b.seen_at || '').localeCompare(a.last_seen || a.seen_at || ''));
  else if (by === 'first') r.sort((a, b) => (b.first_seen || '').localeCompare(a.first_seen || ''));
  return r;
}

export function ServicesTable({ rows, onOpen, showState = true }) {
  const [limit, setLimit] = useState(200);
  if (!rows.length) return <Empty>Brak usług spełniających kryteria.</Empty>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead><tr className="border-b border-white/5">
          <th className="th">Adres</th><th className="th">Usługa / produkt</th><th className="th">HTTP</th><th className="th">Technologie</th><th className="th">Flagi</th><th className="th">Klasa</th><th className="th">Czas</th>{showState && <th className="th">Stan</th>}
        </tr></thead>
        <tbody>
          {rows.slice(0, limit).map((s) => (
            <tr key={s.id} onClick={() => onOpen(s.id)} className="cursor-pointer border-b border-white/[.03] hover:bg-white/[.025]">
              <td className="td whitespace-nowrap">
                <div className="font-mono text-slate-100">{s.ip}<span className="text-slate-500">:{s.port}/{s.proto}</span></div>
                {s.hostname && <div className="text-[11px] text-slate-500">{s.hostname}</div>}
                {s.annotation?.tags?.length > 0 && <div className="mt-1 flex flex-wrap gap-1">{s.annotation.tags.map((t) => <Badge key={t} tone="violet">{t}</Badge>)}</div>}
              </td>
              <td className="td"><div className="text-slate-200">{s.service || '–'}</div><div className="max-w-[220px] truncate text-[11px] text-slate-500">{[s.product, s.version].filter(Boolean).join(' ')}{s.edited && <span className="ml-1 text-amber-300/70">(edyt.)</span>}</div></td>
              <td className="td">{s.http_status ? <><span className={`font-mono text-[12px] ${s.http_status < 300 ? 'text-emerald-300' : s.http_status < 400 ? 'text-accent-soft' : 'text-amber-300'}`}>{s.http_status}</span>{s.tls && <Lock size={11} className="ml-1 inline text-emerald-400" />}{s.response_ms > 0 && <span title="czas pierwszej odpowiedzi" className={`ml-2 font-mono text-[10.5px] ${s.response_ms >= 500 ? 'font-bold text-amber-300' : 'text-slate-500'}`}>{s.response_ms} ms</span>}<div className="max-w-[220px] truncate text-[11px] text-slate-400">{s.title}</div></> : <span className="text-slate-600">–</span>}</td>
              <td className="td"><div className="flex max-w-[260px] flex-wrap gap-1">{s.techs.slice(0, 5).map((t) => <Badge key={t.id} tone="blue" title={`pewność ${t.confidence}%`}>{t.name}{t.version ? ' ' + t.version : ''}</Badge>)}</div></td>
              <td className="td"><div className="flex max-w-[220px] flex-wrap gap-1">{s.flags.map((f) => <Flag key={f} f={f} />)}{s.annotation?.false_positive && <Badge>fałszywy alarm</Badge>}</div></td>
              <td className="td"><Interest v={s.interest} /><div className="mt-1 font-mono text-[10px] text-slate-500" title="dopasowane reguły klasy / aktywne reguły">{(s.rules || []).length}/{s.rules_total} reguł</div></td>
              <td className="td whitespace-nowrap font-mono text-[11px] leading-relaxed text-slate-400">
                {showState ? (<>
                  <div title="pierwsze wykrycie usługi"><span className="text-slate-600">dodano </span><time>{fmtDate(s.first_seen)}</time></div>
                  <div title="ostatnio widziana w skanie"><span className="text-slate-600">widziana </span><time>{fmtDate(s.last_seen || s.seen_at)}</time></div>
                </>) : (
                  <div title="czas przeskanowania usługi"><span className="text-slate-600">skan </span><time>{fmtDate(s.seen_at)}</time></div>
                )}
              </td>
              {showState && <td className="td">{s.service_state && <State s={s.service_state} />}</td>}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > limit && <div className="p-3 text-center"><button className="btn-ghost" onClick={() => setLimit(limit + 500)}>Pokaż więcej ({rows.length - limit})</button></div>}
      <div className="px-3 py-2 text-right text-[11px] text-slate-600">{rows.length} usług</div>
    </div>
  );
}

function KV({ k, v, mono = true }) {
  return <div className="grid grid-cols-[140px_1fr] gap-2 border-b border-white/[.04] py-1.5 text-[12px]"><span className="text-slate-500">{k}</span><span className={`break-all ${mono ? 'font-mono' : ''} text-slate-200`}>{v ?? '–'}</span></div>;
}

export function ServiceDrawer({ id, onClose }) {
  const { data, error, loading, reload } = useApi(id ? `/observations/${id}` : null, [id]);
  const can = useCan();
  const toast = useToast();
  const [ann, setAnn] = useState(null);
  const [edit, setEdit] = useState(null);
  const [wiz, setWiz] = useState(false);
  const o = data?.observation;
  useEffect(() => {
    if (o) {
      const a = o.annotation || {};
      setAnn({ tags: a.tags || [], note: a.note || '', owner: a.owner || '', criticality: a.criticality || 0, false_positive: !!a.false_positive });
      setEdit(null);
    }
  }, [o?.id]); // eslint-disable-line
  const saveAnn = async () => {
    try {
      await api('/annotations', { method: 'PUT', body: { entity: `svc:${o.ip}:${o.port}/${o.proto}`, ...ann, criticality: Number(ann.criticality) } });
      toast('Zapisano adnotację: zostanie zachowana przy kolejnych skanach');
      reload();
    } catch (e) { toast(e.message, 'err'); }
  };
  const saveEdit = async () => {
    try {
      // wysyłamy tylko pola zmienione przez analityka: każde wysłane pole staje się trwałą poprawką usługi
      const body = {};
      if (edit.service !== o.service) body.service = edit.service;
      if (edit.product !== o.product) body.product = edit.product;
      if (edit.version !== o.version) body.version = edit.version;
      if (edit.note !== (o.data.note || '')) body.note = edit.note;
      if (Number(edit.interest) !== o.interest) body.interest = Number(edit.interest);
      if (edit.techs !== edit.techs0) {
        // „Nazwa wersja, Nazwa2”: kategoria zostaje z wykrycia o tej samej nazwie, nowe pozycje jako „inne”
        body.techs = edit.techs.split(',').map((x) => x.trim()).filter(Boolean).map((x) => {
          const m = x.match(/^(.*?)\s+(v?\d[\w.\-]*)$/);
          const name = m ? m[1] : x, version = m ? m[2] : '';
          const prev = (o.techs || []).find((t) => t.name.toLowerCase() === name.toLowerCase());
          return { id: prev?.id || 'analityk-' + name.toLowerCase().replace(/[^a-z0-9]+/g, '-'), name, version, category: prev?.category || 'other', confidence: 100, source: 'analityk' };
        });
      }
      if (!Object.keys(body).length) { setEdit(null); return; }
      await api(`/observations/${o.id}`, { method: 'PUT', body });
      toast('Zapisano zmiany wyniku');
      setEdit(null);
      reload();
    } catch (e) { toast(e.message, 'err'); }
  };
  const h = o?.data?.http;
  return (
    <Drawer open={!!id} onClose={onClose} title={o ? `${o.ip}:${o.port}/${o.proto} · ${o.service || ''}` : 'Usługa'}>
      {loading && !o ? <Spinner /> : error ? <ErrorBox msg={error} /> : o && (
        <div className="space-y-5">
          {can('signatures.create') && (() => {
            const known = (o.data.detections || []).some((d) => !['login-form', 'admin-path', 'basic-auth', 'default-page'].includes(d.id));
            return (
              <div className={`flex items-center justify-between gap-3 rounded-xl border p-3 ${known ? 'border-white/5 bg-white/[.02]' : 'border-accent/40 bg-accent/[.06] shadow-[0_0_14px_rgba(108,182,255,.15)]'}`}>
                <div className="text-[12px] text-slate-300">{known ? 'Rozpoznana sygnaturą. Możesz dodać własną nazwę dla podobnych usług.' : <><b className="text-white">Nierozpoznana usługa.</b> Nazwij ją, a system rozpozna ją w kolejnych skanach.</>}</div>
                <button className={known ? 'btn-ghost' : 'btn-primary'} onClick={() => setWiz(true)}><WizardIcon size={13} /> Naucz system</button>
              </div>
            );
          })()}
          <SigWizard o={o} open={wiz} onClose={() => setWiz(false)} />
          <div className="flex flex-wrap items-center gap-2">
            <Interest v={o.interest} />{o.flags.map((f) => <Flag key={f} f={f} />)}{o.edited && <Badge tone="amber">edytowano: {o.edited_by}</Badge>}
          </div>

          <Card title="Usługa (nmap)" icon={Server} actions={can('results.update') && !edit && <button className="btn-ghost" onClick={() => setEdit({ service: o.service, product: o.product, version: o.version, note: o.data.note || '', interest: o.interest, techs: (o.techs || []).map((t) => (t.version ? `${t.name} ${t.version}` : t.name)).join(', '), techs0: (o.techs || []).map((t) => (t.version ? `${t.name} ${t.version}` : t.name)).join(', ') })}><Pencil size={12} /> Edytuj wynik</button>}>
            {o.edited && can('results.update') && !edit && <div className="mb-3 flex items-center gap-2 text-[12px] text-amber-300">Wynik poprawiony ręcznie{o.edited_by ? ` (${o.edited_by})` : ''}; poprawka nakłada się na kolejne skany. <button className="btn-ghost" onClick={async () => { if (!confirm('Cofnąć poprawkę? Kolejny skan zapisze wartości wykryte automatycznie.')) return; await api(`/observations/${o.id}/override`, { method: 'DELETE' }); reload(); }}>Cofnij poprawkę</button></div>}
            {edit ? (
              <div className="grid grid-cols-2 gap-3">
                <Field label="Usługa"><input className="input" value={edit.service} onChange={(e) => setEdit({ ...edit, service: e.target.value })} /></Field>
                <Field label="Produkt"><input className="input" value={edit.product} onChange={(e) => setEdit({ ...edit, product: e.target.value })} /></Field>
                <Field label="Wersja"><input className="input" value={edit.version} onChange={(e) => setEdit({ ...edit, version: e.target.value })} /></Field>
                <Field label="Klasa (0–100%)"><input className="input" type="number" value={edit.interest} onChange={(e) => setEdit({ ...edit, interest: e.target.value })} /></Field>
                <Field label="Technologie (po przecinku, np. WordPress 5.8, nginx)" className="col-span-2"><input className="input" value={edit.techs} onChange={(e) => setEdit({ ...edit, techs: e.target.value })} /></Field>
                <Field label="Notatka do wyniku" className="col-span-2"><textarea className="input" rows={2} value={edit.note} onChange={(e) => setEdit({ ...edit, note: e.target.value })} /></Field>
                <div className="col-span-2 flex gap-2"><button className="btn-primary" onClick={saveEdit}><Save size={13} /> Zapisz</button><button className="btn-ghost" onClick={() => setEdit(null)}>Anuluj</button></div>
              </div>
            ) : (
              <>
                <KV k="Usługa" v={o.service} /><KV k="Produkt" v={[o.product, o.version].filter(Boolean).join(' ')} />
                <KV k="Dodatkowe" v={o.data.banner?.extrainfo} /><KV k="Tunel" v={o.data.banner?.tunnel} />
                <KV k="CPE" v={(o.data.banner?.cpe || []).join(', ')} /><KV k="Nazwa hosta" v={o.data.hostname} />
                {o.data.mac && <KV k="MAC / producent" v={`${o.data.mac} ${o.data.vendor || ''}`} />}
                {o.data.note && <KV k="Notatka" v={o.data.note} mono={false} />}
              </>
            )}
          </Card>

          {o.data.detections?.length > 0 && (
            <Card title="Wykryte technologie (sygnatury)" icon={Fingerprint}>
              <div className="space-y-2">
                {o.data.detections.map((t) => (
                  <div key={t.id} className="rounded-lg border border-white/5 bg-white/[.02] p-2.5">
                    <div className="flex items-center justify-between"><span className="text-sm text-slate-100">{t.name} {t.version && <span className="font-mono text-accent-soft">{t.version}</span>}</span><span className="flex gap-1.5"><Badge tone="blue">{t.category}</Badge><Badge tone={t.confidence >= 80 ? 'green' : t.confidence >= 50 ? 'amber' : 'slate'}>pewność {t.confidence}%</Badge></span></div>
                    <ul className="mt-1.5 space-y-0.5">{(t.evidence || []).map((e, i) => <li key={i} className="font-mono text-[11px] text-slate-400">↳ {e}</li>)}</ul>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {h && (
            <Card title="HTTP / HTTPS" icon={Globe}>
              <KV k="URL" v={h.url} /><KV k="Końcowy URL" v={h.final_url} /><KV k="Kod" v={h.status} /><KV k="Tytuł" v={h.title} mono={false} />
              <KV k="Rozmiar / SHA-256" v={`${h.body_length} B · ${h.body_sha256?.slice(0, 16)}…`} />
              {h.favicon_hash !== undefined && h.favicon_hash !== null && <KV k="Favicon mmh3" v={h.favicon_hash} />}
              {h.redirects?.length > 0 && <KV k="Przekierowania" v={h.redirects.join('  ⟶  ')} />}
              {h.error && <KV k="Błąd" v={h.error} />}
              {h.tls && (
                <div className="mt-3 rounded-lg border border-white/5 bg-white/[.02] p-3">
                  <div className="mb-1 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500"><Lock size={12} /> Certyfikat TLS {h.tls.expired && <Badge tone="red">wygasł</Badge>}{h.tls.self_signed && <Badge tone="amber">self-signed</Badge>}</div>
                  <KV k="Wersja / szyfr" v={`${h.tls.version} · ${h.tls.cipher}`} /><KV k="Podmiot" v={h.tls.subject} /><KV k="Wystawca" v={h.tls.issuer} />
                  <KV k="SAN" v={(h.tls.sans || []).join(', ')} /><KV k="Ważność" v={`${fmtDate(h.tls.not_before)} → ${fmtDate(h.tls.not_after)} (${h.tls.days_left} dni)`} /><KV k="SHA-256" v={h.tls.sha256} />
                </div>
              )}
              {h.headers && (
                <div className="mt-3">
                  <div className="mb-1 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500"><FileCode size={12} /> Nagłówki</div>
                  <div className="rounded-lg bg-black/40 p-3 font-mono text-[11px] leading-relaxed text-slate-300">
                    {Object.entries(h.headers).sort().map(([k, v]) => <div key={k}><span className="text-accent-soft">{k}</span>: {v.join(', ')}</div>)}
                  </div>
                </div>
              )}
              {h.cookies?.length > 0 && (
                <div className="mt-3">
                  <div className="mb-1 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500"><Cookie size={12} /> Ciasteczka</div>
                  {h.cookies.map((c, i) => (
                    <div key={i} className="flex flex-wrap items-center gap-1.5 py-0.5 font-mono text-[12px] text-slate-300">
                      {c.name} {c.secure ? <Badge tone="green">Secure</Badge> : <Badge tone="amber">bez Secure</Badge>} {c.httponly ? <Badge tone="green">HttpOnly</Badge> : <Badge tone="amber">bez HttpOnly</Badge>} {c.samesite && <Badge>SameSite={c.samesite}</Badge>}
                    </div>
                  ))}
                </div>
              )}
              {h.paths && Object.keys(h.paths).length > 0 && (
                <div className="mt-3">
                  <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Sprawdzone ścieżki (GET, bez logowania)</div>
                  <div className="flex flex-wrap gap-1.5">{Object.entries(h.paths).map(([p, r]) => <Badge key={p} tone={r.status < 300 ? 'green' : r.status < 400 ? 'blue' : r.status === 401 || r.status === 403 ? 'amber' : 'slate'}>{p} → {r.status}</Badge>)}</div>
                </div>
              )}
              {h.body_snippet && <details className="mt-3"><summary className="cursor-pointer text-[11px] text-slate-500">Fragment odpowiedzi</summary><pre className="mt-2 max-h-60 overflow-auto whitespace-pre-wrap rounded-lg bg-black/40 p-3 text-[11px] text-slate-400">{h.body_snippet}</pre></details>}
            </Card>
          )}

          {ann && (
            <Card title="Adnotacja analityka (zachowywana między skanami)" icon={Tag}>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Tagi" className="col-span-2"><TagInput value={ann.tags} onChange={(t) => setAnn({ ...ann, tags: t })} /></Field>
                <Field label="Właściciel"><input className="input" value={ann.owner} onChange={(e) => setAnn({ ...ann, owner: e.target.value })} disabled={!can('results.update')} /></Field>
                <Field label="Ważność (0–5)"><input className="input" type="number" min={0} max={5} value={ann.criticality} onChange={(e) => setAnn({ ...ann, criticality: e.target.value })} disabled={!can('results.update')} /></Field>
                <Field label="Notatka (szyfrowana)" className="col-span-2"><textarea className="input" rows={3} value={ann.note} onChange={(e) => setAnn({ ...ann, note: e.target.value })} disabled={!can('results.update')} /></Field>
                <span className="inline-flex items-center gap-2"><Toggle checked={ann.false_positive} onChange={(v) => setAnn({ ...ann, false_positive: v })} label="fałszywy alarm" /> <InfoTip text="Zaznacz, jeśli po sprawdzeniu to wykrycie jest nietrafne. Usługa zostaje w bazie i historii, ale nie będzie liczona na dashboardzie ani wysyłana do DefectDojo, także po kolejnych skanach. Odznaczenie przywraca ją od razu." /></span>
                {can('results.update') && <div className="text-right"><button className="btn-primary" onClick={saveAnn}><Save size={13} /> Zapisz adnotację</button></div>}
              </div>
              {o.annotation?.updated_by && <div className="mt-2 text-[11px] text-slate-500">ostatnia zmiana: {o.annotation.updated_by}, <time>{fmtDate(o.annotation.updated_at)}</time></div>}
            </Card>
          )}

          {data.history?.length > 0 && (
            <Card title="Historia tej usługi w skanach" icon={History} pad={false}>
              <table className="w-full"><tbody>
                {data.history.map((x) => (
                  <tr key={x.obs_id} className="border-b border-white/[.03]"><td className="td font-mono text-[11px] text-slate-500">#{x.scan_id}</td><td className="td text-[12px]"><time>{fmtDate(x.started_at)}</time></td><td className="td text-[12px] text-slate-300">{x.product} {x.version}</td><td className="td font-mono text-[11px]">{x.http_status || ''}</td><td className="td font-mono text-[10px] text-slate-600">{x.fingerprint}</td></tr>
                ))}
              </tbody></table>
            </Card>
          )}
        </div>
      )}
    </Drawer>
  );
}
