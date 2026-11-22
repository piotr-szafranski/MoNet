import { useEffect, useState } from 'react';
import { Users, ShieldCheck, ScrollText, Plus, Save, Trash2, KeyRound, Download, ChevronDown, Gauge } from 'lucide-react';
import { api, useApi, useCan, useToast, Card, Badge, Spinner, Field, Modal, fmtDate, download, CollapseToggle, Empty } from '../lib.jsx';
import { PageHeader } from '../App.jsx';

const PERM_LABEL = {
  'users.manage': 'Użytkownicy', 'roles.manage': 'Role', 'settings.manage': 'Ustawienia (DefectDojo)', 'audit.read': 'Dziennik logów',
  'targets.read': 'Cele: odczyt', 'targets.create': 'Cele: dodawanie', 'targets.update': 'Cele: modyfikacja', 'targets.delete': 'Cele: usuwanie',
  'configs.read': 'Konfiguracje: odczyt', 'configs.create': 'Konfiguracje: dodawanie', 'configs.update': 'Konfiguracje: modyfikacja', 'configs.delete': 'Konfiguracje: usuwanie',
  'scans.read': 'Skany: odczyt', 'scans.run': 'Skany: uruchamianie/zatrzymanie', 'scans.update': 'Skany: modyfikacja', 'scans.delete': 'Skany: usuwanie',
  'results.read': 'Wyniki: odczyt', 'results.create': 'Wyniki: import', 'results.update': 'Wyniki: edycja i adnotacje', 'results.delete': 'Wyniki: usuwanie',
  'signatures.read': 'Sygnatury: odczyt', 'signatures.create': 'Sygnatury: dodawanie', 'signatures.update': 'Sygnatury: modyfikacja', 'signatures.delete': 'Sygnatury: usuwanie',
  'data.export': 'Eksport danych', 'dojo.push': 'Wysyłka do DefectDojo',
};

export default function Admin() {
  const users = useApi('/users');
  const roles = useApi('/roles');
  const perms = useApi('/permissions');
  const can = useCan();
  const toast = useToast();
  const [nu, setNu] = useState(null);
  const [role, setRole] = useState(null);
  const createUser = async () => {
    try { await api('/users', { method: 'POST', body: nu }); toast('Utworzono użytkownika'); setNu(null); users.reload(); } catch (e) { toast(e.message, 'err'); }
  };
  const upd = async (u, body) => { try { await api(`/users/${u.id}`, { method: 'PUT', body }); users.reload(); toast('Zapisano'); } catch (e) { toast(e.message, 'err'); } };
  const delUser = async (u) => { if (confirm(`Usunąć ${u.username}?`)) { try { await api(`/users/${u.id}`, { method: 'DELETE' }); users.reload(); } catch (e) { toast(e.message, 'err'); } } };
  const saveRole = async () => {
    try { await api(role.id ? `/roles/${role.id}` : '/roles', { method: role.id ? 'PUT' : 'POST', body: role }); toast('Zapisano rolę'); setRole(null); roles.reload(); } catch (e) { toast(e.message, 'err'); }
  };
  return (
    <div>
      <PageHeader title="Administracja" sub="Użytkownicy, role (RBAC) i dziennik logów (trwały, z pobieraniem logów z całego dnia)" />
      <div className="grid gap-5 xl:grid-cols-2">
        <Card title="Użytkownicy" icon={Users} pad={false} actions={<button className="btn-primary" onClick={() => setNu({ username: '', password: '', role: 'Obserwator' })}><Plus size={13} /> Dodaj</button>}>
          {users.loading ? <Spinner /> : (
            <table className="w-full">
              <thead><tr className="border-b border-white/5"><th className="th">Login</th><th className="th">Rola</th><th className="th">Ostatnie logowanie</th><th className="th">Aktywny</th><th className="th"></th></tr></thead>
              <tbody>
                {(users.data || []).map((u) => (
                  <tr key={u.id} className="border-b border-white/[.03]">
                    <td className="td font-mono text-slate-100">{u.username}</td>
                    <td className="td"><select className="input py-1 text-xs" value={u.role} onChange={(e) => upd(u, { role: e.target.value })}>{(roles.data || []).map((r) => <option key={r.id}>{r.name}</option>)}</select></td>
                    <td className="td text-[12px] text-slate-400"><time>{fmtDate(u.last_login)}</time></td>
                    <td className="td"><button onClick={() => upd(u, { disabled: !u.disabled })}>{u.disabled ? <Badge tone="red">zablokowany</Badge> : <Badge tone="green">aktywny</Badge>}</button></td>
                    <td className="td whitespace-nowrap text-right">
                      <button className="btn-ghost" onClick={() => { const p = prompt(`Nowe hasło dla ${u.username} (min. 8 znaków)`); if (p) upd(u, { password: p }); }}><KeyRound size={12} /></button>{' '}
                      <button className="btn-danger" onClick={() => delUser(u)}><Trash2 size={12} /></button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
        <Card title="Role i uprawnienia" icon={ShieldCheck} pad={false} actions={can('roles.manage') && <button className="btn-primary" onClick={() => setRole({ name: '', description: '', permissions: [] })}><Plus size={13} /> Własna rola</button>}>
          {roles.loading ? <Spinner /> : (
            <div className="divide-y divide-white/[.04]">
              {(roles.data || []).map((r) => (
                <div key={r.id} className="px-4 py-3">
                  <div className="flex items-center justify-between">
                    <div><span className="font-medium text-slate-100">{r.name}</span> {r.builtin ? <Badge>wbudowana</Badge> : <Badge tone="violet">własna</Badge>}<div className="text-[12px] text-slate-500">{r.description}</div></div>
                    <button className="btn-ghost" onClick={() => setRole({ ...r })}>{r.builtin ? 'Podgląd' : 'Edytuj'}</button>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1">{r.permissions.sort().map((p) => <Badge key={p} tone="slate">{p}</Badge>)}</div>
                </div>
              ))}
            </div>
          )}
        </Card>
        {can('settings.manage') && <div className="xl:col-span-2"><ScanPolicy /></div>}
        {can('audit.read') && <div className="xl:col-span-2"><LogJournal /></div>}
      </div>
      <Modal open={!!nu} onClose={() => setNu(null)} title="Nowy użytkownik">
        {nu && <div className="space-y-3">
          <Field label="Login"><input className="input" value={nu.username} onChange={(e) => setNu({ ...nu, username: e.target.value })} /></Field>
          <Field label="Hasło (min. 8 znaków)"><input className="input" type="password" value={nu.password} onChange={(e) => setNu({ ...nu, password: e.target.value })} /></Field>
          <Field label="Rola"><select className="input" value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value })}>{(roles.data || []).map((r) => <option key={r.id}>{r.name}</option>)}</select></Field>
          <button className="btn-primary" onClick={createUser}><Save size={13} /> Utwórz</button>
        </div>}
      </Modal>
      <Modal open={!!role} onClose={() => setRole(null)} title={role?.id ? `Rola: ${role.name}` : 'Nowa rola'} wide>
        {role && <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Field label="Nazwa"><input className="input" value={role.name} disabled={role.builtin} onChange={(e) => setRole({ ...role, name: e.target.value })} /></Field>
            <Field label="Opis"><input className="input" value={role.description} disabled={role.builtin} onChange={(e) => setRole({ ...role, description: e.target.value })} /></Field>
          </div>
          <div className="grid grid-cols-2 gap-1.5 md:grid-cols-3">
            {(perms.data || []).map((p) => (
              <label key={p} className="flex items-center gap-2 rounded-lg border border-white/5 px-2.5 py-1.5 text-[12px] text-slate-300">
                <input type="checkbox" disabled={role.builtin} checked={role.permissions.includes(p)} onChange={(e) => setRole({ ...role, permissions: e.target.checked ? [...role.permissions, p] : role.permissions.filter((x) => x !== p) })} />
                {PERM_LABEL[p] || p}
              </label>
            ))}
          </div>
          {!role.builtin && <button className="btn-primary" onClick={saveRole}><Save size={13} /> Zapisz rolę</button>}
          {role.builtin && <p className="text-[12px] text-slate-500">Role wbudowane odpowiadają wymaganiom (Administracja; Dodawanie, usuwanie, modyfikacja; Modyfikacja i odczyt; Odczyt) i są chronione przed zmianą. Utwórz własną rolę, aby nadać inny zestaw uprawnień.</p>}
        </div>}
      </Modal>
    </div>
  );
}

// Dziennik logów: lista dni (najnowsze u góry), każdy dzień rozwijany, pobieranie logów z całego dnia (CSV / JSON).
const dayName = (d) => { const t = new Date(d + 'T12:00:00').toLocaleDateString('pl-PL', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' }); return t.charAt(0).toUpperCase() + t.slice(1); };
// Twarde limity skanera: operator nie przekroczy ich w konfiguracji skanu; silnik sprawdza je przy każdym starcie.
function ScanPolicy() {
  const pol = useApi('/settings/policy');
  const toast = useToast();
  const [f, setF] = useState(null);
  useEffect(() => { if (pol.data) setF({ ...pol.data, cidrs: (pol.data.allow_cidrs || []).join('\n') }); }, [pol.data]);
  if (!f) return null;
  const num = (k) => (e) => setF({ ...f, [k]: Number(e.target.value) || 0 });
  const save = async () => {
    if (!f.cidrs.trim() && !confirm('Pusta lista sieci oznacza zgodę na skanowanie dowolnych adresów, także publicznych. Zapisać bez ograniczenia sieci?')) return;
    try {
      await api('/settings/policy', { method: 'PUT', body: { allow_cidrs: f.cidrs.split(/[\s,;]+/).filter(Boolean), max_rate: f.max_rate, max_http_rps: f.max_http_rps, max_workers: f.max_workers, no_generic_paths: !!f.no_generic_paths, confirm_any: !f.cidrs.trim() } });
      toast('Zapisano politykę skanera'); pol.reload();
    } catch (e) { toast(e.message, 'err'); }
  };
  return (
    <Card title="Polityka Skanera" icon={Gauge} collapsible defaultOpen actions={f.default ? <Badge tone="sky">polityka domyślna: tylko sieci prywatne</Badge> : !(f.allow_cidrs || []).length && !f.max_rate && <Badge tone="amber">brak limitów i dozwolonych sieci</Badge>}>
      <p className="mb-3 text-[12px] text-slate-400">Granice ustawiane przez administratora. Konfiguracja skanu nie może ich przekroczyć, a skan z adresem spoza dozwolonych sieci nie wystartuje. Puste pole lub 0 oznacza brak ograniczenia.</p>
      <div className="grid gap-3 md:grid-cols-4">
        <Field label="Dozwolone sieci (CIDR, po jednej w linii)" className="md:col-span-1"><textarea className="input font-mono" rows={4} placeholder="10.66.0.0/18" value={f.cidrs} onChange={(e) => setF({ ...f, cidrs: e.target.value })} /></Field>
        <Field label="Maks. tempo pakietów / s"><input className="input" type="number" min="0" value={f.max_rate} onChange={num('max_rate')} /></Field>
        <Field label="Maks. zapytań HTTP / s"><input className="input" type="number" min="0" value={f.max_http_rps} onChange={num('max_http_rps')} /></Field>
        <Field label="Maks. równoległych podgrup"><input className="input" type="number" min="0" value={f.max_workers} onChange={num('max_workers')} /></Field>
      </div>
      <label className="mt-3 flex items-center gap-2 text-[13px] text-slate-300"><input type="checkbox" checked={!!f.no_generic_paths} onChange={(e) => setF({ ...f, no_generic_paths: e.target.checked })} /> Nie sprawdzaj ścieżek ogólnych (/admin, /.env, /.git/HEAD, /server-status) na każdej usłudze HTTP; tylko ścieżki potwierdzające technologię</label>
      <div className="mt-3"><button className="btn-primary" onClick={save}><Save size={13} /> Zapisz politykę</button>{!f.default && <button className="btn-ghost ml-2" onClick={async () => { await api('/settings/policy?reset=1', { method: 'PUT', body: {} }); pol.reload(); toast('Przywrócono politykę domyślną'); }}>Przywróć domyślną</button>}</div>
    </Card>
  );
}

function LogJournal() {
  const days = useApi('/audit/days', [], 30000);
  const list = days.data || [];
  const total = list.reduce((a, d) => a + d.count, 0);
  return (
    <Card title={<>Dziennik logów ({total})</>} icon={ScrollText} pad={false} collapsible defaultOpen actions={<DownloadMenu day="all" label="Pobierz całość" />}>
      <p className="px-4 pt-3 text-[11px] text-slate-500">Logi działań w aplikacji (logowania, zmiany konfiguracji, edycje, eksporty) zapisywane trwale w bazie. Rozwiń dzień, aby zobaczyć wpisy, albo pobierz logi z całego dnia.</p>
      {days.loading && !days.data ? <Spinner /> : !list.length ? <Empty>Brak logów.</Empty> : (
        <div className="space-y-2 p-3">{list.map((d) => <LogDay key={d.day} d={d} />)}</div>
      )}
    </Card>
  );
}
function LogDay({ d }) {
  const [open, setOpen] = useState(false);
  const rows = useApi(open ? `/audit?day=${d.day}` : null, [open, d.day]);
  return (
    <div className="rounded-xl border border-white/[.08]">
      <div role="button" tabIndex={0} onClick={() => setOpen(!open)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setOpen(!open); } }}
        className="flex cursor-pointer select-none items-center gap-4 px-4 py-2.5 hover:bg-white/[.02]">
        <span className="w-28 font-mono text-[13px] font-bold text-white">{d.day}</span>
        <span className="flex-1 text-[12.5px] text-slate-300">{dayName(d.day)}</span>
        <span className="text-[12px] text-slate-400">{d.count} wpisów</span>
        {d.login_fails > 0 && <Badge tone="red">{d.login_fails} nieudanych logowań</Badge>}
        <span onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()}><DownloadMenu day={d.day} /></span>
        <CollapseToggle open={open} />
      </div>
      {open && (
        <div className="max-h-[420px] overflow-y-auto border-t border-white/[.06]">
          {rows.loading && !rows.data ? <Spinner /> : (
            <table className="w-full">
              <thead><tr><th className="th">Godzina</th><th className="th">Użytkownik</th><th className="th">Akcja</th><th className="th">Obiekt</th><th className="th">Szczegóły</th></tr></thead>
              <tbody>
                {(rows.data || []).map((a) => (
                  <tr key={a.id} className="border-b border-white/[.03]">
                    <td className="td whitespace-nowrap font-mono text-[12px] text-slate-400">{new Date(a.ts).toLocaleTimeString('pl-PL')}</td>
                    <td className="td font-mono text-[12px]">{a.user || '–'}</td>
                    <td className="td"><Badge tone={a.action.includes('fail') ? 'red' : a.action.includes('delete') ? 'amber' : 'slate'}>{a.action}</Badge></td>
                    <td className="td font-mono text-[11px] text-slate-400">{a.entity}</td>
                    <td className="td max-w-[460px] truncate font-mono text-[10px] text-slate-500" title={a.detail}>{a.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

// „Pobierz ▾”: po kliknięciu wybór formatu (JSON, CSV, TXT) logów z całego dnia
function DownloadMenu({ day, label = 'Pobierz' }) {
  const [open, setOpen] = useState(false);
  const pick = (f) => { setOpen(false); download(`/audit/export?day=${day}&format=${f}`); };
  return (
    <span className="relative inline-block" onBlur={(e) => { if (!e.currentTarget.contains(e.relatedTarget)) setOpen(false); }}>
      <button className="btn-ghost py-1" onClick={() => setOpen(!open)} aria-haspopup="menu" aria-expanded={open}>
        <Download size={12} /> {label} <ChevronDown size={12} className={`transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <span role="menu" className="tip absolute right-0 top-full z-50 mt-1.5 flex w-56 flex-col overflow-hidden rounded-xl py-1"
          style={{ background: 'rgba(10,16,30,.97)', border: '1px solid rgba(140,190,255,.35)', boxShadow: '0 10px 30px -10px rgba(0,0,0,.9)' }}>
          {[['json', 'JSON', 'dane strukturalne'], ['csv', 'CSV', 'arkusz kalkulacyjny'], ['txt', 'TXT', 'zwykły tekst']].map(([f, l, h]) => (
            <button key={f} role="menuitem" onClick={() => pick(f)} className="flex items-baseline gap-2 px-3 py-1.5 text-left text-[12.5px] text-slate-200 hover:bg-white/[.06]">
              <b className="w-10 font-mono">{l}</b><span className="text-[11px] text-slate-500">{h}</span>
            </button>
          ))}
        </span>
      )}
    </span>
  );
}
