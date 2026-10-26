import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, qs } from '../api'
import { useApp } from '../context'
import type { Ban, GroupRow, Overview as Ov, Page, SiteCounts, Certificate } from '../types'
import { Btn, Empty, IconBtn, ModePill, Segmented, useInterval } from '../ui'
import { ago, categoryLabel, clock, countryName, daysLeft, int, pct, siteName, when } from '../util'
import { Flow, Radar } from './live'

type Range = '24h' | '7d'

/** Draws one chart into a div whenever its inputs change. */
export function ChartBox({ draw, deps, height, label }: { draw: (el: HTMLDivElement) => void; deps: unknown[]; height?: number; label: string }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (ref.current) draw(ref.current)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  return <div ref={ref} className="chart" style={{ minHeight: height }} aria-label={label} />
}

const stages: { key: string; name: string; note: (n: number) => string }[] = [
  { key: 'deny', name: 'Access rules', note: () => 'refused by IP, country or rule' },
  { key: 'rate_limit', name: 'Rate limits', note: () => 'from banned sources' },
  { key: 'auth', name: 'Password gate', note: (n) => (n ? 'sign-in pages shown' : 'no gate was hit') },
  { key: 'wait', name: 'Queue', note: (n) => (n ? 'visitors held in line' : 'nobody had to wait') },
  { key: 'challenge', name: 'Bot check', note: () => 'challenge pages shown' },
  { key: 'block', name: 'Threat inspection', note: () => 'stopped by the rule set' },
]

export default function Overview() {
  const { sites, siteById, notify, notifyError } = useApp()
  const navigate = useNavigate()
  const [range, setRange] = useState<Range>('24h')
  const [ov, setOv] = useState<Ov | null>(null)
  const [sources, setSources] = useState<GroupRow[]>([])
  const [bans, setBans] = useState<Record<string, Ban[]>>({})
  const [counts, setCounts] = useState<SiteCounts>({})
  const [certs, setCerts] = useState<Certificate[]>([])
  const [watched, setWatched] = useState(0)
  const [stamp, setStamp] = useState<Date | null>(null)

  const load = useCallback(() => {
    Promise.all([
      api.get<Ov>('/stats/overview' + qs({ range })),
      api.get<Page<GroupRow>>('/attacks/groups' + qs({ range, size: 50 })),
      api.get<Record<string, Ban[]>>('/bans').catch(() => ({})),
      api.get<SiteCounts>('/site-counts'),
      api.get<Certificate[]>('/certificates'),
      api.get<Page<{ blocked: boolean }>>('/attacks' + qs({ range, size: 200 })),
    ]).then(([o, g, b, c, ce, a]) => {
      // ranked by how much each source sent; a source let through in Watch never leads the finding
      setOv(o); setSources(g.items); setBans(b); setCounts(c); setCerts(ce)
      setWatched(a.items.filter((x) => !x.blocked).length)
      setStamp(new Date())
    }).catch(notifyError)
  }, [range, notifyError])
  useEffect(() => { load() }, [load])
  useInterval(load, 60_000)

  const act = useMemo(() => Object.fromEntries((ov?.actions ?? []).map((a) => [a.key, a.count])), [ov])
  const requests = ov?.requests ?? 0
  const held = stages.reduce((n, s) => n + (act[s.key] ?? 0), 0)
  const reached = requests - held

  const watchSites = new Set(sites.filter((s) => s.resolved.waf.mode === 'detect').map((s) => s.id))
  const ranked = [...sources].sort((a, b) => b.count - a.count || b.last.localeCompare(a.last))
  const top = ranked.find((g) => !watchSites.has(g.site_id))
  const topBan = top ? (bans[top.site_id] ?? []).find((b) => b.ip === top.client_ip) : undefined
  const denyTop = async () => {
    if (!top) return
    try {
      await api.post('/rules', { name: `Refuse ${top.client_ip}`, enabled: true, action: 'block', sites: [], match: { ip: [top.client_ip] }, priority: 0 })
      notify(`${top.client_ip} is now refused on every site`)
    } catch (e) {
      notifyError(e)
    }
  }

  const banRows = Object.entries(bans).flatMap(([s, list]) => list.map((b) => ({ site: s, ...b })))
  const attention: { text: React.ReactNode; to: string; action: string }[] = []
  for (const c of certs) {
    const d = daysLeft(c.not_after)
    if (d <= 21) attention.push({ text: <>Certificate for <strong>{c.dns_names?.[0] ?? c.name}</strong> expires in <strong className="warn-text">{d} days</strong></>, to: '/settings/certificates', action: 'Replace' })
  }
  for (const s of sites) {
    if (s.resolved.waf.mode === 'detect') attention.push({ text: <><strong>{siteName(s)}</strong> is in Watch: threats are logged and let through</>, to: `/threats?site=${s.id}`, action: 'Review' })
  }
  for (const b of banRows) {
    attention.push({ text: <><strong>{b.ip}</strong> is banned on {siteName(siteById[b.site], b.site)} until {clock(b.until)}</>, to: '/access?tab=bans', action: 'Bans' })
  }

  const finding = top
    ? <>{top.client_ip} ({countryName(top.country)}) sent <strong>{top.count} attacks</strong> to {siteName(siteById[top.site_id], top.site_id)} {top.count > 1 ? <>between {clock(top.first)} and {clock(top.last)}</> : <>at {clock(top.last)}</>}{topBan ? <>; it is banned until {clock(topBan.until)}</> : null}.</>
    : <>No threats in the last {range === '24h' ? '24 hours' : '7 days'}.</>

  // the newest source on a blocking site decides the status line: under attack within 15 minutes
  const newest = [...sources].filter((g) => !watchSites.has(g.site_id)).sort((a, b) => b.last.localeCompare(a.last))[0]
  const active = newest && Date.now() - new Date(newest.last).getTime() < 15 * 60_000 ? newest : undefined
  const status = !ov ? null : active ? (
    <p className="alert-line" role="status"><span className="beacon" aria-hidden="true" />
      Under attack: {active.client_ip} is hitting {siteName(siteById[active.site_id], active.site_id)}, last {ago(active.last)}</p>
  ) : (
    <p className="alert-line calm" role="status"><span className="beacon" aria-hidden="true" />
      {newest ? `Quiet: the last stopped threat was ${ago(newest.last)}` : 'Quiet: nothing has been stopped in this window'}</p>
  )
  const last = ov?.series[ov.series.length - 1]
  const perSecond = last && ov ? last.requests / Math.max(1, ov.step_sec) : 0

  const chartDraw = (el: HTMLDivElement) => {
    if (!ov) return
    const step = ov.step_sec
    const labels = ov.series.map((p) => {
      const d = new Date(p.t)
      return step >= 86400 || (step >= 6 * 3600) ? `${d.getMonth() + 1}/${d.getDate()} ${String(d.getHours()).padStart(2, '0')}h` : clock(d)
    })
    const res = window.Charts.line(el, {
      labels, height: 300, format: window.Charts.fmt.int,
      series: [
        { name: 'Requests', values: ov.series.map((p) => p.requests) },
        { name: 'Stopped', values: ov.series.map((p) => p.blocked), colour: '#4a8ad6' },
      ],
    })
    const legendSlot = el.parentElement?.querySelector('.legend-slot')
    if (legendSlot && res && res.legend) { legendSlot.innerHTML = ''; legendSlot.appendChild(res.legend) }
  }

  const typeDraw = (el: HTMLDivElement) => {
    const rows = (ov?.attack_types ?? []).map((c) => ({ label: categoryLabel(c.key), value: c.count }))
    if (!rows.length) { el.innerHTML = ''; return }
    window.Charts.barList(el, rows, { thin: true, colour: '#4a8ad6' })
  }

  const ordered = [...sites].sort((a, b) => (counts[b.id]?.requests ?? 0) - (counts[a.id]?.requests ?? 0)).slice(0, 5)

  return (
    <>
      <div className="title-row">
        <div>
          <h1>Overview</h1>
          <p className="sub">{finding}</p>
          {status}
        </div>
        <div className="actions">
          <Segmented label="Time window" value={range} onChange={setRange} options={[{ value: '24h', label: '24 hours' }, { value: '7d', label: '7 days' }]} />
          <span className="stamp">{stamp ? `Updated ${clock(stamp)}` : 'Loading'}</span>
          <IconBtn icon="refresh" label="Refresh" onClick={load} />
          {top && <Btn kind="primary" onClick={denyTop}>Refuse {top.client_ip} everywhere</Btn>}
        </div>
      </div>

      <section className="panel" aria-labelledby="cp-title" style={{ marginBottom: 'var(--gap)' }}>
        <header>
          <h2 id="cp-title">Where requests stopped</h2>
          <span className="meta">Each request passes the stages left to right; the first one that refuses it ends its trip.</span>
        </header>
        <Flow requests={requests} stops={act} perSecond={perSecond} />
        <div className="checkpoints">
          <div className="cp">
            <div className="cp-name">Requests in</div>
            <div className="cp-value lead num">{int(requests)}</div>
            <div className="cp-bar ink"><span style={{ width: '100%' }} /></div>
            <div className="cp-note">{ov ? `${int(ov.unique_ips)} client IPs` : ''}</div>
          </div>
          {stages.map((s) => {
            const n = act[s.key] ?? 0
            return (
              <div key={s.key} className={'cp' + (n ? '' : ' off')}>
                <div className="cp-name" title={s.name}>{s.name}</div>
                <div className="cp-value num">{int(n)}</div>
                <div className="cp-bar"><span style={{ width: requests ? `${Math.max(n ? 2 : 0, (n / requests) * 100)}%` : 0 }} /></div>
                <div className="cp-note">{s.key === 'block' && watched ? `${s.note(n)}; ${watched} more watched` : s.note(n)}</div>
              </div>
            )
          })}
          <div className="cp">
            <div className="cp-name">Reached the origin</div>
            <div className="cp-value lead num">{int(reached)}</div>
            <div className="cp-bar ink"><span style={{ width: requests ? `${(reached / requests) * 100}%` : 0 }} /></div>
            <div className="cp-note">{pct(reached, requests)} of requests{act.allow ? `, ${int(act.allow)} by allow rule` : ''}</div>
          </div>
        </div>
      </section>

      <div className="grid top">
        <section className="panel span-7" aria-labelledby="tr-title">
          <header>
            <h2 id="tr-title">Requests and stops</h2>
            <div className="legend-slot meta" />
          </header>
          <ChartBox label="Requests and stopped requests over time" draw={chartDraw} deps={[ov]} height={300} />
        </section>

        <section className="panel span-5" aria-labelledby="src-title">
          <header>
            <h2 id="src-title">Threat sources</h2>
            <Link className="card-link" to="/threats">All threats</Link>
          </header>
          {ranked.length ? (
            <div className="radar-panel">
              <Radar sources={ranked} watchSites={watchSites} />
              <div className="rows">
                {ranked.slice(0, 5).map((g) => (
                  <button key={g.site_id + g.client_ip} type="button" className="row" onClick={() => navigate(`/threats?ip=${g.client_ip}&site=${g.site_id}`)}
                    style={{ width: '100%', border: 0, background: 'none', textAlign: 'left', cursor: 'pointer', padding: '8px 0' }}>
                    <span className="mode-dot" style={{ background: watchSites.has(g.site_id) ? 'var(--warning)' : 'var(--negative)', flex: 'none' }} aria-hidden="true" />
                    <span className="grow">
                      <span className="num" style={{ display: 'block', fontWeight: 600 }}>{g.client_ip}</span>
                      <span className="meta truncate" style={{ display: 'block' }}>{countryName(g.country)} · {siteName(siteById[g.site_id], g.site_id)}</span>
                    </span>
                    <span style={{ textAlign: 'right' }}>
                      <span className="num" style={{ display: 'block', fontWeight: 500 }}>{g.count}</span>
                      <span className="meta" style={{ display: 'block', whiteSpace: 'nowrap' }}>{when(g.last)}</span>
                    </span>
                  </button>
                ))}
              </div>
            </div>
          ) : <Empty>No threats in this window.</Empty>}
        </section>

        <section className="panel span-7 flush" aria-labelledby="sites-title">
          <header>
            <h2 id="sites-title">Sites today</h2>
            <Link className="card-link" to="/sites">All {sites.length} sites</Link>
          </header>
          <div className="table-wrap" style={{ marginTop: 4 }}>
            <table className="responsive">
              <thead>
                <tr><th>Site</th><th>Mode</th><th className="n">Requests</th><th className="n">Stopped</th></tr>
              </thead>
              <tbody>
                {ordered.map((s) => (
                  <tr key={s.id} className="clickable" onClick={() => navigate(`/sites/${s.id}`)}>
                    <td><span className="ident">{siteName(s)}</span><span className="sub truncate">{s.resolved.domains.join(', ')}</span></td>
                    <td><ModePill mode={s.resolved.waf.mode} /></td>
                    <td className="n num">{int(counts[s.id]?.requests ?? 0)}</td>
                    <td className="n num">{int(counts[s.id]?.blocked ?? 0)}</td>
                  </tr>
                ))}
              </tbody>
              <tfoot>
                <tr>
                  <td className="muted">All {sites.length} sites</td><td />
                  <td className="n num">{int(sites.reduce((n, s) => n + (counts[s.id]?.requests ?? 0), 0))}</td>
                  <td className="n num">{int(sites.reduce((n, s) => n + (counts[s.id]?.blocked ?? 0), 0))}</td>
                </tr>
              </tfoot>
            </table>
          </div>
        </section>

        <div className="span-5 stack">
          <section className="panel" aria-labelledby="att-title">
            <header><h2 id="att-title">Needs attention</h2><span className="meta num">{attention.length}</span></header>
            {attention.length ? (
              <div className="rows">
                {attention.map((a, i) => (
                  <div key={i} className="row">
                    <div className="grow">{a.text}</div>
                    <Link className="card-link" to={a.to}>{a.action}</Link>
                  </div>
                ))}
              </div>
            ) : <Empty>Nothing needs you right now.</Empty>}
          </section>
          <section className="panel" aria-labelledby="types-title">
            <header><h2 id="types-title">What the threats tried</h2><span className="meta">{range === '24h' ? 'last 24 hours' : 'last 7 days'}</span></header>
            {(ov?.attack_types ?? []).length ? <ChartBox label="Threats by kind" draw={typeDraw} deps={[ov]} /> : <Empty>No threats in this window.</Empty>}
          </section>
        </div>
      </div>
    </>
  )
}
