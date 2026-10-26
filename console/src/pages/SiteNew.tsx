import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, errText } from '../api'
import { useApp } from '../context'
import type { Certificate, SiteView } from '../types'
import { Btn, ChipsInput, Field } from '../ui'

type Kind = 'proxy' | 'static' | 'redirect'

/** One page, in the order an engineer thinks about a new customer site:
 *  which names it answers, where the content lives, then how it is encrypted. */
export default function SiteNew() {
  const { reloadSites, notify, system } = useApp()
  const navigate = useNavigate()
  const [domains, setDomains] = useState<string[]>([])
  const [name, setName] = useState('')
  const [kind, setKind] = useState<Kind>('proxy')
  const [origins, setOrigins] = useState('')
  const [target, setTarget] = useState('')
  const [keepPath, setKeepPath] = useState(true)
  const [tls, setTls] = useState('auto')
  const [httpPort, setHttpPort] = useState(system?.http_port ?? 80)
  const [httpsPort, setHttpsPort] = useState(system?.https_port ?? 443)
  const [certs, setCerts] = useState<Certificate[]>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { api.get<Certificate[]>('/certificates').then(setCerts).catch(() => {}) }, [])

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr('')
    const doms = domains.length ? domains : ['*']
    const encrypted = tls !== 'off'
    if (doms.includes('*') && encrypted) {
      setErr('A site that answers any host name cannot be encrypted. Add its domain, or choose "No encryption".')
      return
    }
    const doc: Record<string, unknown> = {
      name: name.trim() || undefined, type: kind, domains: doms,
      ports: encrypted ? [{ port: httpPort, https: false }, { port: httpsPort, https: true }] : [{ port: httpPort, https: false }],
      tls: tls === 'auto' ? { mode: 'auto' } : tls === 'off' ? { mode: 'off' } : { mode: 'uploaded', cert_id: tls },
    }
    if (kind === 'proxy') doc.upstreams = origins.split(/[\s,]+/).filter(Boolean)
    if (kind === 'redirect') doc.redirect = { url: target.trim(), code: 301, preserve_path: keepPath }
    setBusy(true)
    try {
      const s = await api.post<SiteView>('/sites', doc)
      await reloadSites()
      notify(`${s.resolved.name || s.resolved.domains[0]} is behind the WAF`)
      navigate(`/sites/${s.id}`)
    } catch (e) {
      setErr(errText(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={save}>
      <div className="title-row">
        <div>
          <h1>Add a site</h1>
          <p className="sub">It starts in Block with the default rule set, attack and error limits. Tune each guard on the next page.</p>
        </div>
        <div className="actions">
          <Btn onClick={() => navigate('/sites')}>Cancel</Btn>
          <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Adding' : 'Add site'}</button>
        </div>
      </div>
      {err && <p className="notice" role="alert" style={{ marginBottom: 'var(--gap)' }}>{err}</p>}
      <section className="panel" style={{ paddingTop: 0, paddingBottom: 0 }}>
        <div className="setting">
          <div><h2>Host names</h2><p className="desc">The names visitors type. The WAF answers only these; point their DNS at this server.</p></div>
          <div style={{ display: 'grid', gap: 16 }}>
            <Field label="Domains" id="domains" hint="Press Enter after each one. A leading *. covers every subdomain. Leave empty to answer any host on plain HTTP.">
              <ChipsInput id="domains" value={domains} onChange={(v) => setDomains(v.map((d) => d.toLowerCase()))} placeholder="shop.lanterntea.com.tw" />
            </Field>
            <Field label="Name in the console" id="name">
              <input id="name" className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} placeholder="Defaults to the first domain" />
            </Field>
          </div>
        </div>
        <div className="setting">
          <div><h2>Where the content lives</h2><p className="desc">Clean requests go here after every guard has let them through.</p></div>
          <div style={{ display: 'grid', gap: 16 }}>
            <div style={{ display: 'grid', gap: 10 }} role="radiogroup" aria-label="Where the content lives">
              {([
                ['proxy', 'On the customer’s server', 'Forward to one or more origins; several are load-balanced.'],
                ['static', 'In files kept on the WAF', 'Upload a .zip on the site page after adding it.'],
                ['redirect', 'Somewhere else', 'Send every visitor to another address.'],
              ] as [Kind, string, string][]).map(([v, l, h]) => (
                <label key={v} className="check" style={{ alignItems: 'flex-start' }}>
                  <input type="radio" name="kind" checked={kind === v} onChange={() => setKind(v)} style={{ marginTop: 2 }} />
                  <span><span style={{ fontWeight: 500 }}>{l}</span><span className="muted" style={{ display: 'block' }}>{h}</span></span>
                </label>
              ))}
            </div>
            {kind === 'proxy' && (
              <Field label="Origins" id="origins" hint="host:port, or http(s)://host:port. Separate several with a comma.">
                <input id="origins" className="input" required value={origins} onChange={(e) => setOrigins(e.target.value)} placeholder="10.20.1.15:8080" />
              </Field>
            )}
            {kind === 'redirect' && (
              <>
                <Field label="Send visitors to" id="target">
                  <input id="target" className="input" required type="url" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://lanterntea.com.tw" />
                </Field>
                <label className="check"><input type="checkbox" checked={keepPath} onChange={(e) => setKeepPath(e.target.checked)} />Keep the path they asked for</label>
              </>
            )}
          </div>
        </div>
        <div className="setting">
          <div><h2>Encryption</h2><p className="desc">HTTPS on {httpsPort}; plain HTTP on {httpPort} redirects to it.</p></div>
          <div style={{ display: 'grid', gap: 16 }}>
            <Field label="Certificate" id="tls">
              <select id="tls" className="input select" value={tls} onChange={(e) => setTls(e.target.value)}>
                <option value="auto">Issue and renew one automatically</option>
                {certs.map((c) => <option key={c.id} value={c.id}>Uploaded: {c.name}</option>)}
                <option value="off">No encryption (plain HTTP only)</option>
              </select>
            </Field>
            <details>
              <summary className="muted" style={{ cursor: 'pointer' }}>Other ports</summary>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 12 }}>
                <Field label="HTTP port" id="hp"><input id="hp" className="input num" type="number" value={httpPort} onChange={(e) => setHttpPort(Number(e.target.value))} /></Field>
                <Field label="HTTPS port" id="sp"><input id="sp" className="input num" type="number" value={httpsPort} disabled={tls === 'off'} onChange={(e) => setHttpsPort(Number(e.target.value))} /></Field>
              </div>
            </details>
          </div>
        </div>
      </section>
    </form>
  )
}
