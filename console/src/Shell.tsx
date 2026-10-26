import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { api, DEMO } from './api'
import { useApp } from './context'
import type { SiteCounts } from './types'
import { Icon, IconBtn, Mark } from './ui'
import { int, siteName } from './util'

const pages = [
  { to: '/overview', icon: 'overview', label: 'Overview' },
  { to: '/sites', icon: 'sites', label: 'Sites' },
  { to: '/threats', icon: 'threats', label: 'Threats' },
  { to: '/access', icon: 'access', label: 'Access' },
  { to: '/activity', icon: 'activity', label: 'Activity' },
  { to: '/settings', icon: 'settings', label: 'Settings' },
]

const modeDot: Record<string, string> = { block: 'var(--positive)', detect: 'var(--warning)', off: '#5b5b60' }
const modeWord: Record<string, string> = { block: 'Blocking', detect: 'Watching', off: 'Off' }

/** The menu: a drawer from the left with the pages and every site. */
function Drawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null)
  const { sites, me, setMe } = useApp()
  const navigate = useNavigate()
  const [counts, setCounts] = useState<SiteCounts>({})
  useEffect(() => {
    const d = ref.current
    if (!d) return
    if (open && !d.open) {
      d.showModal()
      api.get<SiteCounts>('/site-counts').then(setCounts).catch(() => {})
    }
    if (!open && d.open) d.close()
  }, [open])
  const logout = async () => {
    try {
      await api.post('/auth/logout')
    } catch {
      /* the session may be gone already */
    }
    setMe(null)
    navigate('/login')
  }
  const ordered = [...sites].sort((a, b) => (counts[b.id]?.blocked ?? 0) - (counts[a.id]?.blocked ?? 0) || siteName(a).localeCompare(siteName(b)))

  return (
    <dialog ref={ref} className="drawer" aria-label="Menu" onClose={onClose} onCancel={(e) => { e.preventDefault(); onClose() }}
      onClick={(e) => { if (e.target === ref.current) onClose() }}>
      <div className="drawer-head">
        <IconBtn icon="close" label="Close the menu" onClick={onClose} />
        <Mark size={22} />
        <span className="product">HostingInside WAF</span>
      </div>
      <nav aria-label="Pages">
        {pages.map((p) => (
          <NavLink key={p.to} to={p.to} className="drawer-link" onClick={onClose}>
            <Icon name={p.icon} />
            <span>{p.label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="drawer-section">
        <span>Sites</span>
        <span className="num">{sites.length}</span>
      </div>
      <ul className="drawer-sites">
        {ordered.map((s) => (
          <li key={s.id}>
            <NavLink to={`/sites/${s.id}`} className="drawer-site" onClick={onClose} title={`${siteName(s)}: ${modeWord[s.resolved.waf.mode]}`}>
              <span className="mode-dot" style={{ background: modeDot[s.resolved.waf.mode] }} aria-label={modeWord[s.resolved.waf.mode]} />
              <span className="name">{siteName(s)}</span>
              <span className={'num stops' + ((counts[s.id]?.blocked ?? 0) > 0 ? ' hot' : '')} title="Refused or stopped today">{int(counts[s.id]?.blocked ?? 0)}</span>
            </NavLink>
          </li>
        ))}
      </ul>
      <NavLink to="/sites/new" className="drawer-add" onClick={onClose}><Icon name="plus" /> Add a site</NavLink>
      <div className="drawer-foot">
        <span className="muted">Signed in as {me?.username}</span>
        <button type="button" className="card-link" onClick={logout}>Sign out</button>
      </div>
    </dialog>
  )
}

export default function Shell() {
  const { system } = useApp()
  const [open, setOpen] = useState(() => DEMO && new URLSearchParams(window.location.hash.split('?')[1]).get('menu') === '1')
  const loc = useLocation()
  useEffect(() => { if (!DEMO || !loc.search.includes('menu=1')) setOpen(false) }, [loc.pathname, loc.search])
  const edge = DEMO ? 'edge-tpe-01' : window.location.hostname

  return (
    <div className="app">
      <header className="topbar">
        <button type="button" className="menu-btn" aria-label="Open the menu" aria-expanded={open} onClick={() => setOpen(true)}>
          <span /><span /><span />
        </button>
        <NavLink to="/overview" className="brand" aria-label="HostingInside WAF, overview"><Mark size={24} /><span className="product">HostingInside WAF</span></NavLink>
        <span className="edge hide-phone">{edge}</span>
        <span className="spacer" />
        <span className={'dot' + (system && !system.engine_ok ? ' off' : '')} aria-hidden="true" />
        <span className="engine">{system ? (system.engine_ok ? 'Engine running' : 'Engine unreachable') : 'Checking engine'}</span>
      </header>
      <Drawer open={open} onClose={() => setOpen(false)} />
      <main className="canvas">
        <Outlet />
      </main>
    </div>
  )
}
