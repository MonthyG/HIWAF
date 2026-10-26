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
const PHONE = '(max-width: 860px)'

/** The menu's content: the pages, then every site. Shared by the sidebar and the phone drawer. */
function Menu({ onNavigate, counts }: { onNavigate?: () => void; counts: SiteCounts }) {
  const { sites, me, setMe } = useApp()
  const navigate = useNavigate()
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
    <>
      <nav aria-label="Pages">
        {pages.map((p) => (
          <NavLink key={p.to} to={p.to} className="drawer-link" onClick={onNavigate}>
            <Icon name={p.icon} />
            <span>{p.label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="drawer-section"><span>Sites</span><span className="num">{sites.length}</span></div>
      <ul className="drawer-sites">
        {ordered.map((s) => (
          <li key={s.id}>
            <NavLink to={`/sites/${s.id}`} className="drawer-site" onClick={onNavigate} title={`${siteName(s)}: ${modeWord[s.resolved.waf.mode]}`}>
              <span className="mode-dot" style={{ background: modeDot[s.resolved.waf.mode] }} aria-label={modeWord[s.resolved.waf.mode]} />
              <span className="name">{siteName(s)}</span>
              <span className={'num stops' + ((counts[s.id]?.blocked ?? 0) > 0 ? ' hot' : '')} title="Refused or stopped today">{int(counts[s.id]?.blocked ?? 0)}</span>
            </NavLink>
          </li>
        ))}
      </ul>
      <NavLink to="/sites/new" className="drawer-add" onClick={onNavigate}><Icon name="plus" /> Add a site</NavLink>
      <div className="drawer-foot">
        <span className="muted truncate">Signed in as {me?.username}</span>
        <button type="button" className="card-link" onClick={logout}>Sign out</button>
      </div>
    </>
  )
}

/** On phones the menu opens as a drawer over the page. */
function Drawer({ open, onClose, counts }: { open: boolean; onClose: () => void; counts: SiteCounts }) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const d = ref.current
    if (!d) return
    if (open && !d.open) d.showModal()
    if (!open && d.open) d.close()
  }, [open])
  return (
    <dialog ref={ref} className="drawer" aria-label="Menu" onClose={onClose} onCancel={(e) => { e.preventDefault(); onClose() }}
      onClick={(e) => { if (e.target === ref.current) onClose() }}>
      <div className="drawer-head">
        <IconBtn icon="close" label="Close the menu" onClick={onClose} />
        <Mark size={22} />
        <span className="product">HostingInside WAF</span>
      </div>
      {open && <Menu onNavigate={onClose} counts={counts} />}
    </dialog>
  )
}

function readHidden(): boolean {
  try {
    return localStorage.getItem('hiwaf.sidebar') === 'hidden'
  } catch {
    return false
  }
}

export default function Shell() {
  const { system, sites } = useApp()
  const loc = useLocation()
  const [drawer, setDrawer] = useState(() => DEMO && new URLSearchParams(window.location.hash.split('?')[1]).get('menu') === '1')
  const [hidden, setHidden] = useState(readHidden)
  const [counts, setCounts] = useState<SiteCounts>({})
  useEffect(() => { if (!DEMO || !loc.search.includes('menu=1')) setDrawer(false) }, [loc.pathname, loc.search])
  useEffect(() => { api.get<SiteCounts>('/site-counts').then(setCounts).catch(() => {}) }, [loc.pathname, sites.length])

  const toggle = () => {
    if (window.matchMedia(PHONE).matches) { setDrawer(true); return }
    const next = !hidden
    setHidden(next)
    try { localStorage.setItem('hiwaf.sidebar', next ? 'hidden' : 'shown') } catch { /* per-browser preference only */ }
  }
  const edge = DEMO ? 'edge-tpe-01' : window.location.hostname

  return (
    <div className={'app' + (hidden ? ' sidebar-hidden' : '')}>
      <aside className="sidebar" aria-label="Menu">
        <NavLink to="/overview" className="sidebar-brand" aria-label="HostingInside WAF, overview"><Mark size={24} /><span className="product">HostingInside WAF</span></NavLink>
        <Menu counts={counts} />
      </aside>
      <div className="main-col">
        <header className="topbar">
          <button type="button" className="menu-btn" aria-label={hidden ? 'Show the menu' : 'Menu'} onClick={toggle}>
            <span /><span /><span />
          </button>
          <NavLink to="/overview" className="brand topbar-brand" aria-label="HostingInside WAF, overview"><Mark size={24} /><span className="product">HostingInside WAF</span></NavLink>
          <span className="edge">{edge}</span>
          <span className="spacer" />
          <span className={'dot' + (system && !system.engine_ok ? ' off' : '')} aria-hidden="true" />
          <span className="engine">{system ? (system.engine_ok ? 'Engine running' : 'Engine unreachable') : 'Checking engine'}</span>
        </header>
        <main className="canvas">
          <Outlet />
        </main>
      </div>
      <Drawer open={drawer} onClose={() => setDrawer(false)} counts={counts} />
    </div>
  )
}
