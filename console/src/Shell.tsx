import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { api, DEMO } from './api'
import { useApp } from './context'
import { Icon, Mark } from './ui'

const main = [
  { to: '/overview', icon: 'overview', label: 'Overview', short: 'Overview' },
  { to: '/sites', icon: 'sites', label: 'Sites', short: 'Sites' },
  { to: '/threats', icon: 'threats', label: 'Threats', short: 'Threats' },
  { to: '/access', icon: 'access', label: 'Access', short: 'Access' },
  { to: '/activity', icon: 'activity', label: 'Activity', short: 'Activity' },
]

export default function Shell() {
  const { me, setMe, system } = useApp()
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
  const edge = DEMO ? 'edge-tpe-01' : window.location.hostname

  return (
    <div className="app">
      <nav className="rail" aria-label="Main">
        <NavLink to="/overview" className="mark" aria-label="HostingInside WAF, overview"><Mark /></NavLink>
        {main.map((m) => (
          <NavLink key={m.to} to={m.to} className="rail-item" aria-label={m.label}>
            <Icon name={m.icon} />
            <span className="tip">{m.label}</span>
            <span className="short" aria-hidden="true">{m.short}</span>
          </NavLink>
        ))}
        <div className="bottom">
          <NavLink to="/settings" className="rail-item" aria-label="Settings">
            <Icon name="settings" />
            <span className="tip">Settings</span>
            <span className="short" aria-hidden="true">Settings</span>
          </NavLink>
          <button type="button" className="rail-item logout" aria-label="Sign out" onClick={logout}
            style={{ border: 0, background: 'none', width: '100%', cursor: 'pointer' }}>
            <Icon name="logout" />
            <span className="tip">Sign out {me?.username}</span>
          </button>
        </div>
      </nav>
      <main className="canvas">
        <div className="topline">
          <span className="product">HostingInside WAF</span>
          <span>·</span>
          <span>{edge}</span>
          <span className="spacer" />
          <span className={'dot' + (system && !system.engine_ok ? ' off' : '')} aria-hidden="true" />
          <span>{system ? (system.engine_ok ? 'Engine running' : 'Engine unreachable') : 'Checking engine'}</span>
          <span className="hide-phone">· {me?.username}</span>
        </div>
        <Outlet />
      </main>
    </div>
  )
}
