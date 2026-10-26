import { useState, type ReactNode } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import {
  Box, Breadcrumbs, Collapse, Divider, IconButton, Link, List, ListItemButton, ListItemIcon, ListItemText,
  Menu, MenuItem, Stack, Tooltip, Typography,
} from '@mui/material'
import BarChartIcon from '@mui/icons-material/BarChartOutlined'
import ShieldIcon from '@mui/icons-material/ShieldOutlined'
import ReportIcon from '@mui/icons-material/GppMaybeOutlined'
import RuleIcon from '@mui/icons-material/RuleOutlined'
import BoltIcon from '@mui/icons-material/BoltOutlined'
import SmartToyIcon from '@mui/icons-material/SmartToyOutlined'
import KeyIcon from '@mui/icons-material/VpnKeyOutlined'
import SettingsIcon from '@mui/icons-material/SettingsOutlined'
import ExpandLess from '@mui/icons-material/ExpandLess'
import ExpandMore from '@mui/icons-material/ExpandMore'
import LogoutIcon from '@mui/icons-material/Logout'
import AccountCircle from '@mui/icons-material/AccountCircleOutlined'
import { api } from '../api'
import { useApp } from '../context'
import { brand } from '../theme'

const SIDEBAR = 220

interface NavItem {
  label: string
  to: string
  icon: ReactNode
  children?: { label: string; to: string }[]
}

const nav: NavItem[] = [
  { label: 'Statistics', to: '/statistics', icon: <BarChartIcon fontSize="small" /> },
  { label: 'Applications', to: '/applications', icon: <ShieldIcon fontSize="small" /> },
  { label: 'Attacks', to: '/attacks', icon: <ReportIcon fontSize="small" /> },
  { label: 'Allow & Deny', to: '/allow-deny', icon: <RuleIcon fontSize="small" /> },
  {
    label: 'HTTP Flood', to: '/http-flood', icon: <BoltIcon fontSize="small" />,
    children: [
      { label: 'Rate Limiting', to: '/http-flood/limits' },
      { label: 'Waiting Room', to: '/http-flood/waiting-room' },
    ],
  },
  { label: 'Anti-Bot', to: '/anti-bot', icon: <SmartToyIcon fontSize="small" /> },
  { label: 'Auth', to: '/auth', icon: <KeyIcon fontSize="small" /> },
  { label: 'Settings', to: '/settings', icon: <SettingsIcon fontSize="small" /> },
]

const crumbNames: Record<string, string> = {
  statistics: 'Statistics', applications: 'Applications', attacks: 'Attacks', 'allow-deny': 'Allow & Deny',
  'http-flood': 'HTTP Flood', limits: 'Rate Limiting', 'waiting-room': 'Waiting Room', 'anti-bot': 'Anti-Bot',
  auth: 'Auth', settings: 'Settings',
}

export function Logo() {
  return (
    <Stack direction="row" alignItems="center" spacing={1}>
      <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden>
        <path d="M16 2 4 6.5v8.2c0 7.3 5.1 13.6 12 15.3 6.9-1.7 12-8 12-15.3V6.5L16 2z" fill={brand} />
        <path d="m11 16 3.6 3.6L21.5 12.6" fill="none" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <Typography sx={{ fontWeight: 800, fontSize: 15, letterSpacing: -0.2 }}>HostingInside WAF</Typography>
    </Stack>
  )
}

export default function Layout() {
  const loc = useLocation()
  const navigate = useNavigate()
  const { me, setMe, siteById, system } = useApp()
  const [open, setOpen] = useState<Record<string, boolean>>({ '/http-flood': loc.pathname.startsWith('/http-flood') })
  const [menu, setMenu] = useState<HTMLElement | null>(null)

  const parts = loc.pathname.split('/').filter(Boolean)
  const logout = async () => {
    try {
      await api.post('/auth/logout')
    } catch {
      /* the session may already be gone */
    }
    setMe(null)
    navigate('/login')
  }

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      <Box
        component="nav"
        sx={{
          width: SIDEBAR, flexShrink: 0, bgcolor: '#fff', borderRight: '1px solid #e6ebee', display: 'flex',
          flexDirection: 'column', position: 'sticky', top: 0, height: '100vh',
        }}
      >
        <Box sx={{ px: 2.5, py: 2.2 }}>
          <Logo />
        </Box>
        <List sx={{ px: 1.2, flex: 1 }}>
          {nav.map((item) => {
            const active = loc.pathname.startsWith(item.to)
            if (item.children) {
              return (
                <Box key={item.to}>
                  <ListItemButton
                    onClick={() => setOpen((o) => ({ ...o, [item.to]: !o[item.to] }))}
                    sx={navSx(active && !open[item.to])}
                  >
                    <ListItemIcon sx={{ minWidth: 32, color: 'inherit' }}>{item.icon}</ListItemIcon>
                    <ListItemText primary={item.label} primaryTypographyProps={{ fontSize: 13.5 }} />
                    {open[item.to] ? <ExpandLess fontSize="small" /> : <ExpandMore fontSize="small" />}
                  </ListItemButton>
                  <Collapse in={open[item.to]}>
                    {item.children.map((c) => (
                      <ListItemButton key={c.to} component={NavLink} to={c.to} sx={{ ...navSx(loc.pathname === c.to), pl: 5.5 }}>
                        <ListItemText primary={c.label} primaryTypographyProps={{ fontSize: 13 }} />
                      </ListItemButton>
                    ))}
                  </Collapse>
                </Box>
              )
            }
            return (
              <ListItemButton key={item.to} component={NavLink} to={item.to} sx={navSx(active)}>
                <ListItemIcon sx={{ minWidth: 32, color: 'inherit' }}>{item.icon}</ListItemIcon>
                <ListItemText primary={item.label} primaryTypographyProps={{ fontSize: 13.5 }} />
              </ListItemButton>
            )
          })}
        </List>
        <Box sx={{ px: 2.5, py: 2, color: 'text.secondary', fontSize: 12 }}>
          <Typography sx={{ fontFamily: 'ui-monospace, Consolas, monospace', fontSize: 12 }}>
            Version {system?.version ?? '-'}
          </Typography>
          <Typography sx={{ fontSize: 12, mt: 0.5 }}>
            Engine{' '}
            <Box component="span" sx={{ color: system?.engine_ok ? 'success.main' : 'error.main', fontWeight: 600 }}>
              {system ? (system.engine_ok ? 'online' : 'offline') : '-'}
            </Box>
          </Typography>
        </Box>
      </Box>

      <Box sx={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
        <Stack
          direction="row"
          alignItems="center"
          sx={{ px: 3, height: 56, bgcolor: '#fff', borderBottom: '1px solid #e6ebee', position: 'sticky', top: 0, zIndex: 10 }}
        >
          <Breadcrumbs sx={{ flex: 1, fontSize: 13 }}>
            <Link underline="hover" color="inherit" component={NavLink} to="/statistics">
              HostingInside WAF
            </Link>
            {parts.map((p, i) => (
              <Typography key={i} sx={{ fontSize: 13, color: i === parts.length - 1 ? 'text.primary' : 'text.secondary' }}>
                {crumbNames[p] ?? (siteById[p] ? siteById[p].resolved.name || siteById[p].resolved.domains[0] : p)}
              </Typography>
            ))}
          </Breadcrumbs>
          <Tooltip title={me?.username ?? ''}>
            <IconButton onClick={(e) => setMenu(e.currentTarget)} size="small">
              <AccountCircle />
            </IconButton>
          </Tooltip>
          <Menu anchorEl={menu} open={!!menu} onClose={() => setMenu(null)}>
            <MenuItem disabled sx={{ fontSize: 13 }}>Signed in as {me?.username}</MenuItem>
            <Divider />
            <MenuItem onClick={() => { setMenu(null); navigate('/settings?tab=account') }} sx={{ fontSize: 13 }}>
              Account & 2FA
            </MenuItem>
            <MenuItem onClick={logout} sx={{ fontSize: 13 }}>
              <LogoutIcon fontSize="small" sx={{ mr: 1 }} /> Sign out
            </MenuItem>
          </Menu>
        </Stack>
        <Box sx={{ p: 3, flex: 1, minWidth: 0 }}>
          <Outlet />
        </Box>
      </Box>
    </Box>
  )
}

function navSx(active: boolean) {
  return {
    borderRadius: 1.5,
    mb: 0.4,
    py: 0.8,
    color: active ? '#fff' : 'text.primary',
    bgcolor: active ? brand : 'transparent',
    boxShadow: active ? '0 4px 12px rgba(15,165,160,.25)' : 'none',
    '&:hover': { bgcolor: active ? brand : 'rgba(15,165,160,.08)' },
  }
}
