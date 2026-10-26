import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Box, Button, Card, Chip, Grid2 as Grid, IconButton, InputAdornment, Menu, MenuItem, Stack, TextField, Typography,
} from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import SearchIcon from '@mui/icons-material/Search'
import MoreIcon from '@mui/icons-material/MoreHoriz'
import LanguageIcon from '@mui/icons-material/LanguageOutlined'
import LanIcon from '@mui/icons-material/LanOutlined'
import { api } from '../api'
import { useApp } from '../context'
import type { SiteView } from '../types'
import AppDialog from '../components/AppDialog'
import { Confirm, Empty, ModeChip, PageTitle, siteName } from '../components/common'
import { fmtNum } from '../util'

type Counts = Record<string, { requests: number; blocked: number }>

export default function Applications() {
  const { sites, sitesLoaded, reloadSites, notify, notifyError } = useApp()
  const navigate = useNavigate()
  const [q, setQ] = useState('')
  const [counts, setCounts] = useState<Counts>({})
  const [dialog, setDialog] = useState<{ open: boolean; site?: SiteView }>({ open: false })
  const [modeMenu, setModeMenu] = useState<{ el: HTMLElement; site: SiteView } | null>(null)
  const [more, setMore] = useState<{ el: HTMLElement; site: SiteView } | null>(null)
  const [del, setDel] = useState<SiteView | null>(null)

  const loadCounts = useCallback(() => api.get<Counts>('/site-counts').then(setCounts).catch(() => {}), [])
  useEffect(() => { loadCounts() }, [loadCounts])

  const shown = useMemo(() => {
    const t = q.trim().toLowerCase()
    if (!t) return sites
    return sites.filter((s) => siteName(s).toLowerCase().includes(t) || s.resolved.domains.some((d) => d.includes(t)) ||
      (s.resolved.upstreams ?? []).some((u) => u.includes(t)))
  }, [sites, q])

  const patch = async (s: SiteView, body: Record<string, unknown>, msg: string) => {
    try {
      await api.patch(`/sites/${s.id}`, body)
      await reloadSites()
      notify(msg)
    } catch (e) {
      notifyError(e)
    }
  }

  const setMode = (s: SiteView, mode: string) => patch(s, { waf: { ...(s.doc.waf ?? {}), mode } }, 'Protection mode updated')

  return (
    <>
      <PageTitle
        title={`${sites.length} Application${sites.length === 1 ? '' : 's'}`}
        actions={
          <Stack direction="row" spacing={1.5}>
            <TextField
              placeholder="Search application" value={q} onChange={(e) => setQ(e.target.value)} sx={{ width: 260 }}
              InputProps={{ startAdornment: <InputAdornment position="start"><SearchIcon fontSize="small" /></InputAdornment> }}
            />
            <Button variant="contained" startIcon={<AddIcon />} onClick={() => setDialog({ open: true })}>Add Application</Button>
          </Stack>
        }
      />
      {sitesLoaded && !sites.length && (
        <Card sx={{ p: 6, textAlign: 'center', borderRadius: 2 }}>
          <Typography variant="h6">No applications yet</Typography>
          <Typography sx={{ color: 'text.secondary', mt: 1, mb: 2 }}>
            Add an application to put a website behind the WAF: enter its domain and the server it runs on.
          </Typography>
          <Button variant="contained" startIcon={<AddIcon />} onClick={() => setDialog({ open: true })}>Add Application</Button>
        </Card>
      )}
      {sitesLoaded && sites.length > 0 && !shown.length && <Empty text="No application matches the search." />}
      <Grid container spacing={2}>
        {shown.map((s) => {
          const r = s.resolved
          const c = counts[s.id] ?? { requests: 0, blocked: 0 }
          const toggles = [
            { label: 'HTTP FLOOD', on: !!r.rate_limit.access, to: '/http-flood/limits' },
            { label: 'BOT PROTECT', on: r.bot_challenge.enabled, to: '/anti-bot' },
            { label: 'AUTH', on: r.auth.enabled, to: '/auth' },
          ]
          return (
            <Grid key={s.id} size={{ xs: 12, md: 6, xl: 4 }}>
              <Card sx={{ borderRadius: 2, display: 'flex', '&:hover': { boxShadow: '0 6px 20px rgba(16,24,40,.08)' } }}>
                <Stack alignItems="center" spacing={1.2} sx={{ width: 120, py: 2.5, borderRight: '1px solid #eef1f3', bgcolor: '#fafbfc' }}>
                  <Box sx={{ width: 44, height: 44, borderRadius: '50%', bgcolor: 'rgba(15,165,160,.1)', display: 'grid', placeItems: 'center', color: 'primary.main' }}>
                    <LanguageIcon />
                  </Box>
                  <ModeChip mode={r.waf.mode} onClick={(e) => setModeMenu({ el: e.currentTarget, site: s })} />
                  <Stack direction="row" spacing={2} sx={{ pt: 0.5 }}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography sx={{ fontSize: 10.5, color: 'text.secondary' }}>RQS TD</Typography>
                      <Typography sx={{ fontWeight: 700 }}>{fmtNum(c.requests)}</Typography>
                    </Box>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography sx={{ fontSize: 10.5, color: 'text.secondary' }}>BLK TD</Typography>
                      <Typography sx={{ fontWeight: 700, color: c.blocked ? 'error.main' : 'text.primary' }}>{fmtNum(c.blocked)}</Typography>
                    </Box>
                  </Stack>
                </Stack>
                <Box sx={{ flex: 1, p: 2, minWidth: 0 }}>
                  <Stack direction="row" alignItems="center">
                    <Typography sx={{ fontWeight: 700, fontSize: 15, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {siteName(s)}
                    </Typography>
                    <Button size="small" onClick={() => navigate(`/applications/${s.id}`)}>DETAIL</Button>
                    <IconButton size="small" onClick={(e) => setMore({ el: e.currentTarget, site: s })}><MoreIcon fontSize="small" /></IconButton>
                  </Stack>
                  <Stack spacing={0.6} sx={{ mt: 1, fontSize: 13 }}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <LanguageIcon sx={{ fontSize: 15, color: 'text.secondary' }} />
                      <Typography sx={{ fontSize: 13, color: 'text.secondary' }}>Domain:</Typography>
                      <Typography sx={{ fontSize: 13, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {r.domains.map((d) => (d === '*' ? 'Match All Host' : d)).join(', ')}
                      </Typography>
                    </Stack>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <LanIcon sx={{ fontSize: 15, color: 'text.secondary' }} />
                      <Typography sx={{ fontSize: 13, color: 'text.secondary' }}>Port:</Typography>
                      <Typography sx={{ fontSize: 13, fontFamily: 'ui-monospace,Consolas,monospace', color: 'primary.main' }}>
                        {r.ports.map((p) => `${p.port}${p.https ? '/HTTPS' : ''}`).join('  ')}
                      </Typography>
                    </Stack>
                    <Typography sx={{ fontSize: 12, color: 'text.secondary', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {r.type === 'proxy' ? `→ ${(r.upstreams ?? []).join(', ')}` : r.type === 'static' ? 'Static files' : `↪ ${r.redirect.url}`}
                    </Typography>
                  </Stack>
                  <Stack direction="row" spacing={1} sx={{ mt: 1.5 }}>
                    {toggles.map((t) => (
                      <Chip
                        key={t.label} size="small" label={t.label} variant="outlined" onClick={() => navigate(t.to)}
                        sx={{ flex: 1, borderRadius: 1, fontSize: 11, color: t.on ? 'primary.main' : 'text.secondary', borderColor: t.on ? 'primary.main' : '#dfe5e9', bgcolor: t.on ? 'rgba(15,165,160,.06)' : 'transparent' }}
                      />
                    ))}
                    <Chip
                      size="small" label="ATTACKS" onClick={() => navigate(`/attacks?site=${s.id}`)}
                      sx={{ flex: 1, borderRadius: 1, fontSize: 11, color: 'primary.main', border: '1px solid', borderColor: 'primary.main', bgcolor: 'transparent' }}
                    />
                  </Stack>
                </Box>
              </Card>
            </Grid>
          )
        })}
      </Grid>

      <Menu anchorEl={modeMenu?.el} open={!!modeMenu} onClose={() => setModeMenu(null)}>
        {[['block', 'Defense', 'Block attacks'], ['detect', 'Audit', 'Log attacks, block nothing'], ['off', 'Disabled', 'No WAF inspection']].map(([m, l, h]) => (
          <MenuItem key={m} selected={modeMenu?.site.resolved.waf.mode === m} onClick={() => { const s = modeMenu!.site; setModeMenu(null); setMode(s, m) }}>
            <Box>
              <Typography sx={{ fontWeight: 600, fontSize: 13 }}>{l}</Typography>
              <Typography sx={{ fontSize: 12, color: 'text.secondary' }}>{h}</Typography>
            </Box>
          </MenuItem>
        ))}
      </Menu>
      <Menu anchorEl={more?.el} open={!!more} onClose={() => setMore(null)}>
        <MenuItem onClick={() => { setDialog({ open: true, site: more!.site }); setMore(null) }}>Edit</MenuItem>
        <MenuItem onClick={() => { navigate(`/applications/${more!.site.id}`); setMore(null) }}>Protection settings</MenuItem>
        <MenuItem sx={{ color: 'error.main' }} onClick={() => { setDel(more!.site); setMore(null) }}>Delete</MenuItem>
      </Menu>

      <AppDialog
        open={dialog.open} site={dialog.site} onClose={() => setDialog({ open: false })}
        onSaved={async (s) => {
          setDialog({ open: false })
          await reloadSites()
          notify(dialog.site ? 'Application updated' : 'Application added')
          if (!dialog.site) navigate(`/applications/${s.id}`)
        }}
      />
      <Confirm
        open={!!del} danger title="Delete application"
        text={<>Delete <b>{del && siteName(del)}</b>? Its traffic is no longer proxied or protected. Logs are kept.</>}
        confirmLabel="Delete" onClose={() => setDel(null)}
        onConfirm={async () => {
          const s = del!
          setDel(null)
          try {
            await api.del(`/sites/${s.id}`)
            await reloadSites()
            notify('Application deleted')
          } catch (e) {
            notifyError(e)
          }
        }}
      />
    </>
  )
}
