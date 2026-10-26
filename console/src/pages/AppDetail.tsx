import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { Alert, Box, Button, Grid2 as Grid, Paper, Stack, Tab, Tabs, Typography } from '@mui/material'
import UploadIcon from '@mui/icons-material/UploadFileOutlined'
import { api, errText, qs } from '../api'
import { useApp } from '../context'
import type { Overview } from '../types'
import Chart from '../components/Chart'
import AppDialog from '../components/AppDialog'
import { BarList, ModeChip, Section, StatTile, TileGroup, siteName } from '../components/common'
import { AccessForm, AdvancedForm, AuthForm, ChallengeForm, ProtectionForm, RateLimitForm, WaitRoomForm } from '../components/forms'
import { categoryLabel, fmtNum, pct } from '../util'

const tabs = ['overview', 'protection', 'rate-limit', 'anti-bot', 'auth', 'waiting-room', 'access', 'advanced'] as const
const tabLabels: Record<string, string> = {
  overview: 'Overview', protection: 'Protection', 'rate-limit': 'HTTP Flood', 'anti-bot': 'Anti-Bot', auth: 'Auth',
  'waiting-room': 'Waiting Room', access: 'Allow & Deny', advanced: 'Advanced',
}

export default function AppDetail() {
  const { id = '' } = useParams()
  const { siteById, sitesLoaded, reloadSites, notify } = useApp()
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const tab = (params.get('tab') as (typeof tabs)[number]) || 'overview'
  const site = siteById[id]
  const [edit, setEdit] = useState(false)
  const [stats, setStats] = useState<Overview | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadMsg, setUploadMsg] = useState('')

  const loadStats = useCallback(() => {
    api.get<Overview>('/stats/overview' + qs({ site: id, range: '24h' })).then(setStats).catch(() => {})
  }, [id])
  useEffect(() => { if (tab === 'overview') loadStats() }, [tab, loadStats])

  const chart = useMemo(() => {
    const s = stats?.series ?? []
    const lbl = (t: string) => { const d = new Date(t); return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}` }
    return {
      grid: { left: 40, right: 12, top: 30, bottom: 24 },
      legend: { top: 0, right: 0, textStyle: { fontSize: 11 } },
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: s.map((p) => lbl(p.t)), boundaryGap: false, axisLabel: { color: '#8a99a5', fontSize: 11 } },
      yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: '#f0f3f5' } } },
      series: [
        { name: 'Requests', type: 'line', smooth: true, showSymbol: false, data: s.map((p) => p.requests), lineStyle: { color: '#3b6fd6' }, itemStyle: { color: '#3b6fd6' } },
        { name: 'Blocked', type: 'line', smooth: true, showSymbol: false, data: s.map((p) => p.blocked), lineStyle: { color: '#e5484d' }, itemStyle: { color: '#e5484d' } },
      ],
    }
  }, [stats])

  if (!site) {
    return sitesLoaded ? (
      <Alert severity="warning" action={<Button onClick={() => navigate('/applications')}>Back</Button>}>Application not found.</Alert>
    ) : null
  }
  const r = site.resolved

  const upload = async (f: File) => {
    const form = new FormData()
    form.append('file', f)
    setUploading(true)
    setUploadMsg('')
    try {
      const res = await api.upload<{ files: number }>(`/sites/${site.id}/static`, form)
      setUploadMsg(`Uploaded ${res.files} files.`)
      notify('Static files uploaded')
    } catch (e) {
      setUploadMsg(errText(e))
    } finally {
      setUploading(false)
    }
  }

  return (
    <Stack spacing={2}>
      <Paper sx={{ p: 2.5, borderRadius: 2 }}>
        <Stack direction="row" alignItems="flex-start" spacing={2}>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Stack direction="row" alignItems="center" spacing={1.5}>
              <Typography variant="h5" sx={{ fontSize: 20 }}>{siteName(site)}</Typography>
              <ModeChip mode={r.waf.mode} />
            </Stack>
            {r.description && <Typography sx={{ color: 'text.secondary', mt: 0.5 }}>{r.description}</Typography>}
            <Stack direction="row" spacing={3} sx={{ mt: 1.5, fontSize: 13, color: 'text.secondary', flexWrap: 'wrap' }}>
              <span>Domain: <b style={{ color: '#1d2b36' }}>{r.domains.map((d) => (d === '*' ? 'Match All Host' : d)).join(', ')}</b></span>
              <span>Port: <b style={{ color: '#0fa5a0' }}>{r.ports.map((p) => `${p.port}${p.https ? '/HTTPS' : ''}`).join(', ')}</b></span>
              <span>{r.type === 'proxy' ? <>Upstream: <b style={{ color: '#1d2b36' }}>{(r.upstreams ?? []).join(', ')}</b></> : r.type === 'static' ? 'Static files' : <>Redirect: <b style={{ color: '#1d2b36' }}>{r.redirect.url}</b></>}</span>
              <span>TLS: <b style={{ color: '#1d2b36' }}>{r.tls.mode === 'off' ? 'off' : r.tls.mode === 'auto' ? 'automatic' : 'uploaded certificate'}</b></span>
            </Stack>
          </Box>
          <Button variant="outlined" onClick={() => setEdit(true)}>Edit</Button>
          <Button variant="outlined" onClick={() => navigate(`/attacks?site=${site.id}`)}>Attacks</Button>
        </Stack>
      </Paper>

      <Paper sx={{ borderRadius: 2 }}>
        <Tabs value={tab} onChange={(_, v) => setParams({ tab: v })} variant="scrollable" sx={{ px: 2, borderBottom: '1px solid #eef1f3' }}>
          {tabs.map((t) => <Tab key={t} value={t} label={tabLabels[t]} />)}
        </Tabs>
        <Box sx={{ p: 3 }}>
          {tab === 'overview' && (
            <Stack spacing={2}>
              {r.type === 'static' && (
                <Alert severity="info" action={
                  <Button component="label" startIcon={<UploadIcon />} disabled={uploading}>
                    {uploading ? 'Uploading…' : 'Upload .zip'}
                    <input hidden type="file" accept=".zip,application/zip" onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])} />
                  </Button>
                }>
                  Static site: upload a .zip of its files (index.html at the top level or in a single folder). {uploadMsg}
                </Alert>
              )}
              <TileGroup>
                <StatTile label="Requests (24h)" value={fmtNum(stats?.requests)} />
                <StatTile label="Visitors (UV)" value={fmtNum(stats?.uv)} />
                <StatTile label="Blocked" value={fmtNum(stats?.blocked)} tone={stats?.blocked ? 'danger' : undefined} />
                <StatTile label="Blocked Rate" value={pct(stats?.blocked ?? 0, stats?.requests ?? 0)} />
                <StatTile label="4xx" value={fmtNum(stats?.err_4xx)} tone="warn" />
                <StatTile label="5xx" value={fmtNum(stats?.err_5xx)} tone="danger" />
              </TileGroup>
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, md: 8 }}>
                  <Section title="Traffic (24h)"><Chart option={chart} height={260} /></Section>
                </Grid>
                <Grid size={{ xs: 12, md: 4 }}>
                  <Section title="Attack types">
                    <BarList items={stats?.attack_types ?? []} color="#e5484d" render={categoryLabel} empty="No attacks in 24h" />
                  </Section>
                </Grid>
              </Grid>
              <Section title="Enabled protections">
                <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', rowGap: 1 }}>
                  {[
                    ['WAF', r.waf.mode !== 'off'], ['Access limit', !!r.rate_limit.access], ['Attack limit', !!r.rate_limit.attack],
                    ['Error limit', !!r.rate_limit.error], ['Bot challenge', r.bot_challenge.enabled], ['Auth', r.auth.enabled],
                    ['Waiting room', r.waiting_room.enabled], ['Access rules', !!(r.access.rules?.length || r.access.block_ips?.length || r.access.allow_ips?.length)],
                  ].map(([l, on]) => (
                    <Box key={l as string} sx={{ px: 1.5, py: 0.6, borderRadius: 1, fontSize: 12.5, fontWeight: 600, bgcolor: on ? 'rgba(15,165,160,.1)' : '#f1f4f6', color: on ? 'primary.main' : 'text.secondary' }}>
                      {on ? '✓' : '–'} {l as string}
                    </Box>
                  ))}
                </Stack>
              </Section>
            </Stack>
          )}
          {tab === 'protection' && <ProtectionForm site={site} />}
          {tab === 'rate-limit' && <RateLimitForm site={site} />}
          {tab === 'anti-bot' && <ChallengeForm site={site} />}
          {tab === 'auth' && <AuthForm site={site} />}
          {tab === 'waiting-room' && <WaitRoomForm site={site} />}
          {tab === 'access' && <AccessForm site={site} />}
          {tab === 'advanced' && <AdvancedForm site={site} />}
        </Box>
      </Paper>
      <AppDialog open={edit} site={site} onClose={() => setEdit(false)} onSaved={async () => { setEdit(false); await reloadSites(); notify('Application updated') }} />
    </Stack>
  )
}
