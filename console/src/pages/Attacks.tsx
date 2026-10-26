import { useCallback, useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import {
  Alert, Box, Button, Chip, Divider, Drawer, IconButton, Paper, Stack, Table, TableBody, TableCell, TableHead,
  TableRow, TextField, ToggleButton, ToggleButtonGroup, Typography,
} from '@mui/material'
import CloseIcon from '@mui/icons-material/Close'
import { api, qs } from '../api'
import { useApp } from '../context'
import type { Attack, AttackDetail, GroupRow, Page } from '../types'
import { ActionChip, AutoRefresh, CountryCell, Empty, Pager, SiteLabel, SiteSelect, useInterval } from '../components/common'
import { categoryLabel, fmtDuration, fmtTime } from '../util'

function toISO(local: string): string | undefined {
  return local ? new Date(local).toISOString() : undefined
}

export default function Attacks() {
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const { notifyError } = useApp()
  const view = params.get('view') === 'logs' ? 'logs' : 'events'
  const [site, setSite] = useState(params.get('site') ?? '')
  const [ip, setIp] = useState(params.get('ip') ?? '')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [page, setPage] = useState(0)
  const [size, setSize] = useState(20)
  const [refresh, setRefresh] = useState(0)
  const [groups, setGroups] = useState<Page<GroupRow>>({ items: [], total: 0 })
  const [logs, setLogs] = useState<Page<Attack>>({ items: [], total: 0 })
  const [detail, setDetail] = useState<string | null>(null)
  const [banner, setBanner] = useState(() => localStorage.getItem('hiwaf.attackBanner') !== 'off')

  const load = useCallback(() => {
    const q = qs({ site, ip: ip.trim(), since: toISO(from), until: toISO(to), page: page + 1, size })
    if (view === 'events') api.get<Page<GroupRow>>('/attacks/groups' + q).then(setGroups).catch(notifyError)
    else api.get<Page<Attack>>('/attacks' + q).then(setLogs).catch(notifyError)
  }, [view, site, ip, from, to, page, size, notifyError])
  useEffect(() => { load() }, [load])
  useInterval(load, refresh, refresh > 0)

  const setView = (v: string) => { setPage(0); setParams({ view: v, ...(site ? { site } : {}), ...(ip ? { ip } : {}) }) }

  return (
    <Stack spacing={2}>
      {banner && (
        <Alert
          severity="info"
          action={<Stack direction="row"><Button onClick={() => navigate('/applications')}>Go to configuration</Button>
            <Button onClick={() => { localStorage.setItem('hiwaf.attackBanner', 'off'); setBanner(false) }}>Don't show again</Button></Stack>}
        >
          <b>Rule-based detection (OWASP Core Rule Set)</b> finds SQL injection, XSS, command injection, path traversal and more.
          Each application runs in <b>Defense</b> (block), <b>Audit</b> (log only) or <b>Disabled</b> mode; set its detection level on the application's Protection tab.
        </Alert>
      )}
      <Paper sx={{ p: 2, borderRadius: 2 }}>
        <Stack direction="row" spacing={1.5} alignItems="center" sx={{ flexWrap: 'wrap', rowGap: 1.5 }}>
          <ToggleButtonGroup exclusive size="small" value={view} onChange={(_, v) => v && setView(v)}>
            <ToggleButton value="events" sx={{ px: 2 }}>Events</ToggleButton>
            <ToggleButton value="logs" sx={{ px: 2 }}>Logs</ToggleButton>
          </ToggleButtonGroup>
          <TextField label="IP Addr" value={ip} onChange={(e) => { setIp(e.target.value); setPage(0) }} sx={{ width: 170 }} />
          <SiteSelect value={site} onChange={(v) => { setSite(v); setPage(0) }} />
          <TextField label="Start at" type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} InputLabelProps={{ shrink: true }} />
          <TextField label="End at" type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} InputLabelProps={{ shrink: true }} />
          <AutoRefresh value={refresh} onChange={setRefresh} />
          <Button variant="outlined" onClick={load}>Refresh</Button>
        </Stack>
      </Paper>

      <Paper sx={{ borderRadius: 2, overflow: 'hidden' }}>
        {view === 'events' ? (
          <>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>IP Addr</TableCell><TableCell>Application</TableCell><TableCell>Attack Count</TableCell>
                  <TableCell>Duration</TableCell><TableCell>Start At</TableCell><TableCell>Last At</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {groups.items.map((g) => (
                  <TableRow key={g.site_id + g.client_ip} hover sx={{ cursor: 'pointer' }}
                    onClick={() => { setIp(g.client_ip); setSite(g.site_id); setPage(0); setParams({ view: 'logs', site: g.site_id, ip: g.client_ip }) }}>
                    <TableCell><CountryCell ip={g.client_ip} /></TableCell>
                    <TableCell><SiteLabel id={g.site_id} /></TableCell>
                    <TableCell><Chip size="small" label={g.count} sx={{ bgcolor: 'rgba(229,72,77,.1)', color: '#c62828', borderRadius: 1 }} /></TableCell>
                    <TableCell>{fmtDuration(g.first, g.last)}</TableCell>
                    <TableCell>{fmtTime(g.first)}</TableCell>
                    <TableCell>{fmtTime(g.last)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {!groups.items.length && <Empty text="No attacks found." />}
            <Pager total={groups.total} page={page} size={size} onPage={setPage} onSize={setSize} />
          </>
        ) : (
          <>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Time</TableCell><TableCell>IP Addr</TableCell><TableCell>Application</TableCell>
                  <TableCell>Request</TableCell><TableCell>Attack Type</TableCell><TableCell>Rule</TableCell><TableCell>Action</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {logs.items.map((a) => (
                  <TableRow key={a.tx_id} hover sx={{ cursor: 'pointer' }} onClick={() => setDetail(a.tx_id)}>
                    <TableCell sx={{ whiteSpace: 'nowrap' }}>{fmtTime(a.ts)}</TableCell>
                    <TableCell><CountryCell ip={a.client_ip} country={a.country} /></TableCell>
                    <TableCell><SiteLabel id={a.site_id} /></TableCell>
                    <TableCell sx={{ maxWidth: 360 }}>
                      <Typography sx={{ fontSize: 12.5, fontFamily: 'ui-monospace,Consolas,monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        <b>{a.method || 'GET'}</b> {a.host}{a.uri}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={0.5}>
                        {a.categories.map((c) => <Chip key={c} size="small" label={categoryLabel(c)} sx={{ borderRadius: 1, fontSize: 11 }} />)}
                      </Stack>
                    </TableCell>
                    <TableCell sx={{ maxWidth: 260 }}>
                      <Typography sx={{ fontSize: 12.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={a.msg}>
                        {a.rule_id} · {a.msg}
                      </Typography>
                    </TableCell>
                    <TableCell><ActionChip blocked={a.blocked} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {!logs.items.length && <Empty text="No attack logs found." />}
            <Pager total={logs.total} page={page} size={size} onPage={setPage} onSize={setSize} />
          </>
        )}
      </Paper>
      <AttackDrawer tx={detail} onClose={() => setDetail(null)} />
    </Stack>
  )
}

function KVRow({ k, v, mono }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <Stack direction="row" sx={{ py: 0.6, fontSize: 13 }}>
      <Box sx={{ width: 120, color: 'text.secondary', flexShrink: 0 }}>{k}</Box>
      <Box sx={{ flex: 1, minWidth: 0, wordBreak: 'break-all', fontFamily: mono ? 'ui-monospace,Consolas,monospace' : undefined }}>{v || '-'}</Box>
    </Stack>
  )
}

export function AttackDrawer({ tx, onClose }: { tx: string | null; onClose: () => void }) {
  const { notify, notifyError } = useApp()
  const [d, setD] = useState<AttackDetail | null>(null)
  useEffect(() => {
    setD(null)
    if (tx) api.get<AttackDetail>(`/attacks/${encodeURIComponent(tx)}`).then(setD).catch(notifyError)
  }, [tx, notifyError])

  const req = d?.request
  const ip = req?.client_ip || d?.matches[0]?.client_ip || ''
  const blockIP = async () => {
    try {
      await api.post('/rules', { name: `Block ${ip}`, enabled: true, action: 'block', match: { ip: [ip] } })
      notify(`${ip} is now denied on all applications (Allow & Deny → Custom Rules)`)
    } catch (e) {
      notifyError(e)
    }
  }
  const main = d?.matches.find((m) => m.category !== 'score') ?? d?.matches[0]

  return (
    <Drawer anchor="right" open={!!tx} onClose={onClose} PaperProps={{ sx: { width: { xs: '100%', md: 720 } } }}>
      <Stack direction="row" alignItems="center" sx={{ px: 3, py: 2, borderBottom: '1px solid #eef1f3' }}>
        <Typography variant="h6" sx={{ flex: 1 }}>Attack detail</Typography>
        {d && <ActionChip blocked={d.blocked} />}
        <IconButton onClick={onClose} sx={{ ml: 1 }}><CloseIcon /></IconButton>
      </Stack>
      {d && (
        <Box sx={{ p: 3, overflow: 'auto' }}>
          {main && (
            <Paper variant="outlined" sx={{ p: 2, mb: 2, borderColor: 'rgba(229,72,77,.35)', bgcolor: 'rgba(229,72,77,.03)' }}>
              <Typography sx={{ fontWeight: 700 }}>{categoryLabel(main.category ?? '')}: {main.detail}</Typography>
              {main.data && (
                <Box sx={{ mt: 1, p: 1.2, bgcolor: '#1d2b36', color: '#ffd8d9', borderRadius: 1, fontFamily: 'ui-monospace,Consolas,monospace', fontSize: 12.5, wordBreak: 'break-all' }}>
                  {main.data}
                </Box>
              )}
            </Paper>
          )}
          <Typography sx={{ fontWeight: 700, mb: 1 }}>Request</Typography>
          <KVRow k="Time" v={fmtTime(req?.ts ?? d.matches[0]?.ts)} />
          <KVRow k="Client IP" v={<CountryCell ip={ip} country={req?.country || d.matches[0]?.country} />} />
          <KVRow k="Application" v={<SiteLabel id={req?.site_id || d.matches[0]?.site_id || ''} />} />
          <KVRow k="Request" mono v={`${req?.method ?? ''} ${req?.host ?? ''}${req?.uri ?? d.matches[0]?.uri ?? ''}`} />
          <KVRow k="Status" v={req?.status ? String(req.status) : undefined} />
          <KVRow k="User-Agent" mono v={req?.user_agent} />
          <KVRow k="Referer" mono v={req?.referer} />
          <KVRow k="Event ID" mono v={d.tx_id} />
          <Stack direction="row" spacing={1} sx={{ mt: 1.5 }}>
            <Button variant="outlined" color="error" onClick={blockIP} disabled={!ip}>Deny this IP everywhere</Button>
          </Stack>
          <Divider sx={{ my: 2.5 }} />
          <Typography sx={{ fontWeight: 700, mb: 1 }}>Matched rules ({d.matches.length})</Typography>
          <Table size="small">
            <TableHead>
              <TableRow><TableCell>Rule</TableCell><TableCell>Type</TableCell><TableCell>Message / matched data</TableCell></TableRow>
            </TableHead>
            <TableBody>
              {d.matches.map((m) => (
                <TableRow key={m.id}>
                  <TableCell sx={{ fontFamily: 'ui-monospace,Consolas,monospace', verticalAlign: 'top' }}>{m.rule_id}</TableCell>
                  <TableCell sx={{ verticalAlign: 'top', whiteSpace: 'nowrap' }}>{m.category === 'score' ? 'Anomaly score' : categoryLabel(m.category ?? '')}</TableCell>
                  <TableCell>
                    <Typography sx={{ fontSize: 12.5 }}>{m.detail}</Typography>
                    {m.data && <Typography sx={{ fontSize: 12, color: 'text.secondary', fontFamily: 'ui-monospace,Consolas,monospace', wordBreak: 'break-all' }}>{m.data}</Typography>}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Box>
      )}
    </Drawer>
  )
}
