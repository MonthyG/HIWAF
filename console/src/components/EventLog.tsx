import { useCallback, useEffect, useState } from 'react'
import { Button, Chip, Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, ToggleButton, ToggleButtonGroup, Typography } from '@mui/material'
import { api, qs } from '../api'
import { useApp } from '../context'
import type { EventRow, GroupRow, Page } from '../types'
import { AutoRefresh, CountryCell, Empty, Pager, SiteLabel, SiteSelect, useInterval } from './common'
import { eventLabels, fmtDuration, fmtTime } from '../util'

const good = new Set(['allowed_by_rule', 'challenge_passed', 'auth_passed'])

/** Events (grouped by IP) and Logs for a set of event types. */
export default function EventLog({ types, extraViews, defaultView = 'events' }: {
  types: string[]
  extraViews?: { key: string; label: string; render: () => React.ReactNode }[]
  defaultView?: string
}) {
  const { notifyError } = useApp()
  const [view, setView] = useState(defaultView)
  const [site, setSite] = useState('')
  const [ip, setIp] = useState('')
  const [page, setPage] = useState(0)
  const [size, setSize] = useState(20)
  const [refresh, setRefresh] = useState(0)
  const [groups, setGroups] = useState<Page<GroupRow>>({ items: [], total: 0 })
  const [logs, setLogs] = useState<Page<EventRow>>({ items: [], total: 0 })
  const typesKey = types.join(',')

  const load = useCallback(() => {
    const q = qs({ types: typesKey, site, ip: ip.trim(), page: page + 1, size })
    if (view === 'events') api.get<Page<GroupRow>>('/logs/groups' + q).then(setGroups).catch(notifyError)
    else if (view === 'logs') api.get<Page<EventRow>>('/logs' + q).then(setLogs).catch(notifyError)
  }, [view, typesKey, site, ip, page, size, notifyError])
  useEffect(() => { load() }, [load])
  useInterval(load, refresh, refresh > 0)

  const extra = extraViews?.find((v) => v.key === view)
  return (
    <Stack spacing={2}>
      <Paper sx={{ p: 2, borderRadius: 2 }}>
        <Stack direction="row" spacing={1.5} alignItems="center" sx={{ flexWrap: 'wrap', rowGap: 1.5 }}>
          <ToggleButtonGroup exclusive size="small" value={view} onChange={(_, v) => { if (v) { setView(v); setPage(0) } }}>
            <ToggleButton value="events" sx={{ px: 2 }}>Events</ToggleButton>
            <ToggleButton value="logs" sx={{ px: 2 }}>Logs</ToggleButton>
            {extraViews?.map((v) => <ToggleButton key={v.key} value={v.key} sx={{ px: 2 }}>{v.label}</ToggleButton>)}
          </ToggleButtonGroup>
          {!extra && (
            <>
              <TextField label="IP Addr" value={ip} onChange={(e) => { setIp(e.target.value); setPage(0) }} sx={{ width: 170 }} />
              <SiteSelect value={site} onChange={(v) => { setSite(v); setPage(0) }} />
              <AutoRefresh value={refresh} onChange={setRefresh} />
              <Button variant="outlined" onClick={load}>Refresh</Button>
            </>
          )}
        </Stack>
      </Paper>
      {extra ? extra.render() : (
        <Paper sx={{ borderRadius: 2, overflow: 'hidden' }}>
          {view === 'events' ? (
            <>
              <Table size="small">
                <TableHead>
                  <TableRow><TableCell>IP Addr</TableCell><TableCell>Application</TableCell><TableCell>Hit Count</TableCell><TableCell>Duration</TableCell><TableCell>Start At</TableCell></TableRow>
                </TableHead>
                <TableBody>
                  {groups.items.map((g) => (
                    <TableRow key={g.site_id + g.client_ip} hover sx={{ cursor: 'pointer' }} onClick={() => { setIp(g.client_ip); setView('logs') }}>
                      <TableCell><CountryCell ip={g.client_ip} /></TableCell>
                      <TableCell><SiteLabel id={g.site_id} /></TableCell>
                      <TableCell>{g.count}</TableCell>
                      <TableCell>{fmtDuration(g.first, g.last)}</TableCell>
                      <TableCell>{fmtTime(g.first)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {!groups.items.length && <Empty text="No events yet." />}
              <Pager total={groups.total} page={page} size={size} onPage={setPage} onSize={setSize} />
            </>
          ) : (
            <>
              <Table size="small">
                <TableHead>
                  <TableRow><TableCell>Time</TableCell><TableCell>IP Addr</TableCell><TableCell>Application</TableCell><TableCell>Request</TableCell><TableCell>Event</TableCell><TableCell>Detail</TableCell></TableRow>
                </TableHead>
                <TableBody>
                  {logs.items.map((e) => (
                    <TableRow key={e.id}>
                      <TableCell sx={{ whiteSpace: 'nowrap' }}>{fmtTime(e.ts)}</TableCell>
                      <TableCell><CountryCell ip={e.client_ip} country={e.country} /></TableCell>
                      <TableCell><SiteLabel id={e.site_id} /></TableCell>
                      <TableCell sx={{ maxWidth: 340 }}>
                        <Typography sx={{ fontSize: 12.5, fontFamily: 'ui-monospace,Consolas,monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          <b>{e.method}</b> {e.host}{e.uri}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip size="small" label={eventLabels[e.type] ?? e.type}
                          sx={{ borderRadius: 1, bgcolor: good.has(e.type) ? 'rgba(22,163,74,.1)' : 'rgba(229,72,77,.1)', color: good.has(e.type) ? '#15803d' : '#c62828' }} />
                      </TableCell>
                      <TableCell sx={{ fontSize: 12.5, color: 'text.secondary' }}>{e.detail || '-'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {!logs.items.length && <Empty text="No logs yet." />}
              <Pager total={logs.total} page={page} size={size} onPage={setPage} onSize={setSize} />
            </>
          )}
        </Paper>
      )}
    </Stack>
  )
}
