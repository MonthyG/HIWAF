import { useCallback, useEffect, useState } from 'react'
import { Box, Button, Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow } from '@mui/material'
import { api } from '../api'
import { useApp } from '../context'
import type { Ban, Limit } from '../types'
import EventLog from '../components/EventLog'
import SiteFeatureTable, { OnOff } from '../components/SiteFeatureTable'
import { RateLimitForm } from '../components/forms'
import { CountryCell, Empty, PageTitle, SiteLabel } from '../components/common'
import { fmtSeconds, fmtTime } from '../util'

const lim = (l: Limit | null) => <OnOff on={!!l} text={l ? `${l.requests} / ${fmtSeconds(l.window_sec)} → ${fmtSeconds(l.ban_sec)}` : undefined} />

function Bans() {
  const { notify, notifyError } = useApp()
  const [bans, setBans] = useState<Record<string, Ban[]>>({})
  const load = useCallback(() => api.get<Record<string, Ban[]>>('/bans').then(setBans).catch(notifyError), [notifyError])
  useEffect(() => { load() }, [load])
  const rows = Object.entries(bans).flatMap(([site, list]) => list.map((b) => ({ site, ...b })))
  return (
    <Paper sx={{ borderRadius: 2, overflow: 'hidden' }}>
      <Stack direction="row" sx={{ p: 2 }}><Box sx={{ flex: 1 }} /><Button variant="outlined" onClick={load}>Refresh</Button></Stack>
      <Table size="small">
        <TableHead><TableRow><TableCell>IP Addr</TableCell><TableCell>Application</TableCell><TableCell>Blocked until</TableCell><TableCell /></TableRow></TableHead>
        <TableBody>
          {rows.map((b) => (
            <TableRow key={b.site + b.ip}>
              <TableCell><CountryCell ip={b.ip} /></TableCell>
              <TableCell><SiteLabel id={b.site} /></TableCell>
              <TableCell>{fmtTime(b.until)}</TableCell>
              <TableCell align="right">
                <Button size="small" onClick={async () => {
                  try { await api.del(`/bans?site=${encodeURIComponent(b.site)}&ip=${encodeURIComponent(b.ip)}`); notify(`${b.ip} unbanned`); load() } catch (e) { notifyError(e) }
                }}>Unban</Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {!rows.length && <Empty text="Nobody is banned right now." />}
    </Paper>
  )
}

export default function RateLimiting() {
  return (
    <Box>
      <PageTitle title="Rate Limiting" sub="Ban clients that send too many requests, attacks or errors." />
      <EventLog
        types={['rate_limit_ban']}
        defaultView="settings"
        extraViews={[
          {
            key: 'settings', label: 'Settings', render: () => (
              <SiteFeatureTable
                editTitle="Rate limiting"
                columns={[
                  { label: 'Basic access limit', render: (s) => lim(s.resolved.rate_limit.access) },
                  { label: 'Attack limit', render: (s) => lim(s.resolved.rate_limit.attack) },
                  { label: 'Error limit', render: (s) => lim(s.resolved.rate_limit.error) },
                ]}
                renderForm={(s, done) => <RateLimitForm site={s} onSaved={done} />}
              />
            ),
          },
          { key: 'bans', label: 'Banned IPs', render: () => <Bans /> },
        ]}
      />
    </Box>
  )
}
