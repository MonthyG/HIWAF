import { useEffect, useState } from 'react'
import {
  Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, Grid2 as Grid, MenuItem, Stack, TextField,
  ToggleButton, ToggleButtonGroup, Typography,
} from '@mui/material'
import type { IPGroup, KV, Match } from '../types'
import { ChipsInput, SiteSelect } from './common'
import { api } from '../api'
import { useApp } from '../context'

export function emptyMatch(): Match {
  return {}
}

export function matchSummary(m: Match): string {
  const parts: string[] = []
  if (m.ip?.length) parts.push(`IP in ${m.ip.join(', ')}`)
  if (m.not_ip?.length) parts.push(`IP not in ${m.not_ip.join(', ')}`)
  if (m.country?.length) parts.push(`country ${m.country.join(', ')}`)
  if (m.method?.length) parts.push(`method ${m.method.join(', ')}`)
  if (m.path_exact) parts.push(`path = ${m.path_exact}`)
  if (m.path_prefix) parts.push(`path starts with ${m.path_prefix}`)
  if (m.path_regex) parts.push(`path ~ ${m.path_regex}`)
  if (m.host) parts.push(`host = ${m.host}`)
  if (m.header) parts.push(`header ${m.header.name} ${m.header.regex ? '~ ' + m.header.regex : 'contains ' + m.header.contains}`)
  if (m.query) parts.push(`query ${m.query.name} ${m.query.regex ? '~ ' + m.query.regex : 'contains ' + m.query.contains}`)
  return parts.join(' AND ') || 'no conditions'
}

export interface RuleValue {
  name: string
  action: 'allow' | 'block'
  match: Match
  sites?: string[]
  ip_groups?: string[]
  not_ip_groups?: string[]
  enabled?: boolean
  priority?: number
}

type PathMode = 'none' | 'exact' | 'prefix' | 'regex'
type KVMode = 'contains' | 'regex'

/** Rule editor for global and per-application rules. */
export default function RuleEditor({ open, title, initial, global, onClose, onSubmit }: {
  open: boolean
  title: string
  initial: RuleValue
  global?: boolean
  onClose: () => void
  onSubmit: (v: RuleValue) => void | Promise<void>
}) {
  const { sites } = useApp()
  const [v, setV] = useState<RuleValue>(initial)
  const [pathMode, setPathMode] = useState<PathMode>('none')
  const [path, setPath] = useState('')
  const [hdr, setHdr] = useState<{ name: string; mode: KVMode; value: string }>({ name: '', mode: 'contains', value: '' })
  const [qry, setQry] = useState<{ name: string; mode: KVMode; value: string }>({ name: '', mode: 'contains', value: '' })
  const [scope, setScope] = useState<string[]>([])
  const [groups, setGroups] = useState<IPGroup[]>([])
  const [err, setErr] = useState('')

  useEffect(() => {
    if (!open) return
    setV(initial)
    const m = initial.match
    setPathMode(m.path_exact ? 'exact' : m.path_prefix ? 'prefix' : m.path_regex ? 'regex' : 'none')
    setPath(m.path_exact || m.path_prefix || m.path_regex || '')
    const kv = (x?: KV) => ({ name: x?.name ?? '', mode: (x?.regex ? 'regex' : 'contains') as KVMode, value: x?.regex || x?.contains || '' })
    setHdr(kv(m.header))
    setQry(kv(m.query))
    setScope(initial.sites ?? [])
    setErr('')
    if (global) api.get<IPGroup[]>('/ip-groups').then(setGroups).catch(() => {})
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps

  const set = (patch: Partial<Match>) => setV({ ...v, match: { ...v.match, ...patch } })

  const submit = async () => {
    const m: Match = { ...v.match }
    delete m.path_exact; delete m.path_prefix; delete m.path_regex; delete m.header; delete m.query
    if (pathMode !== 'none' && path) {
      if (pathMode === 'exact') m.path_exact = path
      if (pathMode === 'prefix') m.path_prefix = path
      if (pathMode === 'regex') m.path_regex = path
    }
    const kv = (x: typeof hdr): KV | undefined =>
      x.name && x.value ? (x.mode === 'regex' ? { name: x.name, regex: x.value } : { name: x.name, contains: x.value }) : undefined
    if (kv(hdr)) m.header = kv(hdr)
    if (kv(qry)) m.query = kv(qry)
    for (const k of ['ip', 'not_ip', 'country', 'method'] as const) if (m[k] && !m[k]!.length) delete m[k]
    if (!m.host) delete m.host
    if (!v.name.trim()) { setErr('Give the rule a name.'); return }
    setErr('')
    try {
      await onSubmit({ ...v, name: v.name.trim(), match: m, ...(global ? { sites: scope } : {}) })
    } catch (e: any) {
      setErr(e?.message ?? String(e))
    }
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error">{err}</Alert>}
          <Stack direction="row" spacing={2}>
            <TextField label="Name" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} sx={{ flex: 1 }} inputProps={{ maxLength: 64 }} />
            <ToggleButtonGroup exclusive value={v.action} onChange={(_, a) => a && setV({ ...v, action: a })} size="small">
              <ToggleButton value="block" sx={{ px: 3, '&.Mui-selected': { color: 'error.main' } }}>Deny</ToggleButton>
              <ToggleButton value="allow" sx={{ px: 3, '&.Mui-selected': { color: 'success.main' } }}>Allow</ToggleButton>
            </ToggleButtonGroup>
          </Stack>
          {v.action === 'allow' && (
            <Alert severity="warning">
              Allow rules skip rate limits, bot protection and the WAF. They must match an IP or a path, and never match paths with “..” or “;”.
            </Alert>
          )}
          {global && (
            <Stack direction="row" spacing={2}>
              <TextField select label="Applies to" value={scope} SelectProps={{ multiple: true, displayEmpty: true, renderValue: (s) => ((s as string[]).length ? `${(s as string[]).length} application(s)` : 'All applications') }}
                onChange={(e) => setScope(e.target.value as unknown as string[])} sx={{ flex: 1 }} InputLabelProps={{ shrink: true }}>
                {sites.map((s) => <MenuItem key={s.id} value={s.id}>{s.resolved.name || s.resolved.domains.join(', ')}</MenuItem>)}
              </TextField>
              <TextField label="Priority" type="number" value={v.priority ?? 0} onChange={(e) => setV({ ...v, priority: Number(e.target.value) })} sx={{ width: 140 }} helperText="Lower runs first" />
            </Stack>
          )}
          <Typography sx={{ fontWeight: 600 }}>Conditions <Typography component="span" sx={{ fontSize: 12, color: 'text.secondary' }}>(all must match)</Typography></Typography>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, md: 6 }}>
              <ChipsInput label="Source IP / CIDR" value={v.match.ip ?? []} onChange={(x) => set({ ip: x })} />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <ChipsInput label="Source IP is not" value={v.match.not_ip ?? []} onChange={(x) => set({ not_ip: x })} />
            </Grid>
            {global && (
              <>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField select fullWidth label="Source IP in groups" value={v.ip_groups ?? []} SelectProps={{ multiple: true }}
                    onChange={(e) => setV({ ...v, ip_groups: e.target.value as unknown as string[] })}>
                    {groups.map((g) => <MenuItem key={g.id} value={g.id}>{g.name}</MenuItem>)}
                  </TextField>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField select fullWidth label="Source IP not in groups" value={v.not_ip_groups ?? []} SelectProps={{ multiple: true }}
                    onChange={(e) => setV({ ...v, not_ip_groups: e.target.value as unknown as string[] })}>
                    {groups.map((g) => <MenuItem key={g.id} value={g.id}>{g.name}</MenuItem>)}
                  </TextField>
                </Grid>
              </>
            )}
            <Grid size={{ xs: 12, md: 6 }}>
              <ChipsInput label="Country (ISO code)" upper value={v.match.country ?? []} onChange={(x) => set({ country: x })} />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <ChipsInput label="Method" upper value={v.match.method ?? []} onChange={(x) => set({ method: x })} placeholder="GET, POST" />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <TextField select fullWidth label="Path" value={pathMode} onChange={(e) => setPathMode(e.target.value as PathMode)}>
                <MenuItem value="none">Any path</MenuItem>
                <MenuItem value="exact">Equals</MenuItem>
                <MenuItem value="prefix">Starts with</MenuItem>
                <MenuItem value="regex">Matches regex</MenuItem>
              </TextField>
            </Grid>
            <Grid size={{ xs: 12, md: 8 }}>
              <TextField fullWidth label="Path value" value={path} disabled={pathMode === 'none'} onChange={(e) => setPath(e.target.value)} placeholder="/wp-admin" />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <TextField fullWidth label="Host equals" value={v.match.host ?? ''} onChange={(e) => set({ host: e.target.value })} />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }} />
            {([['Header', hdr, setHdr], ['Query parameter', qry, setQry]] as const).map(([label, val, setVal]) => (
              <Grid key={label} size={12}>
                <Stack direction="row" spacing={1}>
                  <TextField label={`${label} name`} value={val.name} onChange={(e) => setVal({ ...val, name: e.target.value })} sx={{ width: 220 }} />
                  <TextField select value={val.mode} onChange={(e) => setVal({ ...val, mode: e.target.value as KVMode })} sx={{ width: 140 }}>
                    <MenuItem value="contains">contains</MenuItem>
                    <MenuItem value="regex">matches regex</MenuItem>
                  </TextField>
                  <TextField label="Value" value={val.value} onChange={(e) => setVal({ ...val, value: e.target.value })} sx={{ flex: 1 }} />
                </Stack>
              </Grid>
            ))}
          </Grid>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={submit}>Save</Button>
      </DialogActions>
    </Dialog>
  )
}

export { SiteSelect }
