import { useEffect, useState, type ReactNode } from 'react'
import {
  Box, Button, Card, Chip, Dialog, DialogActions, DialogContent, DialogTitle, MenuItem, Paper,
  Stack, Switch, TablePagination, TextField, Tooltip, Typography,
} from '@mui/material'
import { countryName, flag, fmtNum } from '../util'
import type { SiteView } from '../types'
import { useApp } from '../context'

export function PageTitle({ title, sub, actions }: { title: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <Stack direction="row" alignItems="center" sx={{ mb: 2.5 }} spacing={2}>
      <Box sx={{ flex: 1 }}>
        <Typography variant="h5" sx={{ fontSize: 20 }}>{title}</Typography>
        {sub && <Typography sx={{ color: 'text.secondary', mt: 0.3 }}>{sub}</Typography>}
      </Box>
      {actions}
    </Stack>
  )
}

export function Section({ title, actions, children, sx }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; sx?: object }) {
  return (
    <Paper sx={{ p: 2.5, borderRadius: 2, ...sx }}>
      {(title || actions) && (
        <Stack direction="row" alignItems="center" sx={{ mb: 1.5 }}>
          <Typography variant="h6" sx={{ flex: 1, fontSize: 15 }}>{title}</Typography>
          {actions}
        </Stack>
      )}
      {children}
    </Paper>
  )
}

export function StatTile({ label, value, tone, hint }: { label: string; value: string; tone?: 'danger' | 'warn' | 'ok'; hint?: string }) {
  const color = tone === 'danger' ? '#e5484d' : tone === 'warn' ? '#f59e0b' : 'text.primary'
  return (
    <Tooltip title={hint ?? ''} placement="top">
      <Box sx={{ flex: 1, minWidth: 90, px: 2, py: 1.5 }}>
        <Typography sx={{ color: 'text.secondary', fontSize: 12.5, whiteSpace: 'nowrap' }}>{label}</Typography>
        <Typography sx={{ fontSize: 24, fontWeight: 700, color, mt: 0.3, fontVariantNumeric: 'tabular-nums' }}>{value}</Typography>
      </Box>
    </Tooltip>
  )
}

export function TileGroup({ children }: { children: ReactNode }) {
  return (
    <Card sx={{ display: 'flex', borderRadius: 2, '& > div + div': { borderLeft: '1px solid #eef1f3' } }}>{children}</Card>
  )
}

export function CountryCell({ ip, country }: { ip: string; country?: string }) {
  return (
    <Box>
      <Typography sx={{ fontFamily: 'ui-monospace, Consolas, monospace', fontSize: 13, fontWeight: 600 }}>{ip}</Typography>
      <Typography sx={{ fontSize: 11.5, color: 'text.secondary' }}>
        {country ? `${flag(country)} ${countryName(country)}` : 'Unknown'}
      </Typography>
    </Box>
  )
}

export function BarList({ items, total, color = '#0fa5a0', empty = 'No data yet', render }: {
  items: { key: string; count: number }[]
  total?: number
  color?: string
  empty?: string
  render?: (k: string) => ReactNode
}) {
  const max = total ?? Math.max(1, ...items.map((i) => i.count))
  if (!items.length) return <Typography sx={{ color: 'text.secondary', py: 2, textAlign: 'center' }}>{empty}</Typography>
  return (
    <Stack spacing={1.1}>
      {items.map((i) => (
        <Box key={i.key}>
          <Stack direction="row" sx={{ fontSize: 13 }}>
            <Box sx={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', pr: 1 }}>
              {render ? render(i.key) : i.key || '-'}
            </Box>
            <Box sx={{ fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>{fmtNum(i.count)}</Box>
          </Stack>
          <Box sx={{ height: 4, bgcolor: '#eef3f4', borderRadius: 2, mt: 0.4 }}>
            <Box sx={{ height: 4, borderRadius: 2, bgcolor: color, width: `${Math.max(2, (i.count / max) * 100)}%` }} />
          </Box>
        </Box>
      ))}
    </Stack>
  )
}

export function ModeChip({ mode, onClick }: { mode: string; onClick?: (e: React.MouseEvent<HTMLElement>) => void }) {
  const map: Record<string, { label: string; color: string; bg: string }> = {
    block: { label: 'DEFENSE', color: '#0b8f8a', bg: 'rgba(15,165,160,.12)' },
    detect: { label: 'AUDIT', color: '#b7791f', bg: 'rgba(245,158,11,.14)' },
    off: { label: 'DISABLED', color: '#6b7a86', bg: '#eef1f3' },
  }
  const m = map[mode] ?? map.off
  return (
    <Chip
      size="small"
      label={m.label}
      onClick={onClick}
      sx={{ bgcolor: m.bg, color: m.color, fontWeight: 700, letterSpacing: 0.4, cursor: onClick ? 'pointer' : 'default' }}
    />
  )
}

export function ActionChip({ blocked, label }: { blocked: boolean; label?: string }) {
  return (
    <Chip
      size="small"
      label={label ?? (blocked ? 'Blocked' : 'Detected')}
      sx={{
        bgcolor: blocked ? 'rgba(229,72,77,.12)' : 'rgba(245,158,11,.14)',
        color: blocked ? '#c62828' : '#b7791f',
      }}
    />
  )
}

export function Pager({ total, page, size, onPage, onSize }: {
  total: number; page: number; size: number; onPage: (p: number) => void; onSize: (s: number) => void
}) {
  return (
    <TablePagination
      component="div"
      count={total}
      page={page}
      rowsPerPage={size}
      rowsPerPageOptions={[20, 50, 100]}
      onPageChange={(_, p) => onPage(p)}
      onRowsPerPageChange={(e) => { onSize(parseInt(e.target.value, 10)); onPage(0) }}
    />
  )
}

export function SiteSelect({ value, onChange, label = 'Application', allLabel = 'All applications', width = 220 }: {
  value: string; onChange: (v: string) => void; label?: string; allLabel?: string | null; width?: number
}) {
  const { sites } = useApp()
  return (
    <TextField select label={label} value={value} onChange={(e) => onChange(e.target.value)} sx={{ width }}
      SelectProps={{ displayEmpty: true }} InputLabelProps={{ shrink: true }}>
      {allLabel !== null && <MenuItem value="">{allLabel}</MenuItem>}
      {sites.map((s) => (
        <MenuItem key={s.id} value={s.id}>{siteName(s)}</MenuItem>
      ))}
    </TextField>
  )
}

export function siteName(s: SiteView): string {
  return s.resolved.name || s.resolved.domains.map((d) => (d === '*' ? 'Match All Host' : d)).join(', ')
}

export function SiteLabel({ id }: { id: string }) {
  const { siteById } = useApp()
  const s = siteById[id]
  if (!s) return <Typography sx={{ fontSize: 13, color: 'text.secondary' }}>{id}</Typography>
  return (
    <Box>
      <Typography sx={{ fontSize: 13, fontWeight: 600 }}>{siteName(s)}</Typography>
      {s.resolved.name && (
        <Typography sx={{ fontSize: 11.5, color: 'text.secondary' }}>
          {s.resolved.domains.map((d) => (d === '*' ? '*' : d)).join(', ')}
        </Typography>
      )}
    </Box>
  )
}

/** Free-text chips (IPs, domains, countries). */
export function ChipsInput({ label, value, onChange, placeholder, helperText, upper }: {
  label: string; value: string[]; onChange: (v: string[]) => void; placeholder?: string; helperText?: string; upper?: boolean
}) {
  const [input, setInput] = useState('')
  const commit = (raw: string) => {
    const parts = raw.split(/[\s,;]+/).map((x) => (upper ? x.toUpperCase() : x).trim()).filter(Boolean)
    if (parts.length) onChange(Array.from(new Set([...value, ...parts])))
    setInput('')
  }
  return (
    <TextField
      fullWidth
      label={label}
      value={input}
      placeholder={value.length ? 'Add more…' : placeholder}
      helperText={helperText}
      onChange={(e) => {
        const v = e.target.value
        if (/[\s,;]$/.test(v)) commit(v)
        else setInput(v)
      }}
      onKeyDown={(e) => {
        if (e.key === 'Enter') {
          e.preventDefault()
          commit(input)
        } else if (e.key === 'Backspace' && !input && value.length) {
          onChange(value.slice(0, -1))
        }
      }}
      onBlur={() => input && commit(input)}
      InputLabelProps={{ shrink: value.length > 0 || input.length > 0 || undefined }}
      InputProps={{
        sx: { flexWrap: 'wrap', gap: 0.5, py: value.length ? 0.6 : undefined },
        startAdornment: value.length ? (
          <>
            {value.map((v) => (
              <Chip key={v} size="small" label={v} onDelete={() => onChange(value.filter((x) => x !== v))} />
            ))}
          </>
        ) : undefined,
      }}
      inputProps={{ style: { minWidth: 120, flex: 1, width: 'auto' } }}
    />
  )
}

export function Confirm({ open, title, text, danger, onClose, onConfirm, confirmLabel = 'Confirm' }: {
  open: boolean; title: string; text: ReactNode; danger?: boolean; onClose: () => void; onConfirm: () => void; confirmLabel?: string
}) {
  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>{text}</DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" color={danger ? 'error' : 'primary'} onClick={onConfirm}>{confirmLabel}</Button>
      </DialogActions>
    </Dialog>
  )
}

export function LabeledSwitch({ label, checked, onChange, hint }: { label: string; checked: boolean; onChange: (v: boolean) => void; hint?: string }) {
  return (
    <Stack direction="row" alignItems="center" sx={{ py: 0.5 }}>
      <Box sx={{ flex: 1 }}>
        <Typography sx={{ fontWeight: 600, fontSize: 13.5 }}>{label}</Typography>
        {hint && <Typography sx={{ fontSize: 12, color: 'text.secondary' }}>{hint}</Typography>}
      </Box>
      <Switch checked={checked} onChange={(e) => onChange(e.target.checked)} />
    </Stack>
  )
}

/** Polls fn every `ms` when `on`. */
export function useInterval(fn: () => void, ms: number, on: boolean) {
  useEffect(() => {
    if (!on || ms <= 0) return
    const t = setInterval(fn, ms)
    return () => clearInterval(t)
  }, [fn, ms, on])
}

export function AutoRefresh({ value, onChange }: { value: number; onChange: (v: number) => void }) {
  return (
    <TextField select label="Auto refresh" value={value} onChange={(e) => onChange(Number(e.target.value))} sx={{ width: 130 }}>
      <MenuItem value={0}>Off</MenuItem>
      <MenuItem value={5000}>5 seconds</MenuItem>
      <MenuItem value={15000}>15 seconds</MenuItem>
      <MenuItem value={60000}>1 minute</MenuItem>
    </TextField>
  )
}

export function Empty({ text }: { text: string }) {
  return <Typography sx={{ color: 'text.secondary', textAlign: 'center', py: 5 }}>{text}</Typography>
}
