import { useState, type ReactNode } from 'react'
import { Button, Dialog, DialogContent, DialogTitle, IconButton, Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material'
import CloseIcon from '@mui/icons-material/Close'
import { useApp } from '../context'
import type { SiteView } from '../types'
import { Empty, SiteLabel } from './common'

/** A per-application table of one feature with an edit dialog. */
export default function SiteFeatureTable({ columns, editTitle, renderForm, emptyText }: {
  columns: { label: string; render: (s: SiteView) => ReactNode }[]
  editTitle: string
  renderForm: (s: SiteView, done: () => void) => ReactNode
  emptyText?: string
}) {
  const { sites } = useApp()
  const [edit, setEdit] = useState<string | null>(null)
  const { siteById } = useApp()
  const site = edit ? siteById[edit] : undefined
  return (
    <Paper sx={{ borderRadius: 2, overflow: 'hidden' }}>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Application</TableCell>
            {columns.map((c) => <TableCell key={c.label}>{c.label}</TableCell>)}
            <TableCell />
          </TableRow>
        </TableHead>
        <TableBody>
          {sites.map((s) => (
            <TableRow key={s.id} hover>
              <TableCell><SiteLabel id={s.id} /></TableCell>
              {columns.map((c) => <TableCell key={c.label}>{c.render(s)}</TableCell>)}
              <TableCell align="right"><Button size="small" onClick={() => setEdit(s.id)}>Edit</Button></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {!sites.length && <Empty text={emptyText ?? 'No applications yet.'} />}
      <Dialog open={!!site} onClose={() => setEdit(null)} maxWidth="sm" fullWidth>
        <DialogTitle>
          <Stack direction="row" alignItems="center">
            <Typography variant="h6" sx={{ flex: 1 }}>{editTitle}</Typography>
            <IconButton onClick={() => setEdit(null)}><CloseIcon /></IconButton>
          </Stack>
        </DialogTitle>
        <DialogContent>{site && renderForm(site, () => setEdit(null))}</DialogContent>
      </Dialog>
    </Paper>
  )
}

export function OnOff({ on, text }: { on: boolean; text?: string }) {
  return (
    <Typography sx={{ fontSize: 13, fontWeight: 600, color: on ? 'primary.main' : 'text.secondary' }}>
      {on ? text ?? 'On' : 'Off'}
    </Typography>
  )
}
