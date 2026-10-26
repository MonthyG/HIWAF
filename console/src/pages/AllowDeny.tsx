import { useCallback, useEffect, useState } from 'react'
import { Box, Button, Chip, IconButton, Paper, Stack, Switch, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import EditIcon from '@mui/icons-material/EditOutlined'
import DeleteIcon from '@mui/icons-material/DeleteOutline'
import { api, errText } from '../api'
import { useApp } from '../context'
import type { GlobalRule, IPGroup } from '../types'
import EventLog from '../components/EventLog'
import RuleEditor, { matchSummary, type RuleValue } from '../components/RuleEditor'
import { Confirm, Empty, PageTitle, siteName } from '../components/common'
import { fmtTime } from '../util'

function CustomRules() {
  const { siteById, notify, notifyError } = useApp()
  const [rules, setRules] = useState<GlobalRule[]>([])
  const [groups, setGroups] = useState<Record<string, IPGroup>>({})
  const [edit, setEdit] = useState<{ rule?: GlobalRule } | null>(null)
  const [del, setDel] = useState<GlobalRule | null>(null)

  const load = useCallback(() => {
    api.get<GlobalRule[]>('/rules').then(setRules).catch(notifyError)
    api.get<IPGroup[]>('/ip-groups').then((g) => setGroups(Object.fromEntries(g.map((x) => [x.id, x])))).catch(() => {})
  }, [notifyError])
  useEffect(() => { load() }, [load])

  const body = (r: RuleValue) => ({
    name: r.name, enabled: r.enabled ?? true, action: r.action, sites: r.sites ?? [], ip_groups: r.ip_groups ?? [],
    not_ip_groups: r.not_ip_groups ?? [], match: r.match, priority: r.priority ?? 0,
  })
  const toggle = async (r: GlobalRule) => {
    try {
      await api.put(`/rules/${r.id}`, body({ ...r, enabled: !r.enabled }))
      load()
    } catch (e) {
      notifyError(e)
    }
  }
  const summary = (r: GlobalRule) => {
    const parts = [matchSummary(r.match)]
    if (r.ip_groups?.length) parts.unshift(`IP in group ${r.ip_groups.map((g) => groups[g]?.name ?? g).join(', ')}`)
    if (r.not_ip_groups?.length) parts.unshift(`IP not in group ${r.not_ip_groups.map((g) => groups[g]?.name ?? g).join(', ')}`)
    return parts.filter((p) => p !== 'no conditions').join(' AND ') || 'no conditions'
  }

  return (
    <Paper sx={{ borderRadius: 2, overflow: 'hidden' }}>
      <Stack direction="row" alignItems="center" sx={{ p: 2 }}>
        <Typography sx={{ flex: 1, color: 'text.secondary', fontSize: 13 }}>
          Custom rules run before each application's own rules, in priority order; the first match wins.
        </Typography>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setEdit({})}>Add Rule</Button>
      </Stack>
      <Table size="small">
        <TableHead>
          <TableRow><TableCell>Enabled</TableCell><TableCell>Name</TableCell><TableCell>Action</TableCell><TableCell>Applies to</TableCell><TableCell>Conditions</TableCell><TableCell>Updated</TableCell><TableCell /></TableRow>
        </TableHead>
        <TableBody>
          {rules.map((r) => (
            <TableRow key={r.id} hover>
              <TableCell><Switch size="small" checked={r.enabled} onChange={() => toggle(r)} /></TableCell>
              <TableCell sx={{ fontWeight: 600 }}>{r.name}</TableCell>
              <TableCell>
                <Chip size="small" label={r.action === 'allow' ? 'Allow' : 'Deny'} sx={{ borderRadius: 1, bgcolor: r.action === 'allow' ? 'rgba(22,163,74,.1)' : 'rgba(229,72,77,.1)', color: r.action === 'allow' ? '#15803d' : '#c62828' }} />
              </TableCell>
              <TableCell sx={{ fontSize: 12.5 }}>
                {r.sites?.length ? r.sites.map((s) => (siteById[s] ? siteName(siteById[s]) : s)).join(', ') : 'All applications'}
              </TableCell>
              <TableCell sx={{ fontSize: 12.5, color: 'text.secondary', maxWidth: 420 }}>{summary(r)}</TableCell>
              <TableCell sx={{ whiteSpace: 'nowrap', fontSize: 12.5 }}>{fmtTime(r.updated)}</TableCell>
              <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                <IconButton size="small" onClick={() => setEdit({ rule: r })}><EditIcon fontSize="small" /></IconButton>
                <IconButton size="small" onClick={() => setDel(r)}><DeleteIcon fontSize="small" /></IconButton>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {!rules.length && <Empty text="No custom rules. Add one to allow or deny traffic by IP, region, path, header and more." />}
      {edit && (
        <RuleEditor
          open global
          title={edit.rule ? 'Edit custom rule' : 'Add custom rule'}
          initial={edit.rule
            ? { name: edit.rule.name, action: edit.rule.action, match: edit.rule.match, sites: edit.rule.sites, ip_groups: edit.rule.ip_groups,
                not_ip_groups: edit.rule.not_ip_groups, enabled: edit.rule.enabled, priority: edit.rule.priority }
            : { name: '', action: 'block', match: {}, enabled: true, priority: 0 }}
          onClose={() => setEdit(null)}
          onSubmit={async (v) => {
            try {
              if (edit.rule) await api.put(`/rules/${edit.rule.id}`, body(v))
              else await api.post('/rules', body(v))
            } catch (e) {
              throw new Error(errText(e))
            }
            setEdit(null)
            notify('Rule saved')
            load()
          }}
        />
      )}
      <Confirm open={!!del} danger title="Delete rule" text={<>Delete rule <b>{del?.name}</b>?</>} confirmLabel="Delete"
        onClose={() => setDel(null)}
        onConfirm={async () => {
          const r = del!
          setDel(null)
          try { await api.del(`/rules/${r.id}`); notify('Rule deleted'); load() } catch (e) { notifyError(e) }
        }} />
    </Paper>
  )
}

export default function AllowDeny() {
  return (
    <Box>
      <PageTitle title="Allow & Deny" sub="Access control by IP, IP group, region and request attributes." />
      <EventLog
        types={['ip_block', 'geo_block', 'rule_block', 'allowed_by_rule']}
        extraViews={[{ key: 'rules', label: 'Custom Rules', render: () => <CustomRules /> }]}
      />
    </Box>
  )
}
