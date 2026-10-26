import { useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, IconButton, Paper, Stack, Tab, Table,
  TableBody, TableCell, TableHead, TableRow, Tabs, TextField, Typography,
} from '@mui/material'
import AddIcon from '@mui/icons-material/Add'
import DeleteIcon from '@mui/icons-material/DeleteOutline'
import EditIcon from '@mui/icons-material/EditOutlined'
import QRCode from 'qrcode'
import { api, errText } from '../api'
import { useApp } from '../context'
import type { Certificate, IPGroup, Me, Token } from '../types'
import { Confirm, Empty, PageTitle, Section, siteName } from '../components/common'
import { fmtTime } from '../util'

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <Stack direction="row" sx={{ py: 1, borderBottom: '1px solid #f0f3f5', fontSize: 13.5 }}>
      <Box sx={{ width: 200, color: 'text.secondary' }}>{k}</Box>
      <Box sx={{ flex: 1 }}>{v}</Box>
    </Stack>
  )
}

function SystemTab() {
  const { system } = useApp()
  if (!system) return null
  const ok = (b: boolean, yes = 'Enabled', no = 'Not configured') => (
    <Chip size="small" label={b ? yes : no} sx={{ borderRadius: 1, bgcolor: b ? 'rgba(15,165,160,.1)' : '#f1f4f6', color: b ? 'primary.main' : 'text.secondary' }} />
  )
  return (
    <Section title="System">
      <Row k="Version" v={system.version} />
      <Row k="Engine" v={system.engine_ok ? ok(true, 'Online') : <Typography color="error" sx={{ fontSize: 13 }}>Offline: {system.engine_error}</Typography>} />
      <Row k="Manager started" v={fmtTime(system.started)} />
      <Row k="Applications" v={system.sites} />
      <Row k="Default HTTP / HTTPS ports" v={`${system.http_port} / ${system.https_port}`} />
      <Row k="GeoIP database" v={ok(system.geoip)} />
      <Row k="Traffic statistics (access log)" v={ok(system.access_log)} />
      <Row k="Static file applications" v={ok(system.static_sites)} />
    </Section>
  )
}

function CertTab() {
  const { siteById, notify, notifyError } = useApp()
  const [certs, setCerts] = useState<Certificate[]>([])
  const [dlg, setDlg] = useState<{ cert?: Certificate } | null>(null)
  const [del, setDel] = useState<Certificate | null>(null)
  const load = useCallback(() => api.get<Certificate[]>('/certificates').then(setCerts).catch(notifyError), [notifyError])
  useEffect(() => { load() }, [load])
  return (
    <Paper sx={{ borderRadius: 2, overflow: 'hidden' }}>
      <Stack direction="row" alignItems="center" sx={{ p: 2 }}>
        <Typography sx={{ flex: 1, fontSize: 13, color: 'text.secondary' }}>
          Uploaded certificates can be chosen in an application's SSL Cert setting. Applications with “automatic certificate” don't need one.
        </Typography>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setDlg({})}>Upload certificate</Button>
      </Stack>
      <Table size="small">
        <TableHead><TableRow><TableCell>Name</TableCell><TableCell>Domains</TableCell><TableCell>Issuer</TableCell><TableCell>Expires</TableCell><TableCell>Used by</TableCell><TableCell /></TableRow></TableHead>
        <TableBody>
          {certs.map((c) => {
            const days = Math.round((new Date(c.not_after).getTime() - Date.now()) / 86400000)
            return (
              <TableRow key={c.id} hover>
                <TableCell sx={{ fontWeight: 600 }}>{c.name}</TableCell>
                <TableCell sx={{ fontSize: 12.5 }}>{(c.dns_names ?? []).join(', ') || c.subject}</TableCell>
                <TableCell sx={{ fontSize: 12.5 }}>{c.issuer}</TableCell>
                <TableCell sx={{ color: days < 15 ? 'error.main' : 'text.primary', whiteSpace: 'nowrap' }}>{fmtTime(c.not_after)} ({days} d)</TableCell>
                <TableCell sx={{ fontSize: 12.5 }}>{c.used_by.map((s) => (siteById[s] ? siteName(siteById[s]) : s)).join(', ') || '-'}</TableCell>
                <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                  <IconButton size="small" onClick={() => setDlg({ cert: c })}><EditIcon fontSize="small" /></IconButton>
                  <IconButton size="small" onClick={() => setDel(c)}><DeleteIcon fontSize="small" /></IconButton>
                </TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
      {!certs.length && <Empty text="No certificates uploaded." />}
      <CertDialog open={!!dlg} cert={dlg?.cert} onClose={() => setDlg(null)} onSaved={() => { setDlg(null); notify('Certificate saved'); load() }} />
      <Confirm open={!!del} danger title="Delete certificate" text={<>Delete <b>{del?.name}</b>?</>} confirmLabel="Delete" onClose={() => setDel(null)}
        onConfirm={async () => { const c = del!; setDel(null); try { await api.del(`/certificates/${c.id}`); notify('Certificate deleted'); load() } catch (e) { notifyError(e) } }} />
    </Paper>
  )
}

function CertDialog({ open, cert, onClose, onSaved }: { open: boolean; cert?: Certificate; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState('')
  const [crt, setCrt] = useState('')
  const [key, setKey] = useState('')
  const [err, setErr] = useState('')
  useEffect(() => { if (open) { setName(cert?.name ?? ''); setCrt(''); setKey(''); setErr('') } }, [open, cert])
  const readFile = (f: File, set: (s: string) => void) => f.text().then(set)
  const save = async () => {
    try {
      const body = { name, cert_pem: crt, key_pem: key }
      if (cert) await api.put(`/certificates/${cert.id}`, body)
      else await api.post('/certificates', body)
      onSaved()
    } catch (e) {
      setErr(errText(e))
    }
  }
  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{cert ? 'Replace certificate' : 'Upload certificate'}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error">{err}</Alert>}
          <TextField label="Name (optional)" value={name} onChange={(e) => setName(e.target.value)} />
          {[['Certificate (PEM, with chain)', crt, setCrt], ['Private key (PEM)', key, setKey]].map(([label, val, set]) => (
            <Box key={label as string}>
              <TextField label={label as string} value={val as string} onChange={(e) => (set as (s: string) => void)(e.target.value)} multiline minRows={4} fullWidth
                placeholder="-----BEGIN ..." inputProps={{ style: { fontFamily: 'ui-monospace,Consolas,monospace', fontSize: 12 } }} />
              <Button component="label" size="small" sx={{ mt: 0.5 }}>
                Load from file<input hidden type="file" accept=".pem,.crt,.key,.cer" onChange={(e) => e.target.files?.[0] && readFile(e.target.files[0], set as (s: string) => void)} />
              </Button>
            </Box>
          ))}
        </Stack>
      </DialogContent>
      <DialogActions><Button onClick={onClose}>Cancel</Button><Button variant="contained" onClick={save} disabled={!crt || !key}>Save</Button></DialogActions>
    </Dialog>
  )
}

function GroupTab() {
  const { notify, notifyError } = useApp()
  const [groups, setGroups] = useState<IPGroup[]>([])
  const [dlg, setDlg] = useState<{ g?: IPGroup } | null>(null)
  const [del, setDel] = useState<IPGroup | null>(null)
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')
  const [ips, setIps] = useState('')
  const [err, setErr] = useState('')
  const load = useCallback(() => api.get<IPGroup[]>('/ip-groups').then(setGroups).catch(notifyError), [notifyError])
  useEffect(() => { load() }, [load])
  const open = (g?: IPGroup) => { setDlg({ g }); setName(g?.name ?? ''); setDesc(g?.description ?? ''); setIps((g?.ips ?? []).join('\n')); setErr('') }
  const save = async () => {
    const body = { name, description: desc, ips: ips.split(/[\s,;]+/).filter(Boolean) }
    try {
      if (dlg?.g) await api.put(`/ip-groups/${dlg.g.id}`, body)
      else await api.post('/ip-groups', body)
      setDlg(null); notify('IP group saved'); load()
    } catch (e) { setErr(errText(e)) }
  }
  return (
    <Paper sx={{ borderRadius: 2, overflow: 'hidden' }}>
      <Stack direction="row" alignItems="center" sx={{ p: 2 }}>
        <Typography sx={{ flex: 1, fontSize: 13, color: 'text.secondary' }}>Reusable IP lists for custom rules and application allow/deny lists.</Typography>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => open()}>Add IP group</Button>
      </Stack>
      <Table size="small">
        <TableHead><TableRow><TableCell>Name</TableCell><TableCell>Description</TableCell><TableCell>Entries</TableCell><TableCell>Updated</TableCell><TableCell /></TableRow></TableHead>
        <TableBody>
          {groups.map((g) => (
            <TableRow key={g.id} hover>
              <TableCell sx={{ fontWeight: 600 }}>{g.name}</TableCell>
              <TableCell sx={{ fontSize: 12.5, color: 'text.secondary' }}>{g.description || '-'}</TableCell>
              <TableCell>{g.ips.length}</TableCell>
              <TableCell sx={{ fontSize: 12.5 }}>{fmtTime(g.updated)}</TableCell>
              <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                <IconButton size="small" onClick={() => open(g)}><EditIcon fontSize="small" /></IconButton>
                <IconButton size="small" onClick={() => setDel(g)}><DeleteIcon fontSize="small" /></IconButton>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {!groups.length && <Empty text="No IP groups." />}
      <Dialog open={!!dlg} onClose={() => setDlg(null)} maxWidth="sm" fullWidth>
        <DialogTitle>{dlg?.g ? 'Edit IP group' : 'Add IP group'}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            {err && <Alert severity="error">{err}</Alert>}
            <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} />
            <TextField label="Description" value={desc} onChange={(e) => setDesc(e.target.value)} />
            <TextField label="IPs and CIDRs (one per line)" value={ips} onChange={(e) => setIps(e.target.value)} multiline minRows={6}
              inputProps={{ style: { fontFamily: 'ui-monospace,Consolas,monospace', fontSize: 12.5 } }} />
          </Stack>
        </DialogContent>
        <DialogActions><Button onClick={() => setDlg(null)}>Cancel</Button><Button variant="contained" onClick={save}>Save</Button></DialogActions>
      </Dialog>
      <Confirm open={!!del} danger title="Delete IP group" text={<>Delete <b>{del?.name}</b>?</>} confirmLabel="Delete" onClose={() => setDel(null)}
        onConfirm={async () => { const g = del!; setDel(null); try { await api.del(`/ip-groups/${g.id}`); notify('IP group deleted'); load() } catch (e) { notifyError(e) } }} />
    </Paper>
  )
}

function AccountTab() {
  const { me, setMe, notify, notifyError } = useApp()
  const [oldPw, setOldPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [newPw2, setNewPw2] = useState('')
  const [pwErr, setPwErr] = useState('')
  const [setup, setSetup] = useState<{ secret: string; qr: string } | null>(null)
  const [code, setCode] = useState('')
  const [disablePw, setDisablePw] = useState('')
  const [tfaErr, setTfaErr] = useState('')

  if (!me || me.kind !== 'user') return <Alert severity="info">Account settings are only available to console users.</Alert>
  const changePw = async () => {
    if (newPw !== newPw2) { setPwErr('The new passwords differ.'); return }
    try {
      await api.post('/auth/password', { old_password: oldPw, new_password: newPw })
      setOldPw(''); setNewPw(''); setNewPw2(''); setPwErr('')
      notify('Password changed. Other sessions were signed out.')
    } catch (e) { setPwErr(errText(e)) }
  }
  const startTotp = async () => {
    try {
      const r = await api.post<{ secret: string; otpauth_url: string }>('/auth/totp/setup')
      setSetup({ secret: r.secret, qr: await QRCode.toDataURL(r.otpauth_url, { margin: 1, width: 200 }) })
      setTfaErr('')
    } catch (e) { notifyError(e) }
  }
  const enable = async () => {
    try {
      await api.post('/auth/totp/enable', { code })
      setSetup(null); setCode('')
      setMe({ ...me, totp_enabled: true })
      notify('Two-factor authentication is on')
    } catch (e) { setTfaErr(errText(e)) }
  }
  const disable = async () => {
    try {
      await api.post('/auth/totp/disable', { password: disablePw })
      setDisablePw('')
      setMe({ ...me, totp_enabled: false } as Me)
      notify('Two-factor authentication is off')
    } catch (e) { setTfaErr(errText(e)) }
  }

  return (
    <Stack spacing={2}>
      <Section title={`Password (${me.username})`}>
        <Stack spacing={1.5} sx={{ maxWidth: 380 }}>
          {pwErr && <Alert severity="error">{pwErr}</Alert>}
          <TextField label="Current password" type="password" value={oldPw} onChange={(e) => setOldPw(e.target.value)} />
          <TextField label="New password (8+ characters)" type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} />
          <TextField label="Repeat new password" type="password" value={newPw2} onChange={(e) => setNewPw2(e.target.value)} />
          <Box><Button variant="contained" onClick={changePw} disabled={!oldPw || newPw.length < 8}>Change password</Button></Box>
        </Stack>
      </Section>
      <Section title="Two-factor authentication (TOTP)">
        {tfaErr && <Alert severity="error" sx={{ mb: 1.5 }}>{tfaErr}</Alert>}
        {me.totp_enabled ? (
          <Stack spacing={1.5} sx={{ maxWidth: 380 }}>
            <Alert severity="success">On. Sign-in asks for a code from your authenticator app.</Alert>
            <TextField label="Password to turn it off" type="password" value={disablePw} onChange={(e) => setDisablePw(e.target.value)} />
            <Box><Button color="error" variant="outlined" onClick={disable} disabled={!disablePw}>Turn off</Button></Box>
          </Stack>
        ) : setup ? (
          <Stack direction="row" spacing={3} alignItems="flex-start">
            <img src={setup.qr} width={200} height={200} alt="TOTP QR code" />
            <Stack spacing={1.5} sx={{ maxWidth: 360 }}>
              <Typography sx={{ fontSize: 13 }}>Scan the code with Google Authenticator, Authy or 1Password, or enter this key:</Typography>
              <Typography sx={{ fontFamily: 'ui-monospace,Consolas,monospace', fontSize: 13, wordBreak: 'break-all', bgcolor: '#f3f6f8', p: 1, borderRadius: 1 }}>{setup.secret}</Typography>
              <TextField label="6-digit code" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} />
              <Box><Button variant="contained" onClick={enable} disabled={code.length !== 6}>Turn on</Button></Box>
            </Stack>
          </Stack>
        ) : (
          <Button variant="outlined" onClick={startTotp}>Set up two-factor authentication</Button>
        )}
      </Section>
    </Stack>
  )
}

function TokenTab() {
  const { notify, notifyError } = useApp()
  const [tokens, setTokens] = useState<Token[]>([])
  const [name, setName] = useState('')
  const [created, setCreated] = useState<Token | null>(null)
  const [del, setDel] = useState<Token | null>(null)
  const load = useCallback(() => api.get<Token[]>('/tokens').then(setTokens).catch(notifyError), [notifyError])
  useEffect(() => { load() }, [load])
  return (
    <Stack spacing={2}>
      <Section title="API tokens">
        <Typography sx={{ fontSize: 13, color: 'text.secondary', mb: 1.5 }}>
          Tokens authenticate scripts and other systems (for example the cloud control plane) against <code>/api/v1</code> with
          <code> Authorization: Bearer &lt;token&gt;</code>. A token has full access.
        </Typography>
        <Stack direction="row" spacing={1.5}>
          <TextField label="Token name" value={name} onChange={(e) => setName(e.target.value)} sx={{ width: 280 }} />
          <Button variant="contained" disabled={!name.trim()} onClick={async () => {
            try { setCreated(await api.post<Token>('/tokens', { name })); setName(''); load() } catch (e) { notifyError(e) }
          }}>Create token</Button>
        </Stack>
        {created && (
          <Alert severity="success" sx={{ mt: 2 }} onClose={() => setCreated(null)}>
            Copy this token now; it won't be shown again:
            <Typography sx={{ fontFamily: 'ui-monospace,Consolas,monospace', fontSize: 13, mt: 0.5, wordBreak: 'break-all' }}>{created.token}</Typography>
          </Alert>
        )}
      </Section>
      <Paper sx={{ borderRadius: 2, overflow: 'hidden' }}>
        <Table size="small">
          <TableHead><TableRow><TableCell>Name</TableCell><TableCell>Created</TableCell><TableCell>Last used</TableCell><TableCell /></TableRow></TableHead>
          <TableBody>
            {tokens.map((t) => (
              <TableRow key={t.id}>
                <TableCell sx={{ fontWeight: 600 }}>{t.name}</TableCell>
                <TableCell>{fmtTime(t.created)}</TableCell>
                <TableCell>{t.last_used ? fmtTime(t.last_used) : 'Never'}</TableCell>
                <TableCell align="right"><IconButton size="small" onClick={() => setDel(t)}><DeleteIcon fontSize="small" /></IconButton></TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {!tokens.length && <Empty text="No API tokens." />}
      </Paper>
      <Confirm open={!!del} danger title="Revoke token" text={<>Revoke <b>{del?.name}</b>? Anything using it stops working.</>} confirmLabel="Revoke"
        onClose={() => setDel(null)}
        onConfirm={async () => { const t = del!; setDel(null); try { await api.del(`/tokens/${t.id}`); notify('Token revoked'); load() } catch (e) { notifyError(e) } }} />
    </Stack>
  )
}

const tabs = [
  { key: 'system', label: 'System', el: <SystemTab /> },
  { key: 'certificates', label: 'Certificates', el: <CertTab /> },
  { key: 'ip-groups', label: 'IP Groups', el: <GroupTab /> },
  { key: 'account', label: 'Account', el: <AccountTab /> },
  { key: 'tokens', label: 'API Tokens', el: <TokenTab /> },
]

export default function Settings() {
  const [params, setParams] = useSearchParams()
  const tab = params.get('tab') ?? 'system'
  return (
    <Box>
      <PageTitle title="Settings" />
      <Tabs value={tab} onChange={(_, v) => setParams({ tab: v })} sx={{ mb: 2 }}>
        {tabs.map((t) => <Tab key={t.key} value={t.key} label={t.label} />)}
      </Tabs>
      {tabs.find((t) => t.key === tab)?.el}
    </Box>
  )
}
