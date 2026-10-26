import { useEffect, useState } from 'react'
import {
  Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, IconButton, MenuItem,
  Radio, RadioGroup, Stack, TextField, ToggleButton, ToggleButtonGroup, Typography, Checkbox,
} from '@mui/material'
import AddIcon from '@mui/icons-material/AddCircleOutline'
import DeleteIcon from '@mui/icons-material/DeleteOutline'
import { api, errText } from '../api'
import { useApp } from '../context'
import type { Certificate, Port, SiteView } from '../types'
import { ChipsInput } from './common'

interface Props {
  open: boolean
  site?: SiteView // edit when set
  onClose: () => void
  onSaved: (s: SiteView) => void
}

type AppType = 'proxy' | 'static' | 'redirect'

export default function AppDialog({ open, site, onClose, onSaved }: Props) {
  const { system } = useApp()
  const [domains, setDomains] = useState<string[]>([])
  const [ports, setPorts] = useState<Port[]>([])
  const [cert, setCert] = useState('auto')
  const [type, setType] = useState<AppType>('proxy')
  const [upstreams, setUpstreams] = useState<string[]>([''])
  const [redirectURL, setRedirectURL] = useState('')
  const [redirectCode, setRedirectCode] = useState(302)
  const [preserve, setPreserve] = useState(true)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [certs, setCerts] = useState<Certificate[]>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setErr('')
    api.get<Certificate[]>('/certificates').then(setCerts).catch(() => setCerts([]))
    const http = system?.http_port ?? 80
    const https = system?.https_port ?? 443
    if (site) {
      const r = site.resolved
      setDomains(r.domains.filter((d) => d !== '*'))
      setPorts(r.ports)
      setCert(r.tls.mode === 'uploaded' ? r.tls.cert_id || 'legacy' : 'auto')
      setType(r.type)
      setUpstreams(r.upstreams?.length ? r.upstreams : [''])
      setRedirectURL(r.redirect.url)
      setRedirectCode(r.redirect.code || 302)
      setPreserve(r.redirect.preserve_path)
      setName(r.name)
      setDescription(r.description)
    } else {
      setDomains([])
      setPorts([{ port: http, https: false }, { port: https, https: true }])
      setCert('auto')
      setType('proxy')
      setUpstreams([''])
      setRedirectURL('')
      setRedirectCode(302)
      setPreserve(true)
      setName('')
      setDescription('')
    }
  }, [open, site, system])

  const anyHTTPS = ports.some((p) => p.https)

  const save = async () => {
    setErr('')
    const doms = domains.length ? domains : ['*']
    if (doms.includes('*') && anyHTTPS) {
      setErr('An application without a domain (match all hosts) can only listen on HTTP ports. Add a domain or switch the ports to HTTP.')
      return
    }
    const doc: Record<string, any> = {
      name: name.trim(),
      description: description.trim(),
      type,
      domains: doms,
      ports: ports.map((p) => ({ port: Number(p.port), https: p.https })),
      tls: !anyHTTPS ? { mode: 'off' } : cert === 'auto' ? { mode: 'auto' } : cert === 'legacy' ? { mode: 'uploaded' } : { mode: 'uploaded', cert_id: cert },
      upstreams: type === 'proxy' ? upstreams.map((u) => u.trim()).filter(Boolean) : null,
      redirect: type === 'redirect' ? { url: redirectURL.trim(), code: redirectCode, preserve_path: preserve } : null,
    }
    setBusy(true)
    try {
      let saved: SiteView
      if (site) {
        saved = await api.patch<SiteView>(`/sites/${site.id}`, doc)
      } else {
        for (const k of Object.keys(doc)) if (doc[k] === null || doc[k] === '') delete doc[k]
        saved = await api.post<SiteView>('/sites', doc)
      }
      onSaved(saved)
    } catch (e) {
      setErr(errText(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{site ? 'Edit Application' : 'Add Application'}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error">{err}</Alert>}
          <ChipsInput
            label="Domain"
            value={domains}
            onChange={(v) => setDomains(v.map((d) => d.toLowerCase()))}
            placeholder="www.example.com, supports *.example.com"
            helperText="Leave empty to match all hosts (HTTP only). Press Enter after each domain."
          />
          {ports.map((p, i) => (
            <Stack key={i} direction="row" spacing={1} alignItems="center">
              <TextField
                label="Port" type="number" value={p.port} sx={{ flex: 1 }}
                onChange={(e) => setPorts(ports.map((x, j) => (j === i ? { ...x, port: Number(e.target.value) } : x)))}
              />
              <ToggleButtonGroup
                size="small" exclusive value={p.https ? 'https' : 'http'}
                onChange={(_, v) => v && setPorts(ports.map((x, j) => (j === i ? { ...x, https: v === 'https' } : x)))}
              >
                <ToggleButton value="http" sx={{ px: 2 }}>HTTP</ToggleButton>
                <ToggleButton value="https" sx={{ px: 2 }}>HTTPS</ToggleButton>
              </ToggleButtonGroup>
              <IconButton onClick={() => setPorts(ports.filter((_, j) => j !== i))} disabled={ports.length === 1}>
                <DeleteIcon fontSize="small" />
              </IconButton>
            </Stack>
          ))}
          <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setPorts([...ports, { port: 8080, https: false }])}>
            Add listening port
          </Button>
          {anyHTTPS && (
            <TextField select label="SSL Cert" value={cert} onChange={(e) => setCert(e.target.value)}
              helperText={cert === 'auto' ? 'Issued and renewed automatically (ACME). The domain must point to this WAF.' : undefined}>
              <MenuItem value="auto">Automatic certificate (Let's Encrypt / internal CA)</MenuItem>
              {site?.resolved.tls.mode === 'uploaded' && !site.resolved.tls.cert_id && <MenuItem value="legacy">Certificate uploaded for this application</MenuItem>}
              {certs.map((c) => (
                <MenuItem key={c.id} value={c.id}>{c.name} {c.dns_names?.length ? `(${c.dns_names.join(', ')})` : ''}</MenuItem>
              ))}
            </TextField>
          )}
          <RadioGroup row value={type} onChange={(e) => setType(e.target.value as AppType)}>
            {(['proxy', 'static', 'redirect'] as AppType[]).map((t) => (
              <Box key={t} sx={{ flex: 1, border: '1px solid', borderColor: type === t ? 'primary.main' : '#dfe5e9', borderRadius: 1.5, mr: t === 'redirect' ? 0 : 1, px: 1 }}>
                <FormControlLabel value={t} control={<Radio size="small" />} label={t === 'proxy' ? 'Reverse Proxy' : t === 'static' ? 'Static Files' : 'Redirect'} />
              </Box>
            ))}
          </RadioGroup>
          {type === 'proxy' && (
            <>
              {upstreams.map((u, i) => (
                <Stack key={i} direction="row" spacing={1}>
                  <TextField
                    label="Upstream" required value={u} sx={{ flex: 1 }} placeholder="http://192.168.1.10:8080, no path"
                    onChange={(e) => setUpstreams(upstreams.map((x, j) => (j === i ? e.target.value : x)))}
                  />
                  <IconButton onClick={() => setUpstreams(upstreams.filter((_, j) => j !== i))} disabled={upstreams.length === 1}>
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                </Stack>
              ))}
              <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setUpstreams([...upstreams, ''])}>
                Add upstream (load balancing)
              </Button>
            </>
          )}
          {type === 'static' && (
            <Alert severity="info">After saving, upload a .zip of the site's files on the application's page.</Alert>
          )}
          {type === 'redirect' && (
            <Stack spacing={1.5}>
              <TextField label="Redirect to" value={redirectURL} onChange={(e) => setRedirectURL(e.target.value)} placeholder="https://www.example.com" />
              <Stack direction="row" spacing={2} alignItems="center">
                <TextField select label="Status code" value={redirectCode} onChange={(e) => setRedirectCode(Number(e.target.value))} sx={{ width: 200 }}>
                  {[301, 302, 307, 308].map((c) => <MenuItem key={c} value={c}>{c}{c === 301 || c === 308 ? ' (permanent)' : ' (temporary)'}</MenuItem>)}
                </TextField>
                <FormControlLabel control={<Checkbox checked={preserve} onChange={(e) => setPreserve(e.target.checked)} />} label="Keep the request path" />
              </Stack>
            </Stack>
          )}
          <TextField label="Application Name" value={name} onChange={(e) => setName(e.target.value)} inputProps={{ maxLength: 64 }} />
          <TextField label="Application Description" value={description} onChange={(e) => setDescription(e.target.value)} multiline minRows={2} inputProps={{ maxLength: 500 }} />
          <Typography sx={{ fontSize: 12, color: 'text.secondary' }}>
            Protection, rate limiting, bot protection and access rules are set on the application's page after it is created.
          </Typography>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={save} disabled={busy}>{busy ? 'Saving…' : 'Submit'}</Button>
      </DialogActions>
    </Dialog>
  )
}
