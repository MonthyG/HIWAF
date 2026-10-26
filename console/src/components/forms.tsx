import { useEffect, useState } from 'react'
import {
  Alert, Box, Button, Checkbox, Divider, FormControlLabel, Grid2 as Grid, IconButton, MenuItem, Slider, Stack,
  Switch, TextField, ToggleButton, ToggleButtonGroup, Typography,
} from '@mui/material'
import AddIcon from '@mui/icons-material/AddCircleOutline'
import DeleteIcon from '@mui/icons-material/DeleteOutline'
import { api, errText } from '../api'
import { useApp } from '../context'
import type { IPGroup, Limit, Rule, SiteView } from '../types'
import { ChipsInput, LabeledSwitch } from './common'
import RuleEditor, { emptyMatch, matchSummary } from './RuleEditor'

export interface FormProps {
  site: SiteView
  onSaved?: (s: SiteView) => void
  compact?: boolean
}

/** useSave PATCHes the site and reports the result. */
function useSave(site: SiteView, onSaved?: (s: SiteView) => void) {
  const { reloadSites, notify } = useApp()
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const save = async (patch: Record<string, unknown>) => {
    setBusy(true)
    setErr('')
    try {
      const s = await api.patch<SiteView>(`/sites/${site.id}`, patch)
      await reloadSites()
      notify('Saved')
      onSaved?.(s)
      return true
    } catch (e) {
      setErr(errText(e))
      return false
    } finally {
      setBusy(false)
    }
  }
  return { busy, err, save }
}

function SaveBar({ busy, err, onSave }: { busy: boolean; err: string; onSave: () => void }) {
  return (
    <Stack spacing={1.5} sx={{ mt: 2 }}>
      {err && <Alert severity="error">{err}</Alert>}
      <Box>
        <Button variant="contained" onClick={onSave} disabled={busy}>{busy ? 'Saving…' : 'Save'}</Button>
      </Box>
    </Stack>
  )
}

// --- Protection ----------------------------------------------------------

const levels = [
  { p: 1, label: 'Balance', hint: 'Recommended. Blocks obvious attacks with very few false positives.' },
  { p: 2, label: 'Strict', hint: 'Blocks more risky requests; some false positives possible.' },
  { p: 3, label: 'Paranoid', hint: 'Aggressive. Expect false positives; tune with allow rules.' },
  { p: 4, label: 'Extreme', hint: 'Every CRS rule. For testing only.' },
]

export function ProtectionForm({ site, onSaved }: FormProps) {
  const { protections } = useApp()
  const r = site.resolved
  const [mode, setMode] = useState(r.waf.mode)
  const [paranoia, setParanoia] = useState(r.waf.paranoia)
  const [threshold, setThreshold] = useState(r.waf.anomaly_threshold)
  const [prot, setProt] = useState<Record<string, boolean>>(r.waf.protections)
  const { busy, err, save } = useSave(site, onSaved)
  useEffect(() => {
    setMode(r.waf.mode); setParanoia(r.waf.paranoia); setThreshold(r.waf.anomaly_threshold); setProt(r.waf.protections)
  }, [site]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <Box>
      <Typography sx={{ fontWeight: 600, mb: 1 }}>Protection mode</Typography>
      <ToggleButtonGroup exclusive value={mode} onChange={(_, v) => v && setMode(v)} size="small">
        <ToggleButton value="block" sx={{ px: 3 }}>Defense</ToggleButton>
        <ToggleButton value="detect" sx={{ px: 3 }}>Audit</ToggleButton>
        <ToggleButton value="off" sx={{ px: 3 }}>Disabled</ToggleButton>
      </ToggleButtonGroup>
      <Typography sx={{ fontSize: 12, color: 'text.secondary', mt: 0.8 }}>
        {mode === 'block' ? 'Attacks are blocked and logged.' : mode === 'detect' ? 'Attacks are logged but let through (good for a first week).' : 'Requests are not inspected.'}
      </Typography>

      <Divider sx={{ my: 2.5 }} />
      <Typography sx={{ fontWeight: 600, mb: 1 }}>Detection level</Typography>
      <ToggleButtonGroup exclusive value={paranoia} onChange={(_, v) => v && setParanoia(v)} size="small">
        {levels.map((l) => <ToggleButton key={l.p} value={l.p} sx={{ px: 3 }}>{l.label}</ToggleButton>)}
      </ToggleButtonGroup>
      <Typography sx={{ fontSize: 12, color: 'text.secondary', mt: 0.8 }}>{levels.find((l) => l.p === paranoia)?.hint}</Typography>
      <Box sx={{ maxWidth: 420, mt: 2 }}>
        <Typography sx={{ fontSize: 13 }}>Anomaly score threshold: <b>{threshold}</b></Typography>
        <Slider value={threshold} min={1} max={30} step={1} onChange={(_, v) => setThreshold(v as number)} valueLabelDisplay="auto" />
        <Typography sx={{ fontSize: 12, color: 'text.secondary' }}>
          Lower blocks sooner. One critical rule match scores 5 (the default threshold).
        </Typography>
      </Box>

      <Divider sx={{ my: 2.5 }} />
      <Typography sx={{ fontWeight: 600, mb: 1 }}>Detection modules</Typography>
      <Grid container>
        {protections.map((p) => (
          <Grid key={p.key} size={{ xs: 12, sm: 6 }}>
            <FormControlLabel
              control={<Checkbox checked={!!prot[p.key]} onChange={(e) => setProt({ ...prot, [p.key]: e.target.checked })} />}
              label={<Typography sx={{ fontSize: 13 }}>{p.label}</Typography>}
            />
          </Grid>
        ))}
      </Grid>
      <SaveBar busy={busy} err={err} onSave={() => save({ waf: { mode, paranoia, anomaly_threshold: threshold, protections: prot } })} />
    </Box>
  )
}

// --- Rate limiting -------------------------------------------------------

const limitDefs = [
  { key: 'access', title: 'Basic access limit', hint: 'Every request counts. Bans clients that request too fast (HTTP flood, scrapers).', def: { requests: 100, window_sec: 10, ban_sec: 300 } },
  { key: 'attack', title: 'Attack limit', hint: 'WAF-blocked requests count. Bans persistent attackers.', def: { requests: 10, window_sec: 60, ban_sec: 1800 } },
  { key: 'error', title: 'Error limit', hint: '4xx/5xx responses count. Bans scanners and brute-force attempts.', def: { requests: 50, window_sec: 60, ban_sec: 600 } },
] as const

type LimitKey = (typeof limitDefs)[number]['key']

export function RateLimitForm({ site, onSaved }: FormProps) {
  const r = site.resolved
  const [limits, setLimits] = useState<Record<LimitKey, Limit | null>>(r.rate_limit)
  const { busy, err, save } = useSave(site, onSaved)
  useEffect(() => setLimits(r.rate_limit), [site]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <Stack spacing={2.5}>
      {limitDefs.map((d) => {
        const l = limits[d.key]
        const set = (v: Limit | null) => setLimits({ ...limits, [d.key]: v })
        return (
          <Box key={d.key}>
            <LabeledSwitch label={d.title} hint={d.hint} checked={!!l} onChange={(on) => set(on ? { ...d.def } : null)} />
            {l && (
              <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 1, flexWrap: 'wrap', rowGap: 1 }}>
                <TextField label="Requests" type="number" value={l.requests} onChange={(e) => set({ ...l, requests: Number(e.target.value) })} sx={{ width: 120 }} />
                <Typography>in</Typography>
                <TextField label="Seconds" type="number" value={l.window_sec} onChange={(e) => set({ ...l, window_sec: Number(e.target.value) })} sx={{ width: 110 }} />
                <Typography>→ block for</Typography>
                <TextField label="Seconds" type="number" value={l.ban_sec} onChange={(e) => set({ ...l, ban_sec: Number(e.target.value) })} sx={{ width: 120 }} />
              </Stack>
            )}
          </Box>
        )
      })}
      <SaveBar busy={busy} err={err} onSave={() => save({ rate_limit: limits })} />
    </Stack>
  )
}

// --- Anti-bot --------------------------------------------------------------

export function ChallengeForm({ site, onSaved }: FormProps) {
  const r = site.resolved
  const [enabled, setEnabled] = useState(r.bot_challenge.enabled)
  const [difficulty, setDifficulty] = useState(r.bot_challenge.difficulty)
  const { busy, err, save } = useSave(site, onSaved)
  useEffect(() => { setEnabled(r.bot_challenge.enabled); setDifficulty(r.bot_challenge.difficulty) }, [site]) // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <Box>
      <LabeledSwitch
        label="Bot challenge" checked={enabled} onChange={setEnabled}
        hint="Browsers solve a short JavaScript proof-of-work once per hour; bots and scripts are refused."
      />
      {enabled && (
        <>
          <Alert severity="warning" sx={{ my: 1.5 }}>
            Non-browser clients (APIs, mobile apps, webhooks, curl) get 403. Exempt their paths with an allow rule.
          </Alert>
          <Box sx={{ maxWidth: 420 }}>
            <Typography sx={{ fontSize: 13 }}>Difficulty: <b>{difficulty}</b> {difficulty <= 3 ? '(fast)' : difficulty === 4 ? '(about a second)' : '(slow on phones)'}</Typography>
            <Slider value={difficulty} min={1} max={6} step={1} marks onChange={(_, v) => setDifficulty(v as number)} />
          </Box>
        </>
      )}
      <SaveBar busy={busy} err={err} onSave={() => save({ bot_challenge: { enabled, difficulty } })} />
    </Box>
  )
}

// --- Auth --------------------------------------------------------------------

export function AuthForm({ site, onSaved }: FormProps) {
  const r = site.resolved
  const [enabled, setEnabled] = useState(r.auth.enabled)
  const [ttl, setTtl] = useState(r.auth.session_ttl_sec || 86400)
  const [users, setUsers] = useState<{ username: string; password: string; existing: boolean }[]>([])
  const { busy, err, save } = useSave(site, onSaved)
  useEffect(() => {
    setEnabled(r.auth.enabled)
    setTtl(r.auth.session_ttl_sec || 86400)
    setUsers(r.auth.users.map((u) => ({ username: u.username, password: '', existing: true })))
  }, [site]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <Box>
      <LabeledSwitch label="Authentication challenge" checked={enabled} onChange={setEnabled}
        hint="Visitors must sign in with one of these accounts before reaching the application." />
      <Stack spacing={1.2} sx={{ mt: 2 }}>
        {users.map((u, i) => (
          <Stack key={i} direction="row" spacing={1}>
            <TextField label="Username" value={u.username} disabled={u.existing} sx={{ flex: 1 }}
              onChange={(e) => setUsers(users.map((x, j) => (j === i ? { ...x, username: e.target.value } : x)))} />
            <TextField label={u.existing ? 'New password (leave empty to keep)' : 'Password'} type="password" value={u.password} sx={{ flex: 1 }}
              onChange={(e) => setUsers(users.map((x, j) => (j === i ? { ...x, password: e.target.value } : x)))} />
            <IconButton onClick={() => setUsers(users.filter((_, j) => j !== i))}><DeleteIcon fontSize="small" /></IconButton>
          </Stack>
        ))}
        <Box>
          <Button startIcon={<AddIcon />} onClick={() => setUsers([...users, { username: '', password: '', existing: false }])}>Add user</Button>
        </Box>
        <TextField select label="Stay signed in for" value={ttl} onChange={(e) => setTtl(Number(e.target.value))} sx={{ width: 220 }}>
          {[[3600, '1 hour'], [28800, '8 hours'], [86400, '1 day'], [604800, '7 days'], [2592000, '30 days']].map(([v, l]) => (
            <MenuItem key={v} value={v}>{l}</MenuItem>
          ))}
        </TextField>
      </Stack>
      <SaveBar busy={busy} err={err} onSave={() => save({
        auth: {
          enabled,
          session_ttl_sec: ttl,
          users: users.filter((u) => u.username.trim()).map((u) => (u.password ? { username: u.username.trim(), password: u.password } : { username: u.username.trim() })),
        },
      })} />
    </Box>
  )
}

// --- Waiting room ------------------------------------------------------------

export function WaitRoomForm({ site, onSaved }: FormProps) {
  const r = site.resolved
  const [enabled, setEnabled] = useState(r.waiting_room.enabled)
  const [max, setMax] = useState(r.waiting_room.max_active || 100)
  const [ttl, setTtl] = useState(r.waiting_room.session_ttl_sec || 60)
  const { busy, err, save } = useSave(site, onSaved)
  useEffect(() => {
    setEnabled(r.waiting_room.enabled); setMax(r.waiting_room.max_active || 100); setTtl(r.waiting_room.session_ttl_sec || 60)
  }, [site]) // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <Box>
      <LabeledSwitch label="Waiting room" checked={enabled} onChange={setEnabled}
        hint="When too many visitors are active, new ones wait in a queue page that refreshes automatically." />
      <Stack direction="row" spacing={2} sx={{ mt: 2 }}>
        <TextField label="Max active visitors" type="number" value={max} onChange={(e) => setMax(Number(e.target.value))} sx={{ width: 200 }} />
        <TextField label="Idle timeout (seconds)" type="number" value={ttl} onChange={(e) => setTtl(Number(e.target.value))} sx={{ width: 200 }}
          helperText="A visitor's slot frees up after this long without requests" />
      </Stack>
      <SaveBar busy={busy} err={err} onSave={() => save({ waiting_room: { enabled, max_active: max, session_ttl_sec: ttl } })} />
    </Box>
  )
}

// --- Access control (per-site allow & deny) ---------------------------------

export function AccessForm({ site, onSaved }: FormProps) {
  const { system } = useApp()
  const r = site.resolved
  const [allowIPs, setAllowIPs] = useState<string[]>([])
  const [blockIPs, setBlockIPs] = useState<string[]>([])
  const [allowC, setAllowC] = useState<string[]>([])
  const [blockC, setBlockC] = useState<string[]>([])
  const [allowG, setAllowG] = useState<string[]>([])
  const [blockG, setBlockG] = useState<string[]>([])
  const [rules, setRules] = useState<Rule[]>([])
  const [groups, setGroups] = useState<IPGroup[]>([])
  const [editing, setEditing] = useState<{ i: number; rule: Rule } | null>(null)
  const { busy, err, save } = useSave(site, onSaved)
  useEffect(() => {
    setAllowIPs(r.access.allow_ips ?? []); setBlockIPs(r.access.block_ips ?? [])
    setAllowC(r.access.allow_countries ?? []); setBlockC(r.access.block_countries ?? [])
    setAllowG(r.access.allow_groups ?? []); setBlockG(r.access.block_groups ?? [])
    setRules(r.access.rules ?? [])
  }, [site]) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { api.get<IPGroup[]>('/ip-groups').then(setGroups).catch(() => {}) }, [])

  const groupSelect = (label: string, value: string[], set: (v: string[]) => void) => (
    <TextField select label={label} value={value} SelectProps={{ multiple: true }} onChange={(e) => set(e.target.value as unknown as string[])} fullWidth
      helperText={groups.length ? undefined : 'Create IP groups under Settings → IP Groups'}>
      {groups.map((g) => <MenuItem key={g.id} value={g.id}>{g.name} ({g.ips.length})</MenuItem>)}
    </TextField>
  )

  return (
    <Box>
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, md: 6 }}>
          <ChipsInput label="Allowed IPs (skip all checks)" value={allowIPs} onChange={setAllowIPs} placeholder="1.2.3.4, 10.0.0.0/8" />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <ChipsInput label="Blocked IPs" value={blockIPs} onChange={setBlockIPs} placeholder="1.2.3.4, 10.0.0.0/8" />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>{groupSelect('Allowed IP groups', allowG, setAllowG)}</Grid>
        <Grid size={{ xs: 12, md: 6 }}>{groupSelect('Blocked IP groups', blockG, setBlockG)}</Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <ChipsInput label="Allow only these countries" value={allowC} onChange={setAllowC} upper placeholder="TW, ID, US"
            helperText={system?.geoip ? 'ISO codes. Empty = all countries.' : 'Needs the GeoIP database (not configured).'} />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <ChipsInput label="Block these countries" value={blockC} onChange={setBlockC} upper placeholder="KP, RU" />
        </Grid>
      </Grid>

      <Divider sx={{ my: 2.5 }} />
      <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
        <Typography sx={{ fontWeight: 600, flex: 1 }}>Application rules <Typography component="span" sx={{ fontSize: 12, color: 'text.secondary' }}>(run after the global custom rules; first match wins)</Typography></Typography>
        <Button startIcon={<AddIcon />} onClick={() => setEditing({ i: -1, rule: { name: '', action: 'block', match: emptyMatch() } })}>Add rule</Button>
      </Stack>
      {!rules.length && <Typography sx={{ color: 'text.secondary', fontSize: 13 }}>No application rules.</Typography>}
      <Stack spacing={1}>
        {rules.map((rule, i) => (
          <Stack key={i} direction="row" alignItems="center" sx={{ border: '1px solid #eef1f3', borderRadius: 1.5, px: 1.5, py: 1 }} spacing={1.5}>
            <Typography sx={{ fontWeight: 700, fontSize: 12, color: rule.action === 'allow' ? 'success.main' : 'error.main', width: 50 }}>
              {rule.action === 'allow' ? 'ALLOW' : 'DENY'}
            </Typography>
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Typography sx={{ fontSize: 13, fontWeight: 600 }}>{rule.name || `Rule ${i + 1}`}</Typography>
              <Typography sx={{ fontSize: 12, color: 'text.secondary' }}>{matchSummary(rule.match)}</Typography>
            </Box>
            <Button size="small" onClick={() => setEditing({ i, rule })}>Edit</Button>
            <IconButton size="small" onClick={() => setRules(rules.filter((_, j) => j !== i))}><DeleteIcon fontSize="small" /></IconButton>
          </Stack>
        ))}
      </Stack>
      {editing && (
        <RuleEditor
          open
          title={editing.i < 0 ? 'Add application rule' : 'Edit application rule'}
          initial={{ name: editing.rule.name ?? '', action: editing.rule.action, match: editing.rule.match }}
          onClose={() => setEditing(null)}
          onSubmit={(v) => {
            const rule: Rule = { name: v.name, action: v.action, match: v.match }
            setRules(editing.i < 0 ? [...rules, rule] : rules.map((x, j) => (j === editing.i ? rule : x)))
            setEditing(null)
          }}
        />
      )}
      <SaveBar busy={busy} err={err} onSave={() => save({
        access: {
          allow_ips: allowIPs, block_ips: blockIPs, allow_countries: allowC, block_countries: blockC,
          allow_groups: allowG, block_groups: blockG, rules,
          ...(r.access.block_ips_file ? { block_ips_file: r.access.block_ips_file } : {}),
        },
      })} />
    </Box>
  )
}

// --- Advanced --------------------------------------------------------------

export function AdvancedForm({ site, onSaved }: FormProps) {
  const r = site.resolved
  const [adv, setAdv] = useState(r.advanced)
  const [lb, setLb] = useState(r.lb_policy || 'round_robin')
  const [title, setTitle] = useState(r.block_page.title)
  const [message, setMessage] = useState(r.block_page.message)
  const { busy, err, save } = useSave(site, onSaved)
  useEffect(() => { setAdv(r.advanced); setLb(r.lb_policy || 'round_robin'); setTitle(r.block_page.title); setMessage(r.block_page.message) }, [site]) // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <Box>
      <Stack spacing={0.5} sx={{ maxWidth: 640 }}>
        <LabeledSwitch label="Redirect HTTP to HTTPS" checked={adv.http_redirect} onChange={(v) => setAdv({ ...adv, http_redirect: v })} />
        <LabeledSwitch label="HSTS" hint="Tell browsers to always use HTTPS for a year" checked={adv.hsts} onChange={(v) => setAdv({ ...adv, hsts: v })} />
        <LabeledSwitch label="Compression (gzip / zstd)" checked={adv.gzip} onChange={(v) => setAdv({ ...adv, gzip: v })} />
        <LabeledSwitch label="Pass the original Host header" hint="Turn off if the upstream expects its own host name" checked={adv.keep_host} onChange={(v) => setAdv({ ...adv, keep_host: v })} />
      </Stack>
      {r.type === 'proxy' && (
        <TextField select label="Load balancing" value={lb} onChange={(e) => setLb(e.target.value)} sx={{ width: 260, mt: 2 }}>
          <MenuItem value="round_robin">Round robin</MenuItem>
          <MenuItem value="ip_hash">IP hash (sticky by client IP)</MenuItem>
          <MenuItem value="least_conn">Least connections</MenuItem>
        </TextField>
      )}
      <Divider sx={{ my: 2.5 }} />
      <Typography sx={{ fontWeight: 600, mb: 1.5 }}>Block page</Typography>
      <Stack spacing={1.5} sx={{ maxWidth: 640 }}>
        <TextField label="Title" value={title} onChange={(e) => setTitle(e.target.value)} inputProps={{ maxLength: 200 }} />
        <TextField label="Message" value={message} onChange={(e) => setMessage(e.target.value)} multiline minRows={2} inputProps={{ maxLength: 2000 }} />
      </Stack>
      <SaveBar busy={busy} err={err} onSave={() => save({
        advanced: adv, ...(r.type === 'proxy' ? { lb_policy: lb } : {}), block_page: { title, message },
      })} />
    </Box>
  )
}

export { Switch }
