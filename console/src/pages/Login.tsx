import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Alert, Box, Button, Paper, Stack, TextField, Typography } from '@mui/material'
import { api, ApiError, errText } from '../api'
import { useApp } from '../context'
import { Logo } from '../components/Layout'
import type { Me } from '../types'

export default function Login() {
  const { setMe } = useApp()
  const navigate = useNavigate()
  const loc = useLocation()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [needTotp, setNeedTotp] = useState(false)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      const me = await api.post<Me>('/auth/login', { username, password, ...(needTotp ? { totp } : {}) })
      setMe(me)
      const from = (loc.state as { from?: string } | null)?.from
      navigate(from && from !== '/login' ? from : '/statistics', { replace: true })
    } catch (e) {
      if (e instanceof ApiError && e.body?.totp_required) {
        setNeedTotp(true)
        setErr(needTotp ? e.message : '')
      } else {
        setErr(errText(e))
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <Box sx={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'radial-gradient(1200px 600px at 20% 10%, rgba(15,165,160,.16), transparent), radial-gradient(900px 500px at 90% 90%, rgba(59,111,214,.12), transparent), #f3f6f8',
    }}>
      <Paper component="form" onSubmit={submit} sx={{ width: 380, p: 4, borderRadius: 3, boxShadow: '0 12px 40px rgba(16,24,40,.10)' }}>
        <Stack spacing={2.2}>
          <Logo />
          <Box>
            <Typography variant="h5" sx={{ fontSize: 22 }}>Sign in</Typography>
            <Typography sx={{ color: 'text.secondary', mt: 0.5 }}>Web application firewall console</Typography>
          </Box>
          {err && <Alert severity="error">{err}</Alert>}
          {!needTotp ? (
            <>
              <TextField label="Username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" size="medium" autoFocus />
              <TextField label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" size="medium" />
            </>
          ) : (
            <TextField
              label="Two-factor code"
              value={totp}
              onChange={(e) => setTotp(e.target.value.replace(/\D/g, '').slice(0, 6))}
              inputProps={{ inputMode: 'numeric', autoComplete: 'one-time-code' }}
              helperText="Enter the 6-digit code from your authenticator app"
              size="medium"
              autoFocus
            />
          )}
          <Button type="submit" variant="contained" size="large" disabled={busy || !password}>
            {busy ? 'Signing in…' : 'Sign in'}
          </Button>
          <Typography sx={{ fontSize: 12, color: 'text.secondary' }}>
            Forgot the password? On the server run <code>docker exec hiwaf-manager manager -config /data/manager.json -resetadmin</code>
          </Typography>
        </Stack>
      </Paper>
    </Box>
  )
}
