import { useEffect, useState } from 'react'
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { Box, CircularProgress } from '@mui/material'
import { api, setUnauthorizedHandler } from './api'
import { useApp } from './context'
import type { Me } from './types'
import Layout from './components/Layout'
import Login from './pages/Login'
import Statistics from './pages/Statistics'
import Applications from './pages/Applications'
import AppDetail from './pages/AppDetail'
import Attacks from './pages/Attacks'
import AllowDeny from './pages/AllowDeny'
import RateLimiting from './pages/RateLimiting'
import WaitingRoom from './pages/WaitingRoom'
import AntiBot from './pages/AntiBot'
import AuthPage from './pages/AuthPage'
import Settings from './pages/Settings'

export default function App() {
  const { me, setMe } = useApp()
  const [checked, setChecked] = useState(false)
  const navigate = useNavigate()
  const loc = useLocation()

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setMe(null)
      navigate('/login', { replace: true, state: { from: window.location.pathname } })
    })
    api.get<Me>('/auth/me')
      .then(setMe)
      .catch(() => setMe(null))
      .finally(() => setChecked(true))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  if (!checked) {
    return (
      <Box sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <CircularProgress />
      </Box>
    )
  }
  if (!me && loc.pathname !== '/login') return <Navigate to="/login" replace state={{ from: loc.pathname }} />

  return (
    <Routes>
      <Route path="/login" element={me ? <Navigate to="/statistics" replace /> : <Login />} />
      <Route element={<Layout />}>
        <Route path="/statistics" element={<Statistics />} />
        <Route path="/applications" element={<Applications />} />
        <Route path="/applications/:id" element={<AppDetail />} />
        <Route path="/attacks" element={<Attacks />} />
        <Route path="/allow-deny" element={<AllowDeny />} />
        <Route path="/http-flood" element={<Navigate to="/http-flood/limits" replace />} />
        <Route path="/http-flood/limits" element={<RateLimiting />} />
        <Route path="/http-flood/waiting-room" element={<WaitingRoom />} />
        <Route path="/anti-bot" element={<AntiBot />} />
        <Route path="/auth" element={<AuthPage />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/statistics" replace />} />
    </Routes>
  )
}
