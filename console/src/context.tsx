import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { Alert, Snackbar } from '@mui/material'
import { api, errText } from './api'
import type { Me, Protection, SiteView, SystemInfo } from './types'

interface Toast {
  msg: string
  severity: 'success' | 'error' | 'info' | 'warning'
  key: number
}

interface AppState {
  me: Me | null
  setMe: (m: Me | null) => void
  sites: SiteView[]
  sitesLoaded: boolean
  siteById: Record<string, SiteView>
  reloadSites: () => Promise<void>
  protections: Protection[]
  system: SystemInfo | null
  notify: (msg: string, severity?: Toast['severity']) => void
  notifyError: (e: unknown) => void
}

const Ctx = createContext<AppState | null>(null)

export function AppProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null)
  const [sites, setSites] = useState<SiteView[]>([])
  const [sitesLoaded, setSitesLoaded] = useState(false)
  const [protections, setProtections] = useState<Protection[]>([])
  const [system, setSystem] = useState<SystemInfo | null>(null)
  const [toast, setToast] = useState<Toast | null>(null)

  const notify = useCallback((msg: string, severity: Toast['severity'] = 'success') => {
    setToast({ msg, severity, key: Date.now() })
  }, [])
  const notifyError = useCallback((e: unknown) => notify(errText(e), 'error'), [notify])

  const reloadSites = useCallback(async () => {
    try {
      setSites(await api.get<SiteView[]>('/sites'))
      setSitesLoaded(true)
    } catch (e) {
      notifyError(e)
    }
  }, [notifyError])

  useEffect(() => {
    if (!me) return
    reloadSites()
    api.get<Protection[]>('/protections').then(setProtections).catch(notifyError)
    api.get<SystemInfo>('/system').then(setSystem).catch(() => {})
  }, [me, reloadSites, notifyError])

  const siteById = useMemo(() => Object.fromEntries(sites.map((s) => [s.id, s])), [sites])

  return (
    <Ctx.Provider
      value={{ me, setMe, sites, sitesLoaded, siteById, reloadSites, protections, system, notify, notifyError }}
    >
      {children}
      <Snackbar
        key={toast?.key}
        open={!!toast}
        autoHideDuration={toast?.severity === 'error' ? 8000 : 3000}
        onClose={() => setToast(null)}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
      >
        <Alert severity={toast?.severity} variant="filled" onClose={() => setToast(null)} sx={{ maxWidth: 640 }}>
          {toast?.msg}
        </Alert>
      </Snackbar>
    </Ctx.Provider>
  )
}

export function useApp(): AppState {
  const v = useContext(Ctx)
  if (!v) throw new Error('useApp outside AppProvider')
  return v
}
