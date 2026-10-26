import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, HashRouter } from 'react-router-dom'
import './styles.css'
import './lib/charts.js'
import { DEMO } from './api'
import { AppProvider } from './context'
import App from './App'

// The demo build is served as static files, so it routes on the hash.
const Router = DEMO ? HashRouter : BrowserRouter

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Router>
      <AppProvider>
        <App />
      </AppProvider>
    </Router>
  </StrictMode>,
)
