import countries from 'i18n-iso-countries'
import en from 'i18n-iso-countries/langs/en.json'

countries.registerLocale(en)

export function countryName(code: string): string {
  if (!code) return 'Unknown'
  return countries.getName(code, 'en', { select: 'alias' }) || code
}

export function flag(code: string): string {
  if (!code || code.length !== 2) return ''
  const base = 0x1f1e6
  return String.fromCodePoint(base + code.charCodeAt(0) - 65, base + code.charCodeAt(1) - 65)
}

export function alpha2ToNumeric(code: string): string | undefined {
  return countries.alpha2ToNumeric(code)
}

export function numericToAlpha2(n: string): string | undefined {
  return countries.numericToAlpha2(n)
}

export function fmtNum(n: number | undefined): string {
  if (n === undefined || n === null) return '-'
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(n >= 10_000_000 ? 0 : 1) + 'm'
  if (n >= 10_000) return (n / 1000).toFixed(n >= 100_000 ? 0 : 1) + 'k'
  return n.toLocaleString()
}

export function pct(part: number, whole: number): string {
  if (!whole) return '0%'
  return ((part / whole) * 100).toFixed(2) + '%'
}

const pad = (n: number) => String(n).padStart(2, '0')

export function fmtTime(s: string | undefined): string {
  if (!s) return '-'
  const d = new Date(s)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

export function fmtDuration(fromIso: string, toIso: string): string {
  const ms = new Date(toIso).getTime() - new Date(fromIso).getTime()
  const m = Math.max(0, Math.round(ms / 60000))
  if (m < 60) return `${m} minute${m === 1 ? '' : 's'}`
  const h = Math.round(m / 60)
  if (h < 48) return `${h} hour${h === 1 ? '' : 's'}`
  return `${Math.round(h / 24)} days`
}

export function fmtSeconds(sec: number): string {
  if (sec % 86400 === 0) return `${sec / 86400} d`
  if (sec % 3600 === 0) return `${sec / 3600} h`
  if (sec % 60 === 0) return `${sec / 60} min`
  return `${sec} s`
}

export const categoryLabels: Record<string, string> = {
  sqli: 'SQL Injection',
  xss: 'XSS',
  rce: 'Command Injection',
  lfi: 'Path Traversal',
  rfi: 'Remote File Inclusion',
  php: 'PHP Injection',
  nodejs: 'Node.js Injection',
  java: 'Java / Deserialization',
  session_fixation: 'Session Fixation',
  scanner: 'Scanner',
  protocol: 'Protocol Violation',
  data_leak: 'Data Leakage',
  '': 'Other',
}

export function categoryLabel(c: string): string {
  return categoryLabels[c] ?? c
}

export const eventLabels: Record<string, string> = {
  waf_block: 'WAF block',
  waf_match: 'WAF match',
  rate_limit_ban: 'Rate-limit ban',
  ip_block: 'IP denied',
  geo_block: 'Region denied',
  rule_block: 'Rule denied',
  allowed_by_rule: 'Rule allowed',
  challenge_passed: 'Challenge passed',
  challenge_failed: 'Challenge failed',
  auth_passed: 'Login passed',
  auth_failed: 'Login failed',
}

export const modeLabel: Record<string, string> = { block: 'Defense', detect: 'Audit', off: 'Disabled' }

export function siteLabel(s: { resolved: { name: string; domains: string[] } } | undefined, id: string): string {
  if (!s) return id
  return s.resolved.name || s.resolved.domains.map((d) => (d === '*' ? 'Match All Host' : d)).join(', ')
}
