import { useCallback, useEffect, useMemo, useState } from 'react'
import { Box, Grid2 as Grid, MenuItem, Stack, Tab, Tabs, TextField, ToggleButton, ToggleButtonGroup, Typography } from '@mui/material'
import { api, qs } from '../api'
import { useApp } from '../context'
import type { Overview } from '../types'
import Chart from '../components/Chart'
import { BarList, Section, SiteSelect, StatTile, TileGroup, siteName, useInterval } from '../components/common'
import { categoryLabel, countryName, flag, fmtNum, pct } from '../util'

const ranges = [
  { v: '24h', label: '24 hours' },
  { v: '7d', label: '7 days' },
  { v: '30d', label: '30 days' },
]

function timeLabel(iso: string, stepSec: number) {
  const d = new Date(iso)
  const p = (n: number) => String(n).padStart(2, '0')
  return stepSec >= 86400 ? `${d.getMonth() + 1}/${d.getDate()}` : stepSec >= 3600 && stepSec > 3600
    ? `${d.getMonth() + 1}/${d.getDate()} ${p(d.getHours())}:00` : `${p(d.getHours())}:${p(d.getMinutes())}`
}

function lineOption(points: { t: string; v: number }[], stepSec: number, color: string, name: string) {
  return {
    grid: { left: 40, right: 12, top: 16, bottom: 24 },
    tooltip: { trigger: 'axis' },
    xAxis: { type: 'category', data: points.map((p) => timeLabel(p.t, stepSec)), boundaryGap: false, axisLabel: { color: '#8a99a5', fontSize: 11 }, axisLine: { lineStyle: { color: '#e3e8ec' } } },
    yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: '#f0f3f5' } }, axisLabel: { color: '#8a99a5', fontSize: 11 } },
    series: [{
      name, type: 'line', smooth: true, showSymbol: false, data: points.map((p) => p.v),
      lineStyle: { width: 2.5, color },
      areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: color + '55' }, { offset: 1, color: color + '05' }] } },
    }],
  }
}

export default function Statistics() {
  const { siteById, notifyError } = useApp()
  const [site, setSite] = useState('')
  const [range, setRange] = useState('24h')
  const [data, setData] = useState<Overview | null>(null)
  const [geoMode, setGeoMode] = useState<'requests' | 'blocked'>('requests')
  const [clientTab, setClientTab] = useState(0)

  const load = useCallback(() => {
    api.get<Overview>('/stats/overview' + qs({ site, range })).then(setData).catch(notifyError)
  }, [site, range, notifyError])
  useEffect(() => { load() }, [load])
  useInterval(load, 30000, true)

  const o = data
  const qpsOption = useMemo(() => {
    const pts = (o?.qps ?? []).map((p) => ({ t: p.t, v: +(p.requests / 10).toFixed(1) }))
    return {
      grid: { left: 6, right: 6, top: 6, bottom: 6 },
      tooltip: { trigger: 'axis', valueFormatter: (v: number) => `${v} req/s` },
      xAxis: { type: 'category', show: false, data: pts.map((p) => timeLabel(p.t, 10)) },
      yAxis: { type: 'value', show: false },
      series: [{ type: 'bar', data: pts.map((p) => p.v), itemStyle: { color: '#0fa5a0', borderRadius: [2, 2, 0, 0] }, barWidth: '60%' }],
    }
  }, [o])
  const reqOption = useMemo(() => lineOption((o?.series ?? []).map((p) => ({ t: p.t, v: p.requests })), o?.step_sec ?? 60, '#3b6fd6', 'Requests'), [o])
  const blkOption = useMemo(() => lineOption((o?.series ?? []).map((p) => ({ t: p.t, v: p.blocked })), o?.step_sec ?? 60, '#e5484d', 'Blocked'), [o])
  const geoOption = useMemo(() => {
    const items = (o?.countries ?? []).filter((c) => c.key)
    const val = (c: { count: number; blocked?: number }) => (geoMode === 'requests' ? c.count : c.blocked ?? 0)
    const max = Math.max(1, ...items.map(val))
    return {
      tooltip: {
        trigger: 'item',
        formatter: (p: any) => `${flag(p.name)} ${countryName(p.name)}<br/>${geoMode === 'requests' ? 'Requests' : 'Blocked'}: ${isNaN(p.value) ? 0 : p.value}`,
      },
      visualMap: { show: false, min: 0, max, inRange: { color: geoMode === 'requests' ? ['#cdeeed', '#0fa5a0'] : ['#fbd5d6', '#e5484d'] } },
      series: [{
        type: 'map', map: 'world', roam: false, top: 10, bottom: 10, left: 0, right: 0,
        itemStyle: { areaColor: '#e9eff2', borderColor: '#fff', borderWidth: 0.5 },
        emphasis: { label: { show: false }, itemStyle: { areaColor: '#f5b041' } },
        data: items.map((c) => ({ name: c.key, value: val(c) })),
      }],
    }
  }, [o, geoMode])

  const req = o?.requests ?? 0
  return (
    <Stack spacing={2}>
      <Stack direction="row" alignItems="center" spacing={2}>
        <Tabs value={0} sx={{ flex: 1, minHeight: 36 }}>
          <Tab label="Traffic analysis" sx={{ minHeight: 36 }} />
        </Tabs>
        <SiteSelect value={site} onChange={setSite} />
        <TextField select label="Range" value={range} onChange={(e) => setRange(e.target.value)} sx={{ width: 130 }}>
          {ranges.map((r) => <MenuItem key={r.v} value={r.v}>{r.label}</MenuItem>)}
        </TextField>
      </Stack>

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, lg: 9 }}>
          <Stack spacing={2}>
            <Grid container spacing={2}>
              <Grid size={{ xs: 12, md: 8 }}>
                <TileGroup>
                  <StatTile label="Requests" value={fmtNum(req)} />
                  <StatTile label="Views (PV)" value={fmtNum(o?.pv)} hint="HTML responses below 400" />
                  <StatTile label="Visitors (UV)" value={fmtNum(o?.uv)} hint="Distinct IP + user agent" />
                  <StatTile label="Unique IP" value={fmtNum(o?.unique_ips)} />
                </TileGroup>
              </Grid>
              <Grid size={{ xs: 12, md: 4 }}>
                <TileGroup>
                  <StatTile label="Blocked" value={fmtNum(o?.blocked)} tone={o?.blocked ? 'danger' : undefined} />
                  <StatTile label="IP Addr" value={fmtNum(o?.blocked_ips)} hint="Distinct blocked IPs" />
                </TileGroup>
              </Grid>
              <Grid size={{ xs: 12, md: 4 }}>
                <TileGroup>
                  <StatTile label="4xx Errors" value={fmtNum(o?.err_4xx)} tone="warn" />
                  <StatTile label="Error Rate" value={pct(o?.err_4xx ?? 0, req)} />
                </TileGroup>
              </Grid>
              <Grid size={{ xs: 12, md: 4 }}>
                <TileGroup>
                  <StatTile label="4xx Blocked" value={fmtNum(o?.blocked_4xx)} />
                  <StatTile label="Blocked Rate" value={pct(o?.blocked ?? 0, req)} />
                </TileGroup>
              </Grid>
              <Grid size={{ xs: 12, md: 4 }}>
                <TileGroup>
                  <StatTile label="5xx Errors" value={fmtNum(o?.err_5xx)} tone="danger" />
                  <StatTile label="Error Rate" value={pct(o?.err_5xx ?? 0, req)} />
                </TileGroup>
              </Grid>
            </Grid>

            <Section
              title="Geo Location"
              actions={
                <ToggleButtonGroup size="small" exclusive value={geoMode} onChange={(_, v) => v && setGeoMode(v)}>
                  <ToggleButton value="requests" sx={{ px: 1.5, py: 0.3 }}>Requests</ToggleButton>
                  <ToggleButton value="blocked" sx={{ px: 1.5, py: 0.3 }}>Blocked</ToggleButton>
                </ToggleButtonGroup>
              }
            >
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, md: 8 }}>
                  <Chart option={geoOption} height={330} map />
                </Grid>
                <Grid size={{ xs: 12, md: 4 }}>
                  <Box sx={{ bgcolor: '#f7f9fa', borderRadius: 2, p: 2, height: '100%' }}>
                    <BarList
                      items={(o?.countries ?? [])
                        .map((c) => ({ key: c.key, count: geoMode === 'requests' ? c.count : c.blocked ?? 0 }))
                        .filter((c) => c.count > 0)
                        .sort((a, b) => b.count - a.count)
                        .slice(0, 8)}
                      color={geoMode === 'requests' ? '#0fa5a0' : '#e5484d'}
                      render={(k) => (k ? `${flag(k)} ${countryName(k)}` : 'Unknown')}
                    />
                  </Box>
                </Grid>
              </Grid>
            </Section>

            <Grid container spacing={2}>
              <Grid size={{ xs: 12, md: 6 }}>
                <Section title="Requests"><Chart option={reqOption} /></Section>
              </Grid>
              <Grid size={{ xs: 12, md: 6 }}>
                <Section title="Blocked"><Chart option={blkOption} /></Section>
              </Grid>
            </Grid>

            <Grid container spacing={2}>
              <Grid size={{ xs: 12, md: 4 }}>
                <Section title="Popular Application">
                  <BarList items={o?.sites ?? []} render={(k) => (siteById[k] ? siteName(siteById[k]) : k)} />
                </Section>
              </Grid>
              <Grid size={{ xs: 12, md: 4 }}>
                <Section title="Popular Page">
                  <BarList items={o?.pages ?? []} color="#3b6fd6" />
                </Section>
              </Grid>
              <Grid size={{ xs: 12, md: 4 }}>
                <Section title="Top Client IP">
                  <BarList items={o?.ips ?? []} color="#8b5cf6" render={(k) => <span style={{ fontFamily: 'ui-monospace,Consolas,monospace' }}>{k}</span>} />
                </Section>
              </Grid>
            </Grid>
          </Stack>
        </Grid>

        <Grid size={{ xs: 12, lg: 3 }}>
          <Stack spacing={2}>
            <Section title={<>Query Per Second <Typography component="span" sx={{ color: 'text.secondary', fontSize: 12, ml: 1 }}>last 10 min</Typography></>}>
              <Typography sx={{ fontSize: 26, fontWeight: 700 }}>
                {o?.qps?.length ? (o.qps[o.qps.length - 1].requests / 10).toFixed(1) : '0'}
                <Typography component="span" sx={{ fontSize: 13, color: 'text.secondary', ml: 0.5 }}>req/s</Typography>
              </Typography>
              <Chart option={qpsOption} height={90} />
            </Section>
            <Section title="Attack Types">
              <BarList items={o?.attack_types ?? []} color="#e5484d" render={categoryLabel} empty="No attacks" />
            </Section>
            <Section title="User Clients">
              <Tabs value={clientTab} onChange={(_, v) => setClientTab(v)} sx={{ mb: 1, minHeight: 32 }}>
                <Tab label="OS" sx={{ minHeight: 32, py: 0 }} />
                <Tab label="Browser" sx={{ minHeight: 32, py: 0 }} />
              </Tabs>
              <BarList items={(clientTab === 0 ? o?.os : o?.browsers) ?? []} color="#3b6fd6" />
            </Section>
            <Section title="Response Status">
              <BarList items={o?.status ?? []} color="#f59e0b" />
            </Section>
            <Section title="Referring Sites">
              <BarList items={o?.referrers ?? []} color="#8b5cf6" />
            </Section>
          </Stack>
        </Grid>
      </Grid>
    </Stack>
  )
}
