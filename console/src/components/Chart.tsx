import { useEffect, useRef } from 'react'
import * as echarts from 'echarts/core'
import { LineChart, BarChart, MapChart, PieChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, VisualMapComponent, GeoComponent, LegendComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { feature } from 'topojson-client'
import world from 'world-atlas/countries-110m.json'
import type { Topology, GeometryCollection } from 'topojson-specification'
import { numericToAlpha2 } from '../util'

echarts.use([LineChart, BarChart, MapChart, PieChart, GridComponent, TooltipComponent, VisualMapComponent,
  GeoComponent, LegendComponent, CanvasRenderer])

// Register the world map once; each feature is named by its ISO alpha-2 code.
let mapReady = false
function ensureWorld() {
  if (mapReady) return
  const topo = world as unknown as Topology<{ countries: GeometryCollection }>
  const fc = feature(topo, topo.objects.countries) as unknown as GeoJSON.FeatureCollection
  for (const f of fc.features) {
    const code = numericToAlpha2(String(f.id ?? '').padStart(3, '0'))
    f.properties = { ...(f.properties ?? {}), name: code ?? String(f.id) }
  }
  echarts.registerMap('world', fc as any)
  mapReady = true
}

export default function Chart({ option, height = 220, map }: { option: any; height?: number | string; map?: boolean }) {
  const ref = useRef<HTMLDivElement>(null)
  const inst = useRef<echarts.ECharts | null>(null)

  useEffect(() => {
    if (!ref.current) return
    if (map) ensureWorld()
    const c = echarts.init(ref.current)
    inst.current = c
    const ro = new ResizeObserver(() => c.resize())
    ro.observe(ref.current)
    return () => {
      ro.disconnect()
      c.dispose()
      inst.current = null
    }
  }, [map])

  useEffect(() => {
    inst.current?.setOption(option, true)
  }, [option])

  return <div ref={ref} style={{ width: '100%', height }} />
}
