import { useCallback, useEffect, useState } from 'react'
import { Box, Typography } from '@mui/material'
import { api } from '../api'
import SiteFeatureTable, { OnOff } from '../components/SiteFeatureTable'
import { WaitRoomForm } from '../components/forms'
import { PageTitle, useInterval } from '../components/common'

export default function WaitingRoom() {
  const [live, setLive] = useState<Record<string, { active: number; waiting: number }>>({})
  const load = useCallback(() => api.get<typeof live>('/waitroom').then(setLive).catch(() => {}), [])
  useEffect(() => { load() }, [load])
  useInterval(load, 5000, true)
  return (
    <Box>
      <PageTitle title="Waiting Room" sub="Queue visitors when an application is busy, instead of letting it fall over." />
      <SiteFeatureTable
        editTitle="Waiting room"
        columns={[
          { label: 'Status', render: (s) => <OnOff on={s.resolved.waiting_room.enabled} /> },
          { label: 'Max active', render: (s) => (s.resolved.waiting_room.enabled ? s.resolved.waiting_room.max_active : '-') },
          { label: 'Active now', render: (s) => <Typography sx={{ fontWeight: 600 }}>{live[s.id]?.active ?? 0}</Typography> },
          { label: 'Waiting now', render: (s) => <Typography sx={{ fontWeight: 600, color: live[s.id]?.waiting ? 'warning.main' : 'text.primary' }}>{live[s.id]?.waiting ?? 0}</Typography> },
        ]}
        renderForm={(s, done) => <WaitRoomForm site={s} onSaved={done} />}
      />
    </Box>
  )
}
