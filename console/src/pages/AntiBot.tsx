import { Box } from '@mui/material'
import EventLog from '../components/EventLog'
import SiteFeatureTable, { OnOff } from '../components/SiteFeatureTable'
import { ChallengeForm } from '../components/forms'
import { PageTitle } from '../components/common'

export default function AntiBot() {
  return (
    <Box>
      <PageTitle title="Anti-Bot" sub="A JavaScript proof-of-work challenge lets browsers through and stops scripts and crawlers." />
      <EventLog
        types={['challenge_passed', 'challenge_failed']}
        defaultView="settings"
        extraViews={[{
          key: 'settings', label: 'Settings', render: () => (
            <SiteFeatureTable
              editTitle="Bot protection"
              columns={[
                { label: 'Bot challenge', render: (s) => <OnOff on={s.resolved.bot_challenge.enabled} /> },
                { label: 'Difficulty', render: (s) => (s.resolved.bot_challenge.enabled ? s.resolved.bot_challenge.difficulty : '-') },
              ]}
              renderForm={(s, done) => <ChallengeForm site={s} onSaved={done} />}
            />
          ),
        }]}
      />
    </Box>
  )
}
