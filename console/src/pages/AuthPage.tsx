import { Box } from '@mui/material'
import EventLog from '../components/EventLog'
import SiteFeatureTable, { OnOff } from '../components/SiteFeatureTable'
import { AuthForm } from '../components/forms'
import { PageTitle } from '../components/common'

export default function AuthPage() {
  return (
    <Box>
      <PageTitle title="Auth" sub="Put a login page in front of an application; only listed accounts get through." />
      <EventLog
        types={['auth_passed', 'auth_failed']}
        defaultView="settings"
        extraViews={[{
          key: 'settings', label: 'Settings', render: () => (
            <SiteFeatureTable
              editTitle="Authentication challenge"
              columns={[
                { label: 'Authentication', render: (s) => <OnOff on={s.resolved.auth.enabled} /> },
                { label: 'Users', render: (s) => s.resolved.auth.users.map((u) => u.username).join(', ') || '-' },
              ]}
              renderForm={(s, done) => <AuthForm site={s} onSaved={done} />}
            />
          ),
        }]}
      />
    </Box>
  )
}
