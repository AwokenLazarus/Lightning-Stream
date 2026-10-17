import { i18n } from '../i18n'
import { sdk } from '../sdk'
import { showSetupCode } from '../actions/showSetupCode'

/** After install: the setup page asks for a setup code before the owner chooses its password. */
export const taskSetupCode = sdk.setupOnInit(async (effects, kind) => {
  if (kind !== 'install') return
  await sdk.action.createOwnTask(effects, showSetupCode, 'important', {
    reason: i18n('Once the service runs, get the setup code and choose the setup page password'),
  })
})
