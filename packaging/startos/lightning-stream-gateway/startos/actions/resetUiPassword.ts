import { rm } from 'node:fs/promises'
import { i18n } from '../i18n'
import { sdk } from '../sdk'

/** Forget the setup page's password hash; on the next start the UI asks for a new setup code (Setup page setup code). */
export const resetUiPassword = sdk.Action.withoutInput(
  'reset-ui-password',
  {
    name: i18n('Reset the setup page password'),
    description: i18n('Forget the setup page password. The service restarts and the UI asks for a new setup code.'),
    warning: i18n('Anyone with the new setup code can choose the password. The gateway, its config and its macaroons are not affected.'),
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  },
  async ({ effects }) => {
    await rm(sdk.volumes.main.subpath('ui/password.scrypt'), { force: true })
    await effects.restart()
    return {
      version: '1',
      title: i18n('Setup page password reset'),
      message: i18n('Run Setup page code once the service is running again.'),
      result: null,
    }
  },
)
