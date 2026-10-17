import { sdk } from '../sdk'
import { resetUiPassword } from './resetUiPassword'
import { showSetupCode } from './showSetupCode'

export const actions = sdk.Actions.of().addAction(showSetupCode).addAction(resetUiPassword)
