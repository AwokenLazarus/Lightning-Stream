import { sdk } from '../sdk'
import { agentConnection } from './agentConnection'
import { filesFolder } from './filesFolder'
import { nodeConfig } from './nodeConfig'
import { resetUiPassword } from './resetUiPassword'
import { rotateAgentToken } from './rotateAgentToken'
import { showSetupCode } from './showSetupCode'

export const actions = sdk.Actions.of()
  .addAction(nodeConfig)
  .addAction(showSetupCode)
  .addAction(agentConnection)
  .addAction(rotateAgentToken)
  .addAction(resetUiPassword)
  .addAction(filesFolder)
