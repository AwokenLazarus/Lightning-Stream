import { rm } from 'node:fs/promises'
import { i18n } from '../i18n'
import { sdk } from '../sdk'

/** A new MCP bearer token: delete it (and the UI's copy); on the restart xbt-init makes a new one. */
export const rotateAgentToken = sdk.Action.withoutInput(
  'rotate-agent-token',
  {
    name: i18n('Rotate the agent token'),
    description: i18n('Replace the MCP bearer token, for example if it leaked. The service restarts.'),
    warning: i18n('Every agent loses access until you give it the new token (Agent connection).'),
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  },
  async ({ effects }) => {
    await rm(sdk.volumes.main.subpath('mcp/secrets/mcp-http-token'), { force: true })
    await rm(sdk.volumes.main.subpath('ui/secrets/mcp-http-token'), { force: true })
    await effects.restart()
    return {
      version: '1',
      title: i18n('Agent token rotated'),
      message: i18n('Run Agent connection once the service is running again, and give your agents the new token.'),
      result: null,
    }
  },
)
