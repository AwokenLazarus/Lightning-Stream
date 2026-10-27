import { VersionGraph } from '@start9labs/start-sdk'
import { current } from './current'
import { v0_1_14 } from './v0_1_14'

export const versionGraph = VersionGraph.of({
  current,
  other: [v0_1_14],
})
