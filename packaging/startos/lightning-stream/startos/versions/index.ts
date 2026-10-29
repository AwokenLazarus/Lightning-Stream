import { VersionGraph } from '@start9labs/start-sdk'
import { current } from './current'
import { v0_1_14 } from './v0_1_14'
import { v0_1_15 } from './v0_1_15'
import { v0_1_16 } from './v0_1_16'
import { v0_1_17 } from './v0_1_17'

export const versionGraph = VersionGraph.of({
  current,
  other: [v0_1_17, v0_1_16, v0_1_15, v0_1_14],
})
