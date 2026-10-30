import { i18n } from '../i18n'
import { sdk } from '../sdk'
import { storeJson } from '../fileModels/store.json'

const { InputSpec, Value } = sdk

const inputSpec = InputSpec.of({
  source: Value.select({
    name: i18n('Files folder'),
    description: i18n(
      "Where the Files service's folder is. File Browser: you put files in File Browser, then choose the folder on the Sell page; Stream only reads them. This app: a folder in this app's own storage.",
    ),
    default: 'own',
    values: { own: i18n("This app's own folder"), filebrowser: i18n('File Browser') },
  }),
})

export const filesFolder = sdk.Action.withInput(
  'files-folder',
  {
    name: i18n('Files folder'),
    description: i18n('Share your File Browser files with the Files service (read-only), or use the folder in this app'),
    warning: null,
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  },
  inputSpec,
  async () => ({ source: (await storeJson.read((s) => s.filesSource).once()) ?? 'own' }),
  async ({ effects, input }) => {
    await storeJson.merge(effects, { filesSource: input.source === 'filebrowser' ? 'filebrowser' : 'own' })
  },
)
