import { i18n } from './i18n'
import { sdk } from './sdk'
import { PORTS } from './spec'

/**
 * The setup page (for the owner) and the gateway (for buyers: an API). Both are on the LAN only by default.
 * Buyers' wallets pay tickets over https with a publicly trusted certificate only: to sell, add a public domain
 * to the Gateway interface (StartOS issues its certificate) and type that https origin on the setup page.
 */
export const setInterfaces = sdk.setupInterfaces(async ({ effects }) => {
  const receipts = []

  const ui = await sdk.MultiHost.of(effects, 'ui').bindPort(PORTS.ui, { protocol: 'http', preferredExternalPort: 80 })
  receipts.push(
    await ui.export([
      sdk.createInterface(effects, {
        name: i18n('Setup page'),
        id: 'ui',
        description: i18n('Set the service you sell, its price, the address buyers use and the macaroons'),
        type: 'ui',
        masked: false,
        schemeOverride: null,
        username: null,
        path: '',
        query: {},
      }),
    ]),
  )

  const gw = await sdk.MultiHost.of(effects, 'gateway').bindPort(PORTS.gateway, {
    protocol: 'http',
    preferredExternalPort: PORTS.gateway,
    addSsl: { alpn: null, auth: null, preferredExternalPort: 443, addXForwardedHeaders: true },
  })
  receipts.push(
    await gw.export([
      sdk.createInterface(effects, {
        name: i18n('Gateway for buyers'),
        id: 'gateway',
        description: i18n('Where buyers reach the service you sell; add a public domain to it to sell outside your LAN'),
        type: 'api',
        masked: false,
        schemeOverride: null,
        username: null,
        path: '',
        query: {},
      }),
    ]),
  )

  return receipts
})
