import { i18n } from './i18n'
import { sdk } from './sdk'
import { PORTS } from './spec'

/**
 * The web UI (for the owner), the MCP server (for agents: an API with a bearer token), the AI address
 * (for programs on the LAN, each with a key), the gateway (for buyers), and hashrate's two plain TCP ports: miners on the LAN, and the link hashtakers' apps reach.
 * StartOS offers each on the LAN; the owner adds a public domain to the Gateway (and a port forward or a
 * tunnel for the link) to sell outside the LAN.
 */
export const setInterfaces = sdk.setupInterfaces(async ({ effects }) => {
  const receipts = []

  const ui = await sdk.MultiHost.of(effects, 'ui').bindPort(PORTS.ui, { protocol: 'http', preferredExternalPort: 80 })
  receipts.push(
    await ui.export([
      sdk.createInterface(effects, {
        name: i18n('Web interface'),
        id: 'ui',
        description: i18n('Buy and sell services, set your spending rules, approve payments, and rent or rent out hashrate'),
        type: 'ui',
        masked: false,
        schemeOverride: null,
        username: null,
        path: '',
        query: {},
      }),
    ]),
  )

  const mcp = await sdk.MultiHost.of(effects, 'mcp').bindPort(PORTS.mcp, { protocol: 'http', preferredExternalPort: PORTS.mcp })
  receipts.push(
    await mcp.export([
      sdk.createInterface(effects, {
        name: i18n('MCP server for agents'),
        id: 'mcp',
        description: i18n('Agents connect here (path /mcp) with the bearer token from the Agent connection action'),
        type: 'api',
        masked: true,
        schemeOverride: null,
        username: null,
        path: '/mcp',
        query: {},
      }),
    ]),
  )

  // the AI endpoint (the connector): programs on the LAN, each with a key the owner makes on the AI page
  const ai = await sdk.MultiHost.of(effects, 'ai').bindPort(PORTS.ai, { protocol: 'http', preferredExternalPort: PORTS.ai })
  receipts.push(
    await ai.export([
      sdk.createInterface(effects, {
        name: i18n('AI address for programs'),
        id: 'ai',
        description: i18n('Programs on your network that speak the OpenAI API use AI sellers here, each with a key from the AI page'),
        type: 'api',
        masked: false,
        schemeOverride: null,
        username: null,
        path: '/v1',
        query: {},
      }),
    ]),
  )

  // The gateway speaks HTTP/1.1 only. With no ALPN named, the OS's TLS proxy offers h2 and a client that takes
  // it gets its connection closed, so name http/1.1, as the SDK's default for 'http' does.
  const gw = await sdk.MultiHost.of(effects, 'gateway').bindPort(PORTS.gateway, {
    protocol: 'http',
    preferredExternalPort: PORTS.gateway,
    addSsl: { alpn: { specified: ['http/1.1'] }, auth: null, preferredExternalPort: 443, addXForwardedHeaders: true },
  })
  receipts.push(
    await gw.export([
      sdk.createInterface(effects, {
        name: i18n('Gateway for buyers'),
        id: 'gateway',
        description: i18n('Where buyers reach what you sell; add a public domain to it to sell outside your LAN'),
        type: 'api',
        masked: false,
        schemeOverride: null,
        username: null,
        path: '',
        query: {},
      }),
    ]),
  )

  // hashrate: plain TCP (Stratum from the miners; the link is encrypted end to end, so it needs no TLS)
  const tcp = (port: number) => ({ protocol: null, preferredExternalPort: port, addSsl: null, secure: { ssl: false } })
  const miners = await sdk.MultiHost.of(effects, 'miners').bindPort(PORTS.miners, tcp(PORTS.miners))
  receipts.push(
    await miners.export([
      sdk.createInterface(effects, {
        name: i18n('Miners'),
        id: 'miners',
        description: i18n('Point the miners you rent out at this address (Stratum). Keep it on your LAN'),
        type: 'api',
        masked: false,
        schemeOverride: { ssl: null, noSsl: 'stratum+tcp' },
        username: null,
        path: '',
        query: {},
      }),
    ]),
  )
  const link = await sdk.MultiHost.of(effects, 'link').bindPort(PORTS.link, tcp(PORTS.link))
  receipts.push(
    await link.export([
      sdk.createInterface(effects, {
        name: i18n('Hashrate link'),
        id: 'link',
        description: i18n("Hashtakers' apps connect here; a port forward or a tunnel makes it reachable from outside your LAN"),
        type: 'p2p',
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
