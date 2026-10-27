// English only for now; the other locales fall back to it (translations are a store-submission step).
export const short = {
  en_US: 'Sell a service per request, per MiB or per second, paid with stream tickets',
}

export const long = {
  en_US:
    "Put a price on an HTTP service you run and let buyers' agents pay for it piece by piece over XBT Lightning. Each buyer locks a few small tickets (hold invoices on your Lightning Fork node) and releases one secret per paid piece; the gateway passes each paid request to your service and signs a receipt. On the setup page you set the service, the https address buyers use, one price, and two macaroons you make in Lightning Fork's dashboard with exactly invoices:read invoices:write and info:read. The package reads only the node's certificate and never holds an admin macaroon; its macaroons cannot pay. Buyers reach the gateway over https only: add a public domain to its interface. On mainnet this software takes real payments; it is tested on mainnet with small amounts only. Needs Lightning Fork.",
}
