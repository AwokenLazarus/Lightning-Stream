// English only for now; the other locales fall back to it (translations are a store-submission step).
export const short = {
  en_US: 'A spending-limited XBT wallet for your AI agents, with a policy you sign',
}

export const long = {
  en_US:
    "Your AI agents reach this wallet through its MCP server. They can only pay what your policy allows, within its budgets; anything above your threshold waits for your approval, signed with a key that stays in your browser. The wallet pays services over XBT Lightning with stream tickets, through your Lightning Fork node: on the web UI's Lightning page, paste a macaroon you make in Lightning Fork's dashboard with exactly info:read, offchain:read, offchain:write and onchain:read. The package reads only the node's certificate and never holds an admin macaroon. The keys stay in the signer, sealed on this server; an anchor witness keeps a tamper record of every signature. On mainnet this software moves real funds and has run on regtest only. Needs Lightning Fork and an XBT (BLAKE2b) node.",
}
