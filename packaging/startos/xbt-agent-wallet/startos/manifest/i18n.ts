// English only for now; the other locales fall back to it (translations are a store-submission step).
export const short = {
  en_US: 'A spending-limited XBT wallet for your AI agents, with a policy you sign',
}

export const long = {
  en_US:
    "Your AI agents reach this wallet through its MCP server. They can only pay what your policy allows, within its budgets; anything above your threshold waits for your approval, signed with a key that stays in your browser. The wallet pays services over XBT Lightning (stream tickets); this package does not connect it to a Lightning node yet, and until it does no service is paid. The keys stay in the signer, sealed on this server; an anchor witness keeps a tamper record of every signature. Needs an XBT (BLAKE2b) node.",
}
