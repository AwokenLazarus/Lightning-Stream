# For an app on this box that uses this wallet, or that puts its own TLS proxy in front of the gateway.
# The bearer token is not exported: the owner copies it from the UI's Agents page.
# The host ports (33511 for agents, 8483 for the sell page) are for the LAN. On the box network the
# service ports below are the ones to use. These names are not the standalone gateway app's.
export APP_LIGHTNING_STREAM_APP_MCP_HOST="lazarus-lightning-stream_mcp_1"
export APP_LIGHTNING_STREAM_APP_MCP_PORT="33510"
export APP_LIGHTNING_STREAM_APP_MCP_PATH="/mcp"
export APP_LIGHTNING_STREAM_APP_GATEWAY_HOST="lazarus-lightning-stream_gateway_1"
export APP_LIGHTNING_STREAM_APP_GATEWAY_PORT="8402"
