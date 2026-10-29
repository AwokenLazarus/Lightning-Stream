# AI for your programs: the inference endpoint

Lightning Stream gives programs on your own network an address that works like OpenAI's API. Open
WebUI, coding agents and your own scripts use AI models from the sellers you allowed through it,
and each answer is paid by the token as it arrives, within the spending rules you signed.

```
http://<your box>:33540/v1      (Umbrel and StartOS; on Linux, 127.0.0.1 unless you open it to the LAN)
```

## Set it up

1. **Add an AI seller** on Services → Sellers, and press **Allow this seller to be paid**. The
   spending rules page opens with that seller added; sign the change.
2. **Services → AI.** The page shows your AI address and the sellers of AI on your list.
3. **Make a key** for each program, with a limit in sats (and, under Advanced, one per day). The
   key is shown once: copy it into the program now. Nobody can show it again.
4. In the program's settings, put the address where it asks for the OpenAI **base URL** (or "API
   base"), and the key where it asks for the **API key**. Pick a model from the list it shows.

Open WebUI, for example: Settings → Connections → OpenAI API, URL `http://umbrel.local:33540/v1`,
key `sk-stream-…`.

## What the address serves

| | |
|---|---|
| `GET /v1/models` | the models your allowed sellers offer. Each model is listed once by its name (any seller), and once as `seller/model` (that seller only) |
| `POST /v1/chat/completions` | a chat answer, streamed (`"stream": true`) or whole |
| `POST /v1/completions` | a plain completion |
| `POST /v1/embeddings` | embeddings, from a seller that offers them |

Errors come in OpenAI's shape (`{"error": {"message", "type", "code"}}`), so programs show them as
they would OpenAI's:

| Status | `code` | Meaning |
|---|---|---|
| 401 | `invalid_api_key` | no key, an unknown one, or a revoked one |
| 402 | `limit_reached` | the key has reached its limit; raise it on the AI page |
| 404 | `model_not_found` | no seller you allowed offers that model, or each one is resting after failures |
| 502 | `upstream_failed` | no seller could answer |

A seller's own refusal of a request (a 4xx such as a `max_tokens` it does not allow) comes back as
the seller sent it.

## Which seller answers

A request goes to one seller at a time:

1. **Preferred sellers first.** Mark them on the AI page.
2. **Then the cheapest.** The cost is what the request may cost at most: its input, and its
   `max_tokens` of output, at each seller's price.
3. **A faster seller wins a near-tie.** Within 20% on price, the seller with the shorter median
   time to the first word over its recent answers goes first.

**Blocked sellers** are never asked. A seller that fails **three times in a row** rests for five
minutes, then gets one request to try again.

**When a seller fails, the request moves to the next one**, at most twice, but **only if no byte of
its answer has arrived**: the wallet would not pay it, the seller answered 5xx, 402, 429 or 408, or it
sent nothing within 20 seconds. Once an answer has begun it is never moved, so one answer is never
paid for twice. If a seller stops mid-answer, your program gets what arrived, paid for exactly that,
and a streamed answer ends with an error event (`"code": "answer_cut"`). Whether to ask again is the
program's choice.

## What you pay

Each request is one purchase through the signer, like any other buy in the app:
- the seller must be allowed, and your spending rules apply (caps, the per-seller cap, approval
  above your threshold);
- the seller meters the answer by the token and signs a receipt;
- the key is charged what the receipt says, exactly, when the answer ends;
- a key that cannot cover what a request may cost at most is refused before anything is paid.

**Tickets.** A seller is paid with prepaid tickets, as for films and other services: what a
ticket bought and was not used stays with that seller, as credit for your next request there, and
is not refunded. The AI page shows what each key has spent.

## Keys and privacy

- A key is 128 random bits after `sk-stream-`. Only its SHA-256 is kept, so a copy of the files
  does not give your keys away, and it is never written to a log.
- Revoking takes effect at once.
- The address is for programs, not web pages: it sends no CORS headers, and a request from a page
  in a browser (an `Origin`, or a cross-site `Sec-Fetch-Site`) is refused. A web chat that calls the
  API from your browser instead of its server does not work with it.
- Your prompts go to the seller you are paying, as they would to any AI service. The seller sees
  them; the box sees them pass; nobody else in between does (sellers use https).

## On each platform

| | Address | Settings |
|---|---|---|
| Umbrel | `http://<your Umbrel's name>:33540/v1` | open on the LAN, every request needs a key |
| StartOS | the **AI address for programs** interface | open on the LAN, every request needs a key |
| Linux | `http://127.0.0.1:33540/v1` | `LS_AI_BIND=0.0.0.0:33540` in `.env` opens it to the LAN; `LS_AI_ADDRESS` is the address the AI page shows |

The endpoint's files are in `run/ai/` of the data dir: the credential store (AI keys and local
links, `credentials.json`), the sellers the AI page writes (`sellers.json`) and the sellers' health
(`state.json`). See docs/CONTAINER.md.

## For sellers of AI

Any OpenAI-compatible server (llama.cpp's server, vLLM, Ollama) sells through a Stream gateway route
priced by the token. Programs on buyers' boxes find it through your listing (kind `ai`) and ask its
`/v1/models`, which a token-priced route answers for free. A distributed model, such as one of
xbt-compute's swarms, sells the same way: put a token-priced route in front of the swarm's
`/v1/chat/completions` and list it.

## Settings (the connector)

| Variable | Meaning |
|---|---|
| `LS_AI_LISTEN` | the endpoint's address; unset: no endpoint |
| `LS_CREDENTIALS` | the credential store (AI keys and local links) |
| `LS_AI_SELLERS` | the sellers file the AI page writes |
| `LS_AI_STATE` | the sellers' health, written by the endpoint |
| `LS_AI_HOSTS` | host names it answers to, comma-separated (a DNS rebinding of the box's address is refused); unset: any |
| `LS_AI_FIRST_BYTE_S` | how long a seller has for the first byte of its answer before the next is tried (default 20) |

The AI page's settings are `XBT_UI_AI_ENDPOINT` (the address it shows), `XBT_UI_AI_SELLERS`,
`XBT_UI_CREDENTIALS` and `XBT_UI_AI_STATE` (docs in `crates/xbt-wallet-ui/src/config.rs`).
