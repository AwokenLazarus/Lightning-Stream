# Compute alpha: the machine check

Lightning Stream sells services paid as you use them. The compute alpha tests a further idea: many
people lend GPUs and other hardware, and together they run mixture-of-experts AI models too big for
any one of them, paid per token by how much work each machine did.

The first step runs no model and moves no sats. It finds out what testers' machines have and how
well they reach each other, so that we know which models a group could run before asking anyone to
download one.

## What you run

On the machine you would lend, on Linux, outside any container so that it can see the graphics card:

```
stream-compute-check check --collector KEY --region "your region, in your own words"
```

`KEY` comes from whoever runs the test. It shows exactly what it would send, and asks first. It takes
about 5 minutes. To add a disk speed test, add `--disk-test-gib 2 --disk-dir /path/to/your/fast/disk`:
it writes 2 GiB there, reads it back and removes it.

To see the report and send nothing: `stream-compute-check report`.

## What it sends and who sees it

- **To the collector:** CPU architecture and core count, memory, each graphics card's name and memory,
  free disk, the optional disk speed, your region text, and what it measured to other testers. No
  name, host name or address. The collector does not write addresses down.
- **The key is made for the run,** and your next run has another. It is not your Lightning node's key.
- **Other testers:** it measures up to 32 of them, at most 16 MiB each way per peer. Where a direct
  path forms, each machine sees the other's internet address, as with any peer-to-peer link. With
  `--relay-only` they do not; the relay sees both addresses and how much passes, and never the
  content. Direct links, which matter most for this test, then cannot be measured.

Everything the machine reports is its own word. Nothing here is proved.

## What whoever runs the test does

```
stream-compute-check collect --out records.jsonl    # prints the KEY for testers
stream-compute-check plan records.jsonl             # which models this group could run
```

`plan` says, per model, whether the group can form a chain of machines inside the speed and
first-token lines, and if not, what is short. Its numbers are ceilings before compute: they say the
memory is there and the links allow it. Only running the model measures how fast it goes.

## Paying the machines of a split

A seller's box runs a gateway that sells one model by the token, and a Mesh-LLM node that serves it,
split over machines. `stream-compute-check payout` pays each machine's owner for the work it does.

```
stream-compute-check shares --gguf model.gguf --stages 0-7,7-14,14-21,21-28   # what each stage is due
stream-compute-check payout --config payout.json                              # keeps running
```

Each machine's share is its **active parameters** over the model's: what it multiplies per token,
read from the header of the model's GGUF file. Speed does not count, and a mixture-of-experts layer
counts only the experts a token uses. The machine with the last layer also does the output head, a
multiplication by the whole vocabulary, so it is due more: on Qwen3-1.7B in four even stages, 38.6%
against 20.5%. A prompt's tokens mostly do not reach the head, and one set of shares covers prompt
and answer alike, so that machine is paid a little more than its share of prompt work.

```json
{
  "gateway_url": "http://127.0.0.1:8402",
  "mesh_console_url": "http://127.0.0.1:3131",
  "gguf": "model.gguf",
  "signer_sock": "signer.sock",
  "ledger": "payout-ledger.json",
  "report": "payout-report.json",
  "operator_cut_ppm": 100000,
  "own_nodes": ["<a Mesh-LLM node id of your own>"],
  "lenders": {"<a lender's Mesh-LLM node id>": {"name": "a lender", "offer": "lno1..."}},
  "min_payout_sats": 1000
}
```

- A lender gives its Mesh-LLM node id and a BOLT 12 offer of its own node, with no amount. It is paid
  through the owner's wallet, so the owner's policy decides: allow each `ln-offer:<id>`, with a
  budget. A payment the policy refuses stays owed and is asked for again. A payment above the wallet's
  human threshold waits for the owner, so set the threshold above the largest payout you expect.
- A stage on an unknown machine accrues to that node id until it is given an offer; a stage on one of
  `own_nodes` accrues to the operator, as does the cut. Routing fees are the operator's, so a lender
  receives at least its amounts. Its node can show a little more, out of the operator's fee: a blinded
  path charges a margin over what its route takes, and what the route leaves arrives with the payment.
  The ledger counts the invoice's amount. Whole sats are paid and the odd msats stay owed.
- **The gateway must sell only this model.** It reports what it earned in all, not per route, so while
  it sells anything else its earnings are not split: they count as the operator's, and the tool says so.
- A new stage plan splits from the round it is first seen: what came in since the round before goes by
  the plan in force then, so a change is out by at most one interval's earnings.

**Paid is what the wallet says settled, and nothing else.** A payment is noted in the ledger on disk
before the wallet is asked. A note still open at the next round is not retried: the tool first takes the
wallet's spend lock, which waits for whatever the wallet is still doing, then credits what settled. So
the tool can be killed and started again at any moment, and nobody is paid twice. The lab's `mesh_pay`
check kills it before, during and after real payments and holds each lender's node to the ledger.

What this does not do yet: the lenders must trust the operator's count. A lender can read its own
stage from the plan and work out its share, and sees what it was paid, but it cannot see what the
gateway earned.
