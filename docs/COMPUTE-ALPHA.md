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

## Lending a machine

If someone runs a split and invites you, one command lends your machine:

```
stream-compute-check lend --invite invite.json \
  --node-rest https://your-node:8080 --node-macaroon invoices.macaroon --node-cert tls.cert
```

It shows the terms, the downloads and what it will run, and asks first. Then it:

1. fetches the Mesh-LLM build and the model, each checked by sha256;
2. makes a BOLT 12 offer on your own Lightning node, where you are paid (the macaroon needs
   `invoices:read` and `invoices:write`);
3. starts Mesh-LLM and joins the split;
4. prints a card, one line, to give the operator;
5. keeps running, and watches whether you are being paid.

**An invite is the operator's word, and it cannot choose what runs on your machine.** The build must be
one this tool pins, whatever hash the invite names; a build you trust by hand takes `--allow-build SHA256`.
It pins one, `stream-0.78.0-2`: see "Running the split".
The invite picks no flags of the command line. The model is data, read by llama.cpp under your user, so
you may want to run this as a user of its own.

**The build sends no usage reports:** it has no analytics key in it. `mesh-llm analytics status` says so.
`lend` also has it not ask after new versions: `mesh-llm update` would replace this build with another.
And it turns speculative decoding off in that Mesh-LLM's settings: see below for why.

### How you know you are being paid

You need trust no one's count. Every generated token passes through every stage of a split, so your own
node's count of them is a figure the operator cannot change. From your own machine and the invite alone,
`lend` works out what you are due at least: your count, at the invite's rate, less the operator's cut, by
your share of the work from your own stage and the model's header, less a slack of 10% (`--slack-ppm`)
for tokens nobody paid for. It compares that with the settled invoices of your offer on your own node.

One exception: tokens committed by speculative decoding (a draft model, or a model's own draft heads)
take no decode step on any stage, so no count includes them, and a split that drafts pays you below your
work. Your own Mesh-LLM is set not to draft, but the operator's settings alone can make the split draft:
n-gram drafting needs no draft model and works with any model. So `lend` watches for it. Your stage reports
the token positions it runs in speculative verify windows, and if any appear, `lend` leaves the split and
ends, saying why. Start it again once the operator has turned speculative decoding off.

When what you are due passes what you have received by more than your credit limit (`--credit-sats`,
three payout floors by default), it stops serving, says why, and serves again by itself once you are
paid, after staying out for at least two minutes so that the split plans your machine in anew. So the most an operator can take from you is about that limit. `report.json` in its directory has
both figures at any time.

Set the limit above what an honest operator's payout round can leave unpaid. Below that, you stop serving
between its rounds, which costs you earnings and it a stage, and come back at each payment.

That catches an operator who stops paying, takes a bigger cut than it invited you on, serves tokens around
its gateway, or books your stage as its own.

What it does not catch:

- The figure is a floor. It counts generated tokens only, so an operator could skim the share of what
  prompts earn.
- It checks the invite's rate, not what buyers paid: an operator who charges buyers more keeps the difference.
- It protects you from an operator. It does not protect an operator from a lender returning wrong results.
- Your evidence is for you. Nothing here proves a cheat to anyone else.

Each lender needs the whole model file for now, and the alpha build runs on the CPU.

### Running the split

```
stream-compute-check invite --config payout.json --name "Your name" --out invite.json \
  --build-file mesh-bundle.tar.gz --build-url https://... --model-file model.gguf --model-url https://...
stream-compute-check lender-add --config payout.json --card lendcard1... --lock lock.json
```

The build this tool pins is `stream-0.78.0-2` (CPU, Linux x86_64), published with its source commit and
checksum at https://github.com/AwokenLazarus/mesh-llm/releases/tag/stream-0.78.0-2. Run it yourself, and
name its asset in the invite: `--build-file` the archive you downloaded, `--build-url` its download link. It is
Mesh-LLM's `main` plus three changes not yet merged upstream; its release notes say which.

The invite holds your mesh's join token, so give it only to those you invite. It takes its terms from your
payout config and your gateway's prices, and it is what lenders hold you to. Run your own Mesh-LLM node with
`--split` and a `--max-vram` above the invite's, so that your machine leads the split.

`lender-add` adds the lender to the payout, which takes it up on its next round, and writes a lock with the
stages even across your machines and theirs. Restart your Mesh-LLM node with `--split-topology-lock lock.json`,
on the same home directory: it keeps its id and join token, and lenders stay joined. A lender needs no lock.
Allow each lender's `ln-offer:<id>` in your wallet's policy.

A card is someone's word, so `lender-add` will not move an existing lender's pay to another offer without
`--replace`. Check who sent it.
