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
