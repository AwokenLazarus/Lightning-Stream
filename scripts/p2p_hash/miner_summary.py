"""Summarises a scripts/p2p_hash_miner.sh run from its reports and its Stratum log, and answers what no lab can:
what a real miner's firmware does with the check."""
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

d, slice_work, stop_after = Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
h = json.loads((d / "hasher.json").read_text())
b = json.loads((d / "buyer.json").read_text())
after = json.loads((d / "pools-after.json").read_text())
st = h.get("stopped") or {}


def blake(x: bytes) -> bytes:
    return hashlib.blake2b(x, digest_size=32).digest()


def eight(s: str) -> bytes:
    raw = bytes.fromhex(s)
    return raw if len(raw) == 8 else raw[::-1] + bytes(4)


def met(hash_: bytes, d_: float) -> bool:
    return int.from_bytes(hash_, "big") * d_ <= 2**224


forms = Counter()
methods = Counter()
extra_params = Counter()
jobs, session, diff, sub_id = {}, None, 1.0, None
newest, new_diff_at_once, new_diff_next_job, proven, failed = None, 0, 0, 0, 0
changed_on = None
log = d / "stratum-lines.log"
for row in log.read_text().splitlines() if log.exists() else []:
    tag, _, body = row.split(" ", 2)
    try:
        v = json.loads(body)
    except ValueError:
        continue
    m = v.get("method")
    if tag == "UP" and m:
        methods[m] += 1
    if tag == "UP" and m == "mining.subscribe":
        sub_id = v.get("id")
    if tag == "DN" and v.get("id") == sub_id and sub_id is not None and isinstance(v.get("result"), list):
        session = (bytes.fromhex(v["result"][1]), v["result"][2])
    if tag == "DN" and m == "mining.set_difficulty":
        if newest is not None and v["params"][0] > diff:
            changed_on = (newest, diff, v["params"][0])
        diff = v["params"][0]
    if tag == "DN" and m == "mining.notify":
        newest = v["params"][0]
        jobs[newest] = (v["params"], diff)
    if tag == "UP" and m == "mining.submit" and session:
        p = v["params"]
        forms[f"en2 {len(p[2])} ntime {len(p[3])} nonce {len(p[4])} hex"] += 1
        extra_params[len(p) - 5] += 1
        job = jobs.get(p[1])
        if not job:
            continue
        n = job[0]
        root = blake(b"\0" + bytes.fromhex(n[2]) + session[0] + bytes.fromhex(p[2]) + bytes.fromhex(n[3]))
        hash_ = blake(bytes.fromhex(n[1]) + eight(p[4]) + eight(p[3]) + root)
        if met(hash_, job[1]):
            proven += 1
        else:
            failed += 1
        # a share of the job the difficulty rose on: does the firmware hold it to the new one at once?
        if changed_on and p[1] == changed_on[0]:
            if met(hash_, changed_on[2]):
                new_diff_at_once += 1
            else:
                new_diff_next_job += 1

slices_past = int(st.get("unpaidWork", "0")) / slice_work
same = (h["meter"]["work"], h["meter"]["proven"]) == (b["meter"]["work"], b["meter"]["proven"])
out = {
    "slicesPaid": h["paid"],
    "hashtakerReleased": b["released"],
    "provenCountsEqual": same,
    "meter": h["meter"],
    "theHashtakersMeter": b["meter"],
    "stopped": st.get("reason"),
    "slicesPastPaid": slices_past,
    "blinded": {"jobsShownBlinded": b.get("jobsShownBlinded", 0), "closed": b.get("closed")},
    "lastRate": b.get("lastRate"),
    "poolsRestored": after.get("restored"),
    "firmware": {
        "methods": methods,
        "submitForms": forms,
        "versionRollingParams": extra_params,
        "proofOfflineFromTheLog": {"proven": proven, "failed": failed},
        "sharesOnAJobWhoseDifficultyRose": {"meetTheNewOne": new_diff_at_once, "onlyTheOldOne": new_diff_next_job},
    },
}
out["pass"] = (
    out["slicesPaid"] == stop_after == out["hashtakerReleased"]
    and same
    and out["stopped"] == "unpaid"
    and slices_past < 1
    and failed == 0
    and proven > 0
    and out["poolsRestored"] is True
)
print(json.dumps(out, indent=2))
