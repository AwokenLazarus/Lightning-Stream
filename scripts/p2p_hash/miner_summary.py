"""Summarises a scripts/p2p_hash_miner.sh run from its reports."""
import json
import sys
from pathlib import Path

d, slice_work, stop_after = Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
h = json.loads((d / "hasher.json").read_text())
b = json.loads((d / "buyer.json").read_text())
after = json.loads((d / "pools-after.json").read_text())
st = h.get("stopped") or {}
past = int(st.get("work", "0")) - (stop_after + 1) * slice_work
out = {
    "slicesPaid": h["paid"],
    "buyerReleased": b["released"],
    "receiptsAgree": h["receiptsAgree"],
    "receiptsDisagree": h["receiptsDisagree"],
    "metersEqual": h["meter"] == b["meter"],
    "meter": h["meter"],
    "stopped": st.get("reason"),
    "slicesPastUnpaid": max(past, 0) / slice_work,
    "minerMethods": h.get("methods"),
    "lastRate": b.get("lastRate"),
    "poolsRestored": after.get("restored"),
}
out["pass"] = (
    out["slicesPaid"] == stop_after == out["buyerReleased"] == out["receiptsAgree"]
    and out["receiptsDisagree"] == 0
    and out["metersEqual"]
    and out["stopped"] == "unpaid"
    and past < slice_work
    and out["poolsRestored"] is True
)
print(json.dumps(out, indent=2))
