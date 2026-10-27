"""Checks the p2p-hash lab's reports against the plan's pass lines (scripts/p2p_hash_lab.sh)."""
import json
import sys
from pathlib import Path

d, slice_work, share, out = Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4])


def load(name, who):
    return json.loads((d / name / f"{who}.json").read_text())


checks = []


def check(name, ok, saw):
    checks.append({"check": name, "pass": bool(ok), "saw": saw})
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {saw}")


# receipts
h, b, p = load("paid", "hasher"), load("paid", "buyer"), load("paid", "pool")
paid = h["paid"]
check("receipts: slices paid", paid >= 5 and b["released"] == paid,
      f"hashmaker paid {paid}, hashtaker released {b['released']}, slices done {len(h['slicesDone'])}")
check("receipts: each receipt equals the hashmaker's count", h["receiptsAgree"] == paid and h["receiptsDisagree"] == 0,
      f"agree {h['receiptsAgree']}, disagree {h['receiptsDisagree']}")
check("receipts: meters equal", h["meter"] == b["meter"], f"hashmaker {h['meter']}, hashtaker {b['meter']}")
check("receipts: gateway credits the hashtaker only", list(p["users"]) == ["buyer.rented"],
      f"pool users {p['users']}, pool work {p['work']}, rejected {p['rejected']} {p['reasons']}")
check("receipts: rejected shares count no work", int(h["meter"]["work"]) == h["meter"]["accepted"] * share
      and h["meter"]["rejected"] > 0, f"accepted {h['meter']['accepted']}, rejected {h['meter']['rejected']}")

# no-hash (same run: the miners stopped at the end)
done_ms = int((d / "paid" / "miners_done_ms").read_text())
last_pay = max(x["atMs"] for x in b["pays"])
cancelled = [e for e in b["events"] if e["ev"] == "cancelled"]
check("no-hash: no payment after the miners stopped", last_pay <= done_ms + 500,
      f"last payment {done_ms - last_pay} ms before the miners stopped")
check("no-hash: the rental ends and locked tickets are cancelled", b["closed"] == "no accepted work" and len(cancelled) == 2,
      f"closed: {b['closed']}; cancelled slices {[e['slice'] for e in cancelled]}")

# unpaid
h, b, p = load("unpaid", "hasher"), load("unpaid", "buyer"), load("unpaid", "pool")
st = h["stopped"] or {}
past = int(st.get("work", "0")) - 4 * slice_work
check("unpaid: the hashmaker stops for non-payment", st.get("reason") == "unpaid" and h["paid"] == 3,
      f"stopped: {st.get('reason')}, paid {h['paid']}")
check("unpaid: within one slice past the unpaid slice", past < slice_work,
      f"{max(past, 0) / slice_work:.2f} slice past slice 4 (unpaid work {st.get('unpaidSlices', 0):.2f} slices)")
miners_done = int((d / "unpaid" / "miners_done_ms").read_text())
check("unpaid: the gateway sees no work after the stop", p["lastAcceptMs"] <= st.get("atMs", 0) + 500
      and int(p["work"]) <= int(st.get("work", "0")) + 2 * share,
      f"pool work {int(p['work']) / slice_work:.2f} slices, last accept {st.get('atMs', 0) - p['lastAcceptMs']} ms before the stop; "
      f"miners cut off {(miners_done - st.get('atMs', 0)) / 1000:.1f} s after it")

ok = all(c["pass"] for c in checks)
out.write_text(json.dumps({"pass": ok, "checks": checks, "sliceWork": str(slice_work)}, indent=2))
print(f"p2p-hash lab: {sum(c['pass'] for c in checks)} of {len(checks)} checks passed")
sys.exit(0 if ok else 1)
