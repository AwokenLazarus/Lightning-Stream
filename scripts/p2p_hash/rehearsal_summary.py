"""Summarises a scripts/p2p_hash_rehearsal.sh run from its evidence directory.

    rehearsal_summary.py DIR T0 SLICE_WORK STOP_PAYING_AFTER HASHER_IP MINER_IP
"""
import base64
import json
import sys
from pathlib import Path

d, t0, slice_work, stop_after, hasher_ip, miner_ip = Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], sys.argv[6]


def load(p, default=None):
    try:
        return json.loads((d / p).read_text())
    except (OSError, ValueError):
        return default


def hexhash(h):
    if not h:
        return ""
    if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
        return h
    return base64.b64decode(h).hex()


h = load("hasher/hasher.json", {})
b = load("buyer.json", {})
found = load("found.json", {})
pays = load("buyer-payments.json", {}).get("payments", [])
invs = load("seller-invoices.json", {}).get("invoices", [])
after = load("pools-after.json", {})

new_pays = [p for p in pays if int(p.get("creation_date", 0)) >= t0]
new_invs = [i for i in invs if int(i.get("creation_date", 0)) >= t0]
st = h.get("stopped") or {}
done = h.get("slicesDone", [])
unpaid_slice_done = done[stop_after]["atMs"] if len(done) > stop_after else None


def conns(name, ports):
    try:
        lines = (d / name).read_text().splitlines()
    except OSError:
        return []
    return [" ".join(x.split()[3:5]) for x in lines if any(p in x for p in ports)]


route = {
    "miner -> hasher": [e.get("peer") for e in h.get("events", []) if e.get("ev") == "miner"],
    "hasher's link peer (buyer key)": h.get("buyer"),
    "listing found": {k: found.get(k) for k in ("event", "author", "refused")} | {"link": (found.get("listing") or {}).get("link")},
    "buyer -> gateway (upstream sessions opened)": [e for e in b.get("events", []) if e.get("ev") == "open"],
    "connections on the hasher": conns("connections-hasher.txt", [":" + p for p in ("34930", "34944", "34942", "23334")]),
    "connections on the buyer": conns("connections-buyer.txt", [hasher_ip]),
}
slices = [
    {"slice": p["slice"], "ok": p.get("ok"), "ms": p.get("ms"), "charged_sats": (p.get("wallet") or {}).get("charged_sats"),
     "rail": (p.get("wallet") or {}).get("rail"), "why": p.get("why")}
    for p in b.get("pays", [])
]
payments = []
for p in new_pays:
    hops = []
    for x in p.get("htlcs", []):
        if x.get("status") == "SUCCEEDED":
            hops = [hop.get("pub_key", "")[:16] for hop in x.get("route", {}).get("hops", [])]
    payments.append({"hash": p.get("payment_hash"), "status": p.get("status"), "value_sat": p.get("value_sat"),
                     "fee_msat": p.get("fee_msat"), "route": hops})
invoices = [{"hash": hexhash(i.get("r_hash")), "state": i.get("state"), "value_sat": i.get("value"), "paid_msat": i.get("amt_paid_msat"),
             "memo": i.get("memo")} for i in new_invs]
out = {
    "route": route,
    "slicesPaidByHasherCount": h.get("paid"),
    "receiptsAgree": h.get("receiptsAgree"),
    "receiptsDisagree": h.get("receiptsDisagree"),
    "metersEqual": h.get("meter") == b.get("meter"),
    "meter": h.get("meter"),
    "minerMethods": h.get("methods"),
    "slices": slices,
    "chargedSats": sum(int(s["charged_sats"] or 0) for s in slices if s["ok"]),
    "buyerNodePayments": payments,
    "feesMsat": sum(int(p["fee_msat"] or 0) for p in payments if p["status"] == "SUCCEEDED"),
    "sellerNodeInvoices": invoices,
    "stop": {"reason": st.get("reason"), "paid": st.get("paid"), "slicesPastUnpaid": max(int(st.get("work", "0")) - (stop_after + 1) * slice_work, 0) / slice_work,
             "msAfterUnpaidSliceDone": (st.get("atMs", 0) - unpaid_slice_done) if unpaid_slice_done else None},
    "buyerClosed": b.get("closed"),
    "walletSessionStop": [e for e in b.get("events", []) if e.get("ev") == "wallet session stopped"],
    "poolsRestored": after.get("restored"),
    "minerIp": miner_ip,
}
print(json.dumps(out, indent=2))
