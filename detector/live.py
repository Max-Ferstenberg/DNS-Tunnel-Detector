#!/usr/bin/env python3
#live.py
#---------------------------------------------------------------------------------------------------------------------------------------------------------------
# Live DNS tunnel detection!
#
# This basically runs the same analysis as the static classifier, but sniffs DNS traffic directly from an interface.
# It accumulates records in a rolling window, and periodically then runs the full pipeline from parsing, to feature extraction, to FFT, to classification.
# 
# Usage:
#   sudo python detector/live.py --interface [IFACE] --window [SECS] --interval [SECS] --threshold [suspicious|tunnel] --verbose
# 
# Raw packet capture requires either root or CAP_NET_RAW
#
# External Dependencies:
#   - Scapy: https://scapy.readthedocs.io/
#   - AsyncSniffer documentation: https://scapy.readthedocs.io/en/latest/api/scapy.sendrecv.html#scapy.sendrecv.AsyncSniffer
#   - argparse: https://docs.python.org/3/library/argparse.html
#   - threading: https://docs.python.org/3/library/threading.html
#   - BPF filter syntax: pcap-filter(7) https://www.tcpdump.org/manpages/pcap-filter.7.html
#---------------------------------------------------------------------------------------------------------------------------------------------------------------

import argparse
import os
import sys
import threading
import time
from datetime import datetime

#Reads imports from sibling directories; like the previous scripts, it will raise a warning because the paths are resolved at runtime
_DETECTOR_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_DETECTOR_DIR)

for _sibling in ("parser", "features", "classifier"):
    sys.path.insert(0, os.path.join(_PROJECT_ROOT, _sibling))

#Internal
from parser import extract_subdomain, RECORD_TYPES 
from featureextraction import compute_features, load_baseline 
from classifier import classify_all, DEFAULT_CONFIG 

from scapy.all import AsyncSniffer, DNS, DNSQR


#these make a shared packet buffer
# records is the list of parsed records between the sniffer thread and the thread doing all the classification
# lock is used to coordinate access to the shared records list; the sniffer thread acquires the lock to append new records
# the main thread acquires it to read recent records and to discard old ones
_lock = threading.Lock()
_records: list[dict] = []

def _packet_to_record(pkt) -> dict | None:
    #convert a single packet into a record dictionary
    # if the packet isn't a DNS query, or if it doesn't have a parsable query name, return None to skip it
    if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
        return None

    #the qname decode is a try/except because in Scapy, malformed packets do occasionally get through and would otherwise cause a crash
    try:
        queryname = pkt[DNSQR].qname.decode("latin-1").rstrip(".")
    except Exception:
        return None

    #qtype is an integer DNS record, DNSQR turns it into the conventional mnemonic (A, TXT, NULL, etc.)
    qtype = pkt[DNSQR].qtype
    subdomain, parentdomain = extract_subdomain(queryname)

    return {
        "timestamp": float(pkt.time),
        "query_name": queryname,
        "subdomain": subdomain,
        "parent_domain": parentdomain,
        "record_type": RECORD_TYPES.get(qtype, f"Unknown ({qtype})"),
    }


def _packet_callback(pkt) -> None:
    #sniffer callback; what to actually do with each packet the sniffer finds.
    record = _packet_to_record(pkt)

    #skip if None
    if record is None:
        return
    
    #the lock is held only until the record is appended
    with _lock:
        _records.append(record)

#a simple map of class strings to integers so that the --threshold argument can be used with a numeric comparison, also makes adding more classes easier if you want
_CLASS = {
    "insufficient_data": -1,
    "benign":             0,
    "suspicious":         1,
    "tunnel":             2,
}

#periodic analysis window
def _run_analysis(
    window_secs: int, #how big is the window
    baseline: dict, #the reference baseline
    config: dict, #the configuration for the classifier
    threshold_verdict: str, #the minimum verdict level to alert on
    verbose: bool,
) -> None:

    now = time.time()
    cutoff = now - window_secs

    #prune the buffer to just the recent records, and take a copy of them for analysis; the lock is held only during the pruning and snapshotting, so the sniffer can keep running and adding new records without waiting for the analysis to finish
    with _lock:
        _records[:] = [r for r in _records if r["timestamp"] >= cutoff]
        snapshot = list(_records)

    ts = _timestamp()

    #if there is no traffic, just put a message and skip the analysis.
    if not snapshot:
        print(f"[{ts}] No DNS queries seen in the last {window_secs}s, waiting...")
        return

    #compute features and classify them!
    features = compute_features(snapshot, baseline)
    results = classify_all(features, config)

    #only output the alerts above the threshold you specify with --threshold 
    alert_rank = _CLASS.get(threshold_verdict, 1)
    alerts = {
        domain: result
        for domain, result in results.items()
        if _CLASS.get(result["classification"], -1) >= alert_rank
    }

    n_domains = len(results)
    if not alerts:
        print(f"[{ts}] Analysed {n_domains} domain(s) in window, nothing above threshold")
        return

    #The actual outputs in a nice format, sorted by score
    print(f"\n[{ts}]  {'='*60}")
    print(f"[{ts}]  {len(alerts)} ALERT(S) — {n_domains} domain(s) analysed")
    print(f"[{ts}]  {'='*60}")

    for domain, result in sorted(
        alerts.items(),
        key=lambda kv: kv[1]["score"] or 0.0, #sort by score, treating None as 0.0 so they go to the bottom
        reverse=True,
    ):
        score_str = f"{result['score']:.3f}" if result["score"] is not None else "N/A "
        print(
            f"[{ts}]  [{result['classification'].upper():11s}]  "
            f"score={score_str}  features={result['features_used']}  {domain}"
        )
        if verbose: #This will output every feature's raw value, normalised suspicion and weight
            for fname, fdata in result["contributing_features"].items():
                print(
                    f"[{ts}]      {fname:30s}  "
                    f"raw={fdata['raw']:8.4f}  "
                    f"suspicion={fdata['suspicion']:.3f}  "
                    f"weight={fdata['weight']}"
                )

    print()

def _timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S") #just outputs the timestamp for the logs

def main() -> None:
    #just provides all the help and whatnot for the CLI
    ap = argparse.ArgumentParser(
        prog="live.py",
        description="live packet capture DNS tunnel detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python detector/live.py\n"
            "  sudo python detector/live.py --interface eth0 --window 120\n"
            "  sudo python detector/live.py --threshold tunnel --verbose\n"
        ),
    )
    ap.add_argument(
        "--interface", "-i",
        metavar="IFACE",
        default=None,
        help="Network interface to capture on (default: Scapy auto-selects).",
    )
    ap.add_argument(
        "--window", "-w",
        metavar="SECS",
        type=int,
        default=60,
        help="Rolling history window in seconds (default: 60).",
    )
    ap.add_argument(
        "--interval", "-n",
        metavar="SECS",
        type=int,
        default=10,
        help="Seconds between analysis passes (default: 10).",
    )
    ap.add_argument(
        "--threshold", "-t",
        choices=["suspicious", "tunnel"],
        default="suspicious",
        help="Minimum verdict level to alert on (default: suspicious).",
    )
    ap.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print per-feature breakdown for each alert.",
    )
    args = ap.parse_args()

    #Load the baseline once at startup
    try:
        baseline = load_baseline()
    except FileNotFoundError as exc: #just in case, let the user know to re-run the baseline script
        print(f"ERROR: could not load baseline — {exc}", file=sys.stderr)
        print("Run baselines/build_baseline.py first.", file=sys.stderr)
        sys.exit(1)

    ts = _timestamp()
    print(f"[{ts}] DNS tunnel detector: live capture mode")
    print(f"[{ts}]   interface : {args.interface or 'auto'}")
    print(f"[{ts}]   window    : {args.window}s")
    print(f"[{ts}]   interval  : {args.interval}s")
    print(f"[{ts}]   threshold : {args.threshold}")
    print(f"[{ts}]   Press Ctrl+C to stop.\n")

    sniffer_kwargs = {
        "filter": "udp port 53", #BPF filter to capture only DNS queries pcap-filter(7): https://www.tcpdump.org/manpages/pcap-filter.7.html
        "prn": _packet_callback, #accesses the callback function 
        "store": False, #tells scapy not to retain any captured packets, otherwise, AsyncSniffer would accumulate every packet in memory
    }
    if args.interface:
        sniffer_kwargs["iface"] = args.interface

    sniffer = AsyncSniffer(**sniffer_kwargs)
    sniffer.start()

    #The main analysis loop; the sniffer thread runs concurrently and fills _records while this thread sleeps; after each interval, the main thread runs one analysis and then sleeps again.
    try:
        while True:
            time.sleep(args.interval)
            _run_analysis(
                window_secs=args.window,
                baseline=baseline,
                config=DEFAULT_CONFIG,
                threshold_verdict=args.threshold,
                verbose=args.verbose,
            )
    except KeyboardInterrupt: #This is the expected stop condition, and this just aims to ensure that the sniffer shuts down gracefully once you stop it manually
        print(f"\n[{_timestamp()}] Stopping.")
    finally:
        sniffer.stop()
        sniffer.join() 
        print(f"[{_timestamp()}] Capture stopped. Goodbye.")


if __name__ == "__main__":
    main()
