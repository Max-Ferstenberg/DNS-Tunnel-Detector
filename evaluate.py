#!/usr/bin/env python3
# evaluate.py
# ----------------------------------------------------------------------------
#Calculates evaluation metrics
#
# Runs the classifier against the data in data/ and gives precision, recall and F1.
#
# Usage:
#     python3 evaluate.py
# ----------------------------------------------------------------------------

import os
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
for _sibling in ("parser", "features", "classifier"):
    sys.path.insert(0, os.path.join(_SCRIPT_DIR, _sibling))

from parser import parse_pcap                              
from featureextraction import compute_features             #raises a warning for the same reasons as discussed already
from classifier import classify_all                        

TRUE_CLASS = { #Works as true labels for the evaluation
    "data/iodine_tunnel.pcap":  "tunnel",
    "data/dns2tcp_tunnel.pcap": "tunnel",
    "data/benign.pcap":         "benign",
    
    #benign
    "data/benign/browsing.pcap":     "benign",
    "data/benign/streaming.pcap":    "benign",
    "data/benign/development.pcap":  "benign",
    "data/benign/mixed.pcap":        "benign",

    #iodine
    "data/iodine/null_idle.pcap":    "tunnel",
    "data/iodine/txt_idle.pcap":     "tunnel",
    "data/iodine/null_active.pcap":  "tunnel",
    "data/iodine/alt_domain.pcap":   "tunnel",

    #dns2tcp
    "data/dns2tcp/default_light.pcap":  "tunnel",
    "data/dns2tcp/default_heavy.pcap":  "tunnel",
    "data/dns2tcp/alt_domain.pcap":     "tunnel",
    "data/dns2tcp/sustained.pcap":      "tunnel",

    #DNScat2
    "data/dnscat2/idle.pcap":         "tunnel",
    "data/dnscat2/interactive.pcap":  "tunnel",
    "data/dnscat2/exfil.pcap":        "tunnel",
    "data/dnscat2/alt_domain.pcap":   "tunnel",
}

def class_to_label(classification: str) -> str:
    #we return both suspicious and tunnel the same for the purposes of evaluation, since the main point is to distinguish truly benign domains from those that are potentially or actually tunnelling; the distinction between "suspicious" and "tunnel" is inconsequential, since both would require triage, and is somewhat subjective, so it doesn't make sense to be super strict about it
    if classification in ("tunnel", "suspicious"):
        return "tunnel"
    else:
        return "benign"

def evaluate_pcap(pcap_path: str, expected_label: str) -> dict:
    #runs the classifier on the pcap and compares to the expected label
    records  = parse_pcap(pcap_path)
    features = compute_features(records)
    results  = classify_all(features)

    tp = 0 
    fp = 0 
    tn = 0
    fn = 0
    domain_outcomes = []

    for domain, result in results.items():
        predicted = class_to_label(result["classification"])

        if expected_label == "tunnel" and predicted == "tunnel":
            outcome = "TP"
            tp += 1
        elif expected_label == "tunnel" and predicted == "benign":
            outcome = "FN"
            fn += 1
        elif expected_label == "benign" and predicted == "tunnel":
            outcome = "FP"
            fp += 1
        else:
            outcome = "TN"
            tn += 1

        domain_outcomes.append({
            "domain":    domain,
            "expected":  expected_label,
            "classification":   result["classification"],
            "predicted": predicted,
            "score":     result["score"],
            "outcome":   outcome,
        })

    return {
        "pcap":     pcap_path,
        "domains":  len(results),
        "tp":       tp,
        "fp":       fp,
        "tn":       tn,
        "fn":       fn,
        "outcomes": domain_outcomes,
    }


def safe_div(numerator: float, denominator: float) -> float | None:
    #This is to avoid ever dividng by zero. Made it into a function because otherwise we'd have to have a lot of try/catch blocks lower down
    if denominator == 0:
        return None
    else:
        return numerator / denominator


def fmt(value) -> str:
    #same reasoning as above, we have to do a lot of formatting, easier to just centralise it
    if value is None:
        return "n/a  "
    else:
        return f"{value:.3f}"


def main() -> None:
    print("=== Evaluation: DNS Tunnel Detector ===\n")

    per_pcap = [] #Keeps track of the results for each PCAP separately
    for pcap_path, expected_label in TRUE_CLASS.items():
        full_path = os.path.join(_SCRIPT_DIR, pcap_path)
        if not os.path.exists(full_path):
            print(f"ERROR: missing pcap {full_path}", file=sys.stderr)
            sys.exit(1)
        per_pcap.append(evaluate_pcap(full_path, expected_label)) #Adds the results for one PCAP to the list, so we can keep track of which PCAP got which result

    print("PCAP breakdown")
    print(f"  {'pcap':<28} {'domains':>8}  {'TP':>3} {'FP':>3} {'TN':>4} {'FN':>3}")
    for r in per_pcap:
        name = os.path.basename(r["pcap"])
        print(
            f"  {name:<28} {r['domains']:>8}  "
            f"{r['tp']:>3} {r['fp']:>3} {r['tn']:>4} {r['fn']:>3}"
        )

    tp = sum(r["tp"] for r in per_pcap)
    fp = sum(r["fp"] for r in per_pcap)
    tn = sum(r["tn"] for r in per_pcap)
    fn = sum(r["fn"] for r in per_pcap)

    print("\nConfusion matrix")
    print(f"                    {'Pred. tunnel':>14}  {'Pred. benign':>14}")
    print(f"  Actually tunnel   {tp:>14}  {fn:>14}")
    print(f"  Actually benign   {fp:>14}  {tn:>14}")

    precision = safe_div(tp, tp + fp)
    recall    = safe_div(tp, tp + fn)
    f1 = (
        safe_div(2 * precision * recall, precision + recall)
        if precision is not None and recall is not None
        else None
    )

    print("\nMetrics")
    print(f"  Precision: {fmt(precision)}")
    print(f"  Recall:    {fmt(recall)}")
    print(f"  F1 score:  {fmt(f1)}")

    misclassified = [
        outcome
        for r in per_pcap
        for outcome in r["outcomes"]
        if outcome["outcome"] in ("FP", "FN")
    ]

    if misclassified:
        print(f"\nMisclassifications ({len(misclassified)}):")
        for m in misclassified:
            score = f"{m['score']:.3f}" if m["score"] is not None else "n/a"
            print(
                f"  [{m['outcome']}] {m['domain']:<35} "
                f"expected={m['expected']:<7} predicted={m['predicted']:<7} "
                f"classification={m['classification']:<18} score={score}"
            )
    else:
        print("\nNo misclassifications!")

    print()


if __name__ == "__main__":
    main()