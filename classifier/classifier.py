# classifier.py
# ----------------------------------------------------------------------------------
#Converts featrure dictionaries into suspicion scores
#Classifies domains as tunnel, suspicious or benign based on these scores
#
# Internal Dependencies:
#  - featureextraction.compute_domain_features
#  - featureextraction.compute_features
# Usage:
#   python3 classifier.py <pcap_file>
# ----------------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "features": {
        #Has already been normalised, proportional 0-1 scale
        "uncommon_record_proportion": {"low": 0.0,  "high": 1.0,  "weight": 3.0},
        #Iodine produces much higher values for Char KL, 
        # and is somewhat of an outlier. Despite that, it is well above the threshold by a significant margin,
        # and will produce an equivalently high suspicion score. Hence, the high threshold is set to a lower
        # value than what a tool like Iodine produces.
        "char_kl_divergence":         {"low": 1.5,  "high": 3.0,  "weight": 2.5},
        #Unique:total distribution of subdomains. Higher means more unique subdomains, which is more suspicious.
        "unique_subdomain_ratio":     {"low": 0.7,  "high": 0.95, "weight": 2.0},
        #Shannon entropy of the subdomains. Higher means more random-looking, which is more suspicious.
        "shannon_entropy":            {"low": 3.5,  "high": 6.0,  "weight": 1.5},
        #Average length of subdomains. Higher means more random-looking, which is more suspicious.
        "mean_subdomain_length":      {"low": 15.0, "high": 35.0, "weight": 1.5},
        #This is less discriminative than other features, because it could also just be behaviour of a regular user clicking on lots of webpages. Hence, it has a lower weight.
        "query_rate":                 {"low": 1.0,  "high": 5.0,  "weight": 1.0},
        #Has much more overlap between benign and tunnel domains, so it has a low weight and a higher threshold.
        "bigram_kl_divergence":       {"low": 6.0,  "high": 8.0, "weight": 0.5},
        #This is the beacon catching, it will only capture certain tools though; not all beacon, but when they do, it is a strong indicator.
        "peak_to_median_ratio":       {"low": 2.5,  "high": 5.0, "weight": 1.5},
    },
    "thresholds": {
        #Score cutoffs as defined through iterative testing.
        "tunnel":     0.7,
        "suspicious": 0.4,
    },
    #Min number of features required to output anything but "insufficient_data"; stops reliance on a single feature.
    "min_features_for_class": 2,
}

def _normalise(value, low, high):
    #Map a val from the inconsisent [low, high] range to [0,1 ]
    # This is private and not part of the public API - PEP8: https://peps.python.org/pep-0008/#naming-conventions
    
    #Guard because high==low would divide by zero
    if high == low:
        return 0.0
    return max(0.0, min(1.0, (value - low) / (high - low)))


def classify_domain(features, config=None):
    #Compute suspicion score and consequent classification for a single domain.
    # score = sum(feature_suspicion * feature_weight) / sum(feature_weights)
    # Returns a dict with keys: score, class, features_used, contributing_features
    if config is None:
        config = DEFAULT_CONFIG

    feature_cfgs = config["features"]
    thresholds   = config["thresholds"]
    min_features = config.get("min_features_for_class", 2)

    weighted_sum  = 0.0
    total_weight  = 0.0
    contributions = {}

    for name, cfg in feature_cfgs.items():
        #skip all the missing ones; the score has been normalised to be between 0 and 1 no matter the number, so missing features don't contribute to the score, but they also don't cause it to be higher or lower.
        value = features.get(name)
        if value is None:
            continue

        suspicion = _normalise(value, cfg["low"], cfg["high"])
        weight    = cfg["weight"]

        weighted_sum  += weight * suspicion
        total_weight  += weight
        contributions[name] = {"raw": value, "suspicion": suspicion, "weight": weight}

    features_used = len(contributions)

    #A guard for insufficient data; without enough data, any output would be statistically unreliable, so it is better to bin them into a separate class.
    if features_used < min_features:
        return {
            "score":    None,
            "classification":   "insufficient_data",
            "features_used":    features_used,
            "contributing_features":    contributions,
        }

    score = weighted_sum / total_weight

    #The classification!
    if score >= thresholds["tunnel"]:
        classification = "tunnel"
    elif score >= thresholds["suspicious"]:
        classification = "suspicious"
    else:
        classification = "benign"

    return {
        #So you can peek at the score and metrics too!
        "score":    score,
        "classification":   classification,
        "features_used":    features_used,
        "contributing_features":    contributions,
    }


def classify_all(all_features, config=None):
    #Run through all the domains and classify them!
    return {
        domain: classify_domain(features, config) for domain, features in all_features.items()
    }


if __name__ == "__main__":
    #CLI for the static classifier
    import os
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "parser"))
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "features"))
    from parser import parse_pcap
    from featureextraction import compute_features #Raises a warning because the path to featureextraction.compute_features is set at runtime

    if len(sys.argv) != 2:
        print("Usage: python classifier.py <pcap_file>")
        sys.exit(1)

    records  = parse_pcap(sys.argv[1])
    features = compute_features(records)
    results  = classify_all(features)

    #Outputs it in a nice format to show you all the results!
    for domain, result in results.items():
        print(f"\n============== {domain} ==============")
        score   = f"{result['score']:.4f}" if result["score"] is not None else "N/A"
        classification = result["classification"]
        n       = result["features_used"]
        print(f"  score={score}  classification={classification}  features_used={n}")
        for fname, fdata in result["contributing_features"].items():
            #space all the output rows evenly so it isn't painful to look  at
            print(f"  {fname:30s}: raw={fdata['raw']:.4f}  suspicion={fdata['suspicion']:.4f}  weight={fdata['weight']}")
