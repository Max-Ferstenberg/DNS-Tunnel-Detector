# featureextraction.py
# -----------------------------------------------------------------------------------
# Computes the full set of features for each parent domain based on its query records
# Each parent domain is reduced to a fixed dictionary
#
# External dependencies:
#   - SciPy:  https://docs.scipy.org/doc/scipy/reference/stats.html
#   - NumPy:  pulled in via scipy and the FFT module
#
# Internal dependencies:
#   - parser/parser.py
#   - fft/fft.py
#   - baselines/reference.json
#
# Usage:
#   python3 featureextraction.py <pcap_file>
# -----------------------------------------------------------------------------------

import json
import math
import os
import sys
from collections import Counter, defaultdict

# https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.entropy.html
from scipy.stats import entropy

# the FFT module lives in the parent directory's fft/ folder, so we add that to the path
# https://docs.python.org/3/library/sys.html#sys.path
# means you don't have to install the project as a package
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fft"))
from fft import analyse_domain

SMOOTHING = 1e-10 # small constant added to probabilities to avoid zeros in KL divergence calculations
MIN_QUERIES_FOR_KL = 5 # minimum number of queries required to compute KL divergence
MIN_QUERIES_FOR_RATE = 8 # minimum number of queries required to compute rate features
MIN_DURATION_FOR_RATE = 1.0  # minimum duration (in seconds) required to compute rate features
MIN_CHARS_FOR_ENTROPY = 30 # minimum number of characters required to compute entropy
MIN_QUERIES_FOR_RATIO = 3 # minimum number of queries required to compute ratio features
MIN_QUERIES_FOR_FFT = 3 # minimum number of queries required to compute FFT features

def load_baseline(baseline_path=None):
    # Load the baseline from the reference distribution produced by baselinecalculator.py
    if baseline_path is None:
        # Default path: ../baselines/reference.json relative to this file.
        script_dir = os.path.dirname(os.path.abspath(__file__))
        baseline_path = os.path.join(script_dir, "..", "baselines", "reference.json")

    #https://docs.python.org/3/library/json.html#json.load
    with open(baseline_path, "r") as f:
        baseline = json.load(f)

    #Return a flattened dictionary prevents any conflicts down the line with the nested JSON structure
    return {
        "alphabet": baseline["metadata"]["alphabet"],
        "other_bucket": baseline["metadata"]["other_bucket"],
        "char_frequencies": baseline["char_frequencies"],
        "bigram_frequencies": baseline["bigram_frequencies"],
    }


def build_char_distribution(text, alphabet, other_bucket):
    # Build a character probability distribution over the given alphabet and other categories
    text = text.lower()

    # Seed every alphabet key with zero so that it appears in the distribution even if absent to avoid missing key errors
    counts = {char: 0 for char in alphabet}
    counts[other_bucket] = 0

    #Count the characters
    for char in text:
        if char in alphabet:
            counts[char] += 1
        else:
            counts[other_bucket] += 1

    total = sum(counts.values())

    # Edge case if total is zero (e.g. empty string), return a uniform distribution to avoid division by zero
    if total == 0:
        uniform = 1.0 / len(counts)
        return {key: uniform for key in counts}

    return {key: count / total for key, count in counts.items()} # Convert counts to probabilities by dividing by the total character count


def build_bigram_distribution(text, alphabet, other_bucket):
    text = text.lower()
    counts = Counter() #https://docs.python.org/3/library/collections.html#collections.Counter

    #Sliding window of size 2 to extract bigrams
    for i in range(len(text) - 1):
        bigram = text[i:i + 2]
        if all(c in alphabet for c in bigram):
            counts[bigram] += 1
        else:
            counts[other_bucket] += 1

    total = sum(counts.values())

    #Same edge case handling as above
    if total == 0:
        return counts

    return {key: count / total for key, count in counts.items()} #same as above; return as probability


def kl_divergence_aligned(observed, baseline):
    # Compute KL divergence between two distributions that may have different keys by aligning them first
    all_keys = set(observed.keys()) | set(baseline.keys()) # Union of keys from both distributions

    obs_array = [observed.get(key, 0.0) + SMOOTHING for key in all_keys] #Align observed distribution to the full key set, filling in zeros (plus smoothing) for missing keys
    base_array = [baseline.get(key, 0.0) + SMOOTHING for key in all_keys] #same here

    #scipy.stats.entropy renormalises both arrays to sum to 1 internally
    return entropy(obs_array, base_array, base=2) #https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.entropy.html


def shannon_entropy(text):
    #Compute the Shannon entropy of the characters in the text, higher entropy means more randomness and less predictability
    if not text:
        return 0.0 #some error handling for empty string input

    counts = Counter(text) #Count the occurrences of each character in the text
    total = len(text) #Total number of characters is the length of the text
    probs = [count / total for count in counts.values()] #calculate the probability of each character by dividing its count by the total number of characters

    return entropy(probs, base=2) #https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.entropy.html


def group_by_parent_domain(records):
    #Group the query records by their parent domain using a defaultdict to automatically create lists for new keys
    groups = defaultdict(list) #https://docs.python.org/3/library/collections.html#collections.defaultdict
    for record in records:
        groups[record["parent_domain"]].append(record)
    return groups


def compute_domain_features(records, baseline):
    #This is the main function that will call all the previous ones
    #All the features are guarded by sample size checks

    #Extract the relevant fields from the records for feature computation
    subdomains = [r["subdomain"] for r in records]
    record_types = [r["record_type"] for r in records]
    timestamps = [r["timestamp"] for r in records]

    #Concatenate all subdomains
    all_chars = "".join(subdomains)

    flags = [] #This will hold any flags about why certain features were skipped due to insufficient data, which can be useful for debugging and analysis later on

    # Feature 1: Shannon entropy of subdomain characters
    # only compute if sufficient character data exists
    # High entropy indicates more uniform distribution, lower entropy indicates more natural language distribution
    if len(all_chars) >= MIN_CHARS_FOR_ENTROPY:
        entropy_value = shannon_entropy(all_chars)
    else:
        entropy_value = None
        flags.append("entropy_skipped_low_chars")

    # Feature 2: KL divergence against character baseline
    # only compute if sufficient query volume, since KL divergence can be unreliable with low volume
    # Quantifies how far the observed character distribution is from the baseline distribution
    if len(records) >= MIN_QUERIES_FOR_KL:
        observed_chars = build_char_distribution(
            all_chars,
            baseline["alphabet"],
            baseline["other_bucket"]
        )
        char_kl = kl_divergence_aligned(
            observed_chars,
            baseline["char_frequencies"]
        )
    else:
        char_kl = None
        flags.append("kl_skipped_low_volume")

    # Feature 3: KL divergence against bigram baseline
    # only compute if sufficient query volume
    if len(records) >= MIN_QUERIES_FOR_KL:
        observed_bigrams = build_bigram_distribution(
            all_chars,
            baseline["alphabet"],
            baseline["other_bucket"]
        )
        bigram_kl = kl_divergence_aligned(
            observed_bigrams,
            baseline["bigram_frequencies"]
        )
    else:
        bigram_kl = None 
        #don't need to add another flag here since it's the same volume check as the character KL divergence

    # Feature 4: Subdomain length stats
    # Tunnels usually produce long subdomains because the subdomain field carries data.
    # Mean and standard deviation are always computable and thus don't need a guard, since shorter strings just produce low values
    lengths = [len(s) for s in subdomains]
    mean_length = sum(lengths) / len(lengths) if lengths else 0
    if len(lengths) > 1:
        stddev_length = math.sqrt(
            sum((l - mean_length) ** 2 for l in lengths) / len(lengths)
        )
    else:
        stddev_length = 0

    # Feature 5: Query volume and rate
    # the total volume is also always available, but the rate is only meaningful if there's enough volume and duration to avoid skew from small sample sizes or short bursts of queries
    total_volume = len(records)
    query_rate = None
    if len(timestamps) > 1:
        duration = max(timestamps) - min(timestamps)
        # only compute rate if sufficient query volume and duration as above
        if total_volume >= MIN_QUERIES_FOR_RATE and duration >= MIN_DURATION_FOR_RATE:
            query_rate = total_volume / duration if duration > 0 else 0
        else:
            flags.append("rate_skipped_low_volume_or_duration")

    # Feature 6: Unique subdomain count
    # Tunnels generate an almost 1:1 ratio of unique subdomains to total queries because each query carries a different payload chunk
    unique_subdomains = len(set(subdomains))

    if total_volume >= MIN_QUERIES_FOR_RATIO:
        unique_ratio = unique_subdomains / total_volume
    else:        
        unique_ratio = None
        flags.append("unique_ratio_skipped_low_volume")

    # Feature 7: Proportion of uncommon record types
    # Common types are A and AAAA (IPv4 and IPv6 addresses; see parser.py)
    common_types = {"A", "AAAA"}
    uncommon_count = sum(1 for t in record_types if t not in common_types)
    uncommon_proportion = uncommon_count / total_volume if total_volume > 0 else 0 #avoid division by zero, and if there are no queries then the proportion of uncommon types is effectively zero since there are no types at all

    # Feature 8: FFT peak:median ratio
    # Delegates to the FFT module, the peak:median ratio is representative of the strength of perodic components in query timing
    if len(timestamps) >= MIN_QUERIES_FOR_FFT:
        fft_result = analyse_domain(timestamps)
        peak_to_median_ratio = fft_result["ratio"] if fft_result is not None else None
    else:
        peak_to_median_ratio = None
        flags.append("fft_skipped_low_volume")

    return { #Return all the computed features in a dictionary for this parent domain
        "shannon_entropy": entropy_value,
        "char_kl_divergence": char_kl,
        "bigram_kl_divergence": bigram_kl,
        "mean_subdomain_length": mean_length,
        "stddev_subdomain_length": stddev_length,
        "total_volume": total_volume,
        "query_rate": query_rate,
        "unique_subdomains": unique_subdomains,
        "unique_subdomain_ratio": unique_ratio,
        "uncommon_record_proportion": uncommon_proportion,
        "peak_to_median_ratio": peak_to_median_ratio,
        "flags": flags,
    }


def compute_features(records, baseline=None):
    #main entry point for this module, computes features for all parent domains in the given records using the provided baseline or loading the default one if not provided
    if baseline is None:
        baseline = load_baseline()

    grouped = group_by_parent_domain(records)

    features = {}
    for parent_domain, domain_records in grouped.items():
        features[parent_domain] = compute_domain_features(domain_records, baseline)

    return features


if __name__ == "__main__":
    #CLI testing code, allows you to run this module directly on a pcap file to see the computed features for each parent domain. This is useful for quick testing and debugging without needing to set up a full pipeline or separate test scripts
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "parser"))
    from parser import parse_pcap

    if len(sys.argv) != 2:
        print("Usage: python featureextraction.py <pcap_file>")
        sys.exit(1)

    records = parse_pcap(sys.argv[1])
    print(f"Parsed {len(records)} DNS records")

    features = compute_features(records)

    for parent_domain, feature_set in features.items():
        print(f"\n=== {parent_domain} ===")
        for name, value in feature_set.items():
            if isinstance(value, float):
            #space all the output rows evenly and truncate some very long decimals so it isn't painful to look  at
                print(f"  {name:30s}: {value:.4f}")
            else:
                print(f"  {name:30s}: {value}")