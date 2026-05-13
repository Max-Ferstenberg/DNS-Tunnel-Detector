# baselinecalculator.py
# ------------------------------------------------------------------------------------------------
# Script to build a reference char and bigram distribution from the Tranco top 1 million domains.
# The output JSON is used as the "reference" distribution for the feature extractor.
# 
# Output is located at ../baselines/reference.json relative to this script.
#
# Usage:
#   python baselinecalculator.py [path/to/top-1m.csv]
#
# External References:
# - Tranco list: https://tranco-list.eu/
#   - Le Pochat et al. (2019), NDSS — research-oriented list construction
#   - csv module:    https://docs.python.org/3/library/csv.html
#   - pathlib:       https://docs.python.org/3/library/pathlib.html
#   - Counter:       https://docs.python.org/3/library/collections.html#collections.Counter
# ------------------------------------------------------------------------------------------------

import csv
import json
import sys
from collections import Counter
from pathlib import Path

# Fixed alphabet over which all distributions are defined
# Anything outside this alphabet is bucketed into "other"
# https://www.rfc-editor.org/rfc/rfc1035#section-2.3.1
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-"
OTHER = "other"


def extract_sld(domain):
    # Extract the second-level domain (SLD) from a full domain name
    # For example, from "www.example.com" we want "example"
    parts = domain.strip().lower().split(".") # Split on dots to separate labels
    if len(parts) < 2: # If there's only one part, we treat it as the SLD (e.g. "localhost")
        return parts[0] if parts else ""
    # Take the label immediately before the TLD
    return parts[-2]


def count_chars_and_bigrams(text, char_counts, bigram_counts):
    # This function updates the provided char_counts and bigram_counts
    # Counters based on the characters and bigrams in the given text
    text = text.lower()

    for char in text:
        if char in ALPHABET: # Only count characters in the defined alphabet
            char_counts[char] += 1 
        else:
            char_counts[OTHER] += 1

    # Counts bigrams by iterating through pairs of characters in the text
    for i in range(len(text) - 1):
        bigram = text[i:i + 2]
        if all(c in ALPHABET for c in bigram):
            bigram_counts[bigram] += 1
        else:
            bigram_counts[OTHER] += 1


def build_baseline(tranco_csv_path, num_domains=None):
    # Builds the baseline character and bigram distributions from the Tranco CSV file
    # If num_domains is specified, it limits the processing to that many domains
    char_counts = Counter()
    bigram_counts = Counter()
    domain_count = 0

    for char in ALPHABET:
        char_counts[char] = 0
    char_counts[OTHER] = 0

    with open(tranco_csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader: # Each row is expected to have at least two columns: rank and domain
            if len(row) < 2:
                continue

            domain = row[1]
            sld = extract_sld(domain)

            if not sld: #skip empty SLDs
                continue

            count_chars_and_bigrams(sld, char_counts, bigram_counts) # Update counts based on the SLD of the domain
            domain_count += 1

            if num_domains is not None and domain_count >= num_domains: # Stop processing if we've reached the specified number of domains
                break

    total_chars = sum(char_counts.values())
    total_bigrams = sum(bigram_counts.values())

    char_freqs = {
        char: count / total_chars # Convert counts to frequencies by dividing by the total number of characters
        for char, count in char_counts.items()
    }

    bigram_freqs = {
        bigram: count / total_bigrams # Convert counts to frequencies by dividing by the total number of bigrams
        for bigram, count in bigram_counts.items()
    }

    # Construct the baseline dictionary with metadata and the calculated frequencies
    baseline = {
        "metadata": {
            "source": str(tranco_csv_path),
            "num_domains_processed": domain_count,
            "alphabet": ALPHABET,
            "other_bucket": OTHER,
        },
        "char_frequencies": char_freqs,
        "bigram_frequencies": bigram_freqs,
    }

    return baseline


if __name__ == "__main__":
    if len(sys.argv) > 1:
        csv_path = Path(sys.argv[1])
    else:
        csv_path = Path(__file__).parent / ".." / "top-1m.csv"

    if not csv_path.exists(): #just some error handling
        print(f"Error: Tranco CSV not found at {csv_path}")
        print("Download it from https://tranco-list.eu/")
        sys.exit(1)

    print(f"Building baseline from {csv_path}...")
    baseline = build_baseline(csv_path, num_domains=10000) #Limit to top 10k domains for speed

    output_path = Path(__file__).parent / ".." / "baselines" / "reference.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(baseline, f, indent=2, sort_keys=True)

    print(f"Baseline written to {output_path}")