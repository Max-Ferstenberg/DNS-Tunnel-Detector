# fft.py
# -----------------------------------------------------------------------------------
# Frequency based analysis of DNS query timings to detect beaconing
# 
# This module implements a simple FFT-based analysis of query timestamps for each parent domain. It looks for strong periodic components in the query timing
# This module computes a single per-domain detection metric as a ratio of peak magnitude to the median magnitude of the FFT spectrum (excluding the DC component). A high ratio indicates a strong periodic signal, which is a common characteristic of beaconing tunnels.
# 
# External Dependencies:
#   - NumPy: https://numpy.org/doc/stable/
#   - numpy.fft.rfft: https://numpy.org/doc/stable/reference/generated/numpy.fft.rfft.html
#   - numpy.histogram: https://numpy.org/doc/stable/reference/generated/numpy.histogram.html
#
# Usage:
#   python3 fft.py <pcap_file>
# -----------------------------------------------------------------------------------

import sys
import os
import numpy as np
from collections import defaultdict

# Thresholds similar to the feature extractor
BIN_SIZE = 1.0          # seconds per bin, the width is used to resample the query timings into an evenly=space time grid
BEACON_THRESHOLD = 4.0  # peak:median ratio above which we flag beaconing
MIN_QUERIES = 8         # skip domains with too few queries to analyse


def analyse_domain(timestamps):
    #The pipeline for this is as follows:
    # 1. Resample the irregular query timestamps into a regular time grid (histogram) with a fixed bin size
    # 2. Compute the FFT of the histogram to get the frequency spectrum
    # 3. Discard the DC component (index 0) and compute the peak and median of the remaining spectrum
    # 4. Find the peak magnitude in the remaining (AC) spectrum and compare to the median
    # 5. Convert the peak bin index to a frequency (Hz) and then to a period (in seconds)
    timestamps = sorted(timestamps) #Sort the timestamps
    duration = timestamps[-1] - timestamps[0]
    if duration == 0: # In the event that all queries are at the same timestamp
        return None

    num_bins = max(1, int(np.ceil(duration / BIN_SIZE))) # Step 1
    counts, _ = np.histogram(timestamps, bins=num_bins, range=(timestamps[0], timestamps[0] + num_bins * BIN_SIZE))

    spectrum = np.abs(np.fft.rfft(counts)) # Step 2, compute the FFT and take the magnitude to get the spectrum. rfft is used since the input is real-valued, it returns the non-negative frequency terms of the FFT which are sufficient to capture all the information for real inputs. The output length is num_bins//2 + 1 due to symmetry of the FFT for real inputs

    # Drop DC component (index 0) and compute peak and median of the remaining spectrum (AC components)
    ac = spectrum[1:]
    if len(ac) == 0:
        return None

    peak = ac.max()
    median = np.median(ac)
    ratio = peak / median if median > 0 else float('inf') # Step 4. If the median is zero but we have a non-zero peak, this indicates a very strong periodic signal with no other significant frequencies, so we can consider the ratio to be infinite in this case

    dominant_bin = ac.argmax() + 1 #+1 because index 0 was dropped
    freqs = np.fft.rfftfreq(num_bins, d=BIN_SIZE)
    dominant_freq = freqs[dominant_bin] #Hz
    period = 1.0 / dominant_freq if dominant_freq > 0 else float('inf') # Step 5. If the dominant frequency is zero (which shouldn't happen since we dropped the DC component), we can consider the period to be infinite since it would correspond to a constant signal with no periodicity. Otherwise, the period is the inverse of the frequency, giving us the time interval of the dominant periodic component in seconds.

    return { #Return all the relevant information about the FFT analysis for this domain in a dictionary
        "num_queries": len(timestamps),
        "duration_s": duration,
        "peak": peak,
        "median_ac": median,
        "ratio": ratio,
        "dominant_period_s": period,
        "is_beacon": ratio >= BEACON_THRESHOLD,
    }


def run(pcap_path):
    # Standalone function to run the FFT analysis on a given pcap file. For testing.
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')) # Import the parser module
    from parser.parser import parse_pcap
    records = parse_pcap(pcap_path)

    by_domain = defaultdict(list)
    for r in records:
        by_domain[r["parent_domain"]].append(r["timestamp"]) #Group timestamps by parent domain, since that's what we did in the feature extractor

    results = []
    for domain, timestamps in by_domain.items():
        if len(timestamps) < MIN_QUERIES:
            continue
        info = analyse_domain(timestamps)
        if info is None:
            continue
        results.append((domain, info))

    results.sort(key=lambda x: x[1]["ratio"], reverse=True) #Highest suspicion first

    #Prints out a nice pretty table! Very cool :)
    print(f"\n{'='*70}")
    print(f"FFT beaconing analysis: {pcap_path}")
    print(f"{'='*70}")
    print(f"{'Domain':<35} {'Queries':>7} {'Period(s)':>10} {'Ratio':>8}  Flag")
    print(f"{'-'*70}")
    for domain, info in results:
        flag = "*** BEACON ***" if info["is_beacon"] else ""
        period = f"{info['dominant_period_s']:.1f}" if info['dominant_period_s'] != float('inf') else "  inf"
        print(f"{domain:<35} {info['num_queries']:>7} {period:>10} {info['ratio']:>8.1f}  {flag}")

    beacons = [d for d, i in results if i["is_beacon"]]
    print(f"\nBeaconing domains ({len(beacons)}): {', '.join(beacons) if beacons else 'none'}")
    return results


if __name__ == "__main__":
    #CLI command formatting and error handling. Defaults to running on a set of example pcaps
    if len(sys.argv) < 2:
        data_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
        pcaps = [os.path.join(data_dir, f) for f in
                 ("benign.pcap", "dns2tcp_tunnel.pcap", "iodine_tunnel.pcap")]
    else:
        pcaps = sys.argv[1:]

    for pcap in pcaps:
        run(pcap)
