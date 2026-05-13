# DNS Tunnel Detector

A lightweight DNS tunnelling detector that uses statistical analysis rather than machine learning. Built to assess whether informational methods can match ML approaches, with the goal of providing more explainability and avoiding the classic black box problem of neural networks.

Operates on static PCAP files and live network traffic. Testing was performed across **Iodine**, **dns2tcp**, and **DNScat2**.

## Why?

DNS tunnelling smuggles arbitrary data across DNS queries, often used by malware for C2, data exfil and bypassing network controls, and because everything uses DNS, firewalls tend not to block it.

Most published methdods are either signature or ML-based, the former of which is good at catching known tools but misses novelty, the latter of which requires labelled data, is computationally expensive, and has a notorious black box problem.

This project aims to use a statistical classifier that uses multiple features with transparent thresholds so that every classification can be inspected and understood, which is helpful for triage.

## Results

| Metric    | Score |
|-----------|-------|
| Precision | 1.000 |
| Recall    | 1.000 |
| F1 Score  | 1.000 |

⚠ These numbers should be read with a massive caveat: all traffic was generated in a controlled lab environment with default tool configurations. Real traffic is noisier, and a sophisticated adversary could evade these signals by adjusting tool parameters (see [Limitations](#limitations)). The value of the project lies in the method and architecture it proposes.

## How?

The detector operates in five stages:

```
PCAP / live capture
        │
        ▼
  ┌──────────┐
  │  Parser  │  Uses Scapy, extracts queries, splits subdomain/parent
  └────┬─────┘
       ▼
  ┌──────────────────┐
  │  Feature Extract │  Domain aggregation across the following metrics:
  └────┬─────────────┘  Shannon entropy, KL divergence (char + bigram),
       │                subdomain length stats, query rate, unique ratio,
       │                uncommon record proportion
       ▼
  ┌─────────┐
  │   FFT   │  Resamples query timings -> frequency spectrum ->
  └────┬────┘  peak-to-median ratio 
       ▼
  ┌─────────────┐
  │  Classifier │  Classifies based on weighted score across normalised features
  └────┬────────┘  
       ▼
   Classification and feature contribution breakdown
```

The `peak_to_median_ratio` from FFT is aimed at catching beaconing specifically, by spotting periodic spikes in the frequency of queries

## Repo Structure
```
.
├── parser/                  # PCAP and live DNS query extraction
├── features/                # Feature extraction and baseline construction
├── fft/                     # Frequency/domain beaconing detection
├── classifier/              # Classification logic
├── detector/                # Live capture (AsyncSniffer)
├── baselines/               # Reference "normal" char/bigram distributions
├── data/                    # Test PCAPs; just the test data I used
├── lab/                     # Dockerfile and compose
├── docs/                    # My full report and complete documentation, in case you fancy reading a very long bit of writing!
├── evaluate.py              # Evaluation script
└── requirements.txt
```

## How To Use

### Setup

```bash
git clone https://github.com/yourusername/dns-tunnel-detector.git
cd dns-tunnel-detector
pip install -r requirements.txt
```

### Classify a single PCAP

```bash
python3 classifier/classifier.py data/iodine_tunnel.pcap
```

### Run the Live Detection on an Interface (needs root)

```bash
sudo python3 detector/live.py \
    --interface [IF] \
    --window [TIME (s) of the rolling time window analysed] \
    --interval [Interval (s) for how often analysis runs] \
    --threshold [What threshold of classification (benign, suspicious, tunnel) do you want to be alerted at?] \
    --verbose
```

## Design Choices

A few decisions worth noting if you look at the code:

- Aggregation is done by parent domain instead of query; a single query with a large entropy value is fucntionally indistinguishable from background noise, so we look at them as a series of queries, grouped by parent domain.
- Latin-1 is used because Iodine specifically pads subdomains with arbitrary 8-bit bytes as a part of its tunnelling mechanism, and UTF-8 would (and did) raise decoding errors.
- Missing features are categorised as None instead of zero; a numerical zero would skew classifications towards benign.
- Median is used for FFT normalisation over mean, because beaconing produces single sharp peaks, which would skew a mean value, but averages out just fine over median

## Limitations

This is a defensive tool that was only tested against controlled data, as such:

- A sophisticated attacker could lower their beacon frequency, restrict to common record types, shorten subdomains to fit benign distributions, and avoid binary payloads; any of which would degrade detection.
- TLD splitting assumes single-label TLDs, so domains with mutliple part TLDs are incorrectly split. A real deployment should use a public suffix list library like tldextract.
- Perfect F1 does NOT mean this is a perfect detector, it very much is not. This is a proof of methodological concept.

## Dependencies

- Python 3.11+
- scapy
- numpy
- scipy


## License

MIT — see [LICENSE](LICENSE).
