"""
AlienVault OTX hash checker

Reads file hashes from a CSV (first column), queries OTX for pulse count,
and writes ONLY malicious results to output.csv.

Before running:
 - Add your API key
 - Set CSV_FILE and OUTPUT_FILE paths
"""

import csv
import requests
import time

# ── CONFIG ──────────────────────────────────────────────
API_KEY = ""  # Add your AlienVault OTX API key here
HEADERS = {"X-OTX-API-KEY": API_KEY}

OTX_URL = "https://otx.alienvault.com/api/v1/indicators/file/{}/general"

CSV_FILE = ""                 # Input CSV path
OUTPUT_FILE = "malicious.csv" # Output only malicious

SLEEP_SECS = 1                # Delay for API rate limits
# ─────────────────────────────────────────────────────────


def get_pulse_count(file_hash: str) -> int:
    """Query OTX for pulse count for a given hash."""
    try:
        resp = requests.get(OTX_URL.format(file_hash), headers=HEADERS, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return data.get("pulse_info", {}).get("count", 0)
    except Exception as e:
        print(f"[!] Error checking {file_hash}: {e}")
        return 0


def main() -> None:
    with open(CSV_FILE, newline="", encoding="utf-8") as infile, \
         open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as outfile:

        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        writer.writerow(["Hash", "Pulse Count"])  # Only malicious output

        # Skip header if present
        _ = next(reader, None)

        for row in reader:
            if not row:
                continue

            hash_value = row[0].strip()
            if not hash_value:
                continue

            pulse_count = get_pulse_count(hash_value)
            status = "Malicious" if pulse_count > 0 else "Clean"

            if pulse_count > 0:
                writer.writerow([hash_value, pulse_count])
                print(f"[BAD] {hash_value} -> pulses: {pulse_count}")
            else:
                print(f"[OK]  {hash_value} clean")

            time.sleep(SLEEP_SECS)


if __name__ == "__main__":
    main()
