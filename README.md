OTX Hash Checker

Reads hashes from the first column of hashlist.csv, checks them against AlienVault OTX, and writes only malicious hashes to output.csv.

Input: hashlist.csv
Output: output.csv

How it works:

1. Read hash
2. Check against OTX
3. Save only if malicious

Instructions

1. Install Python 3.
2. Install required libraries from requirements.txt.
3. Edit the script before running:
   * Update the file path where hashes are stored.
   * Change API key variable to your own API key.
   * Set your output file name if needed.
4. Run the tool using `python scriptname.py`.
5. View the results in the generated output file.
