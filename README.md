# IP_VT_CTI_Abuse
Check the maliciousness of the IPs using VirusTotal, CTI ThreatBook and AbuseIPDB.
Certainly! Here is a README file for your code:

---

# IP Threat Analysis Tool

## Overview

This Python script is designed to analyze IP addresses for potential threats using various external APIs. It retrieves information from AbuseIPDB, VirusTotal, and ThreatBook to provide insights into the potential malicious activities associated with the given IP addresses.

## Features

- **AbuseIPDB Analysis:** Retrieves abuse confidence score, number of reports, and last update information for each IP address.

- **VirusTotal Analysis:** Fetches malicious count, ASN owner, and country information for each IP address.

- **ThreatBook (CTI) Analysis:** Determines judgments values and final verdict for each IP address.

- **Time Elapsed Calculation:** Calculates the time elapsed since the last reported activity for each IP address.

- **Results Output:** The analysis results are stored in an Excel file in the "Result" folder, with a timestamp in the filename.

## Prerequisites

- Python 3.x
- Required Python libraries: `requests`, `pandas`, `datetime`, `colorama`

## Setup

1. Clone the repository or download the script.
2. Install the required libraries using `pip install -r requirements.txt`.
3. Obtain API keys for AbuseIPDB, VirusTotal, and ThreatBook (CTI) and replace placeholders in the script with your keys.
4. Prepare an input Excel file (`input.xlsx`) containing a list of IP addresses.

## Usage

Run the script using the command:

```bash
python threat_analysis.py
```

## Output

The results will be saved in the "Result" folder as an Excel file with a timestamp in the filename.

## Notes

- Ensure that your API keys are kept confidential and not shared publicly.
- It is recommended to run the script in a virtual environment.

## Author

[Your Name]

## License

This project is licensed under the [MIT License](LICENSE).

---

Make sure to replace "[Your Name]" with your actual name, and you can customize the sections based on your preferences. Also, consider adding a license file (e.g., `LICENSE`) if you haven't already.
