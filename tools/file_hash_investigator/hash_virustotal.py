import os
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get the VirusTotal API key from the environment variable
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def get_virustotal_report(file_hash):
    """
    Retrieve the VirusTotal report for a given file hash.
    
    :param file_hash: The hash of the file to investigate
    :return: A dictionary containing the VirusTotal report information
    """
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Extract relevant information from the response
        attributes = data["data"]["attributes"]
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        result = {
            "scan_date": attributes.get("last_analysis_date"),
            "total_scans": sum(last_analysis_stats.values()),
            "malicious": last_analysis_stats.get("malicious", 0),
            "suspicious": last_analysis_stats.get("suspicious", 0),
            "undetected": last_analysis_stats.get("undetected", 0),
            "file_type": attributes.get("type_description"),
            "file_size": attributes.get("size"),
            "md5": attributes.get("md5"),
            "sha1": attributes.get("sha1"),
            "sha256": attributes.get("sha256"),
        }

        return result
    except requests.exceptions.RequestException as e:
        return {"error": f"Error fetching VirusTotal report: {str(e)}"}
    except KeyError as e:
        return {"error": f"Unexpected response structure from VirusTotal: {str(e)}"}

# Example usage
if __name__ == "__main__":
    test_hash = "44d88612fea8a8f36de82e1278abb02f"
    print(get_virustotal_report(test_hash))
