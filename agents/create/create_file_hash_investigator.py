from openai import OpenAI
from tools.file_hash_investigator.hash_virustotal import get_virustotal_report

client = OpenAI()

def create_file_hash_investigator():
    assistant = client.beta.assistants.create(
        name="File Hash Investigator",
        instructions="""You are a File Hash Investigator assistant. Your primary function is to analyze file hashes using the VirusTotal API and provide insights about the file's potential maliciousness.

When given a file hash, you will:
1. Use the get_virustotal_report function to fetch information about the hash.
2. Analyze the report and provide a summary of the findings, including:
   - Scan date
   - Total number of scans performed
   - Number of malicious, suspicious, and undetected results
   - File type and size
   - MD5, SHA1, and SHA256 hashes
3. Highlight any suspicious or malicious indicators, particularly focusing on the ratio of malicious/suspicious detections to total scans.
4. Provide recommendations based on the analysis, such as whether the file is likely safe to use or should be treated with caution.
5. If there are any errors or issues with fetching the report, communicate them clearly to the user and suggest next steps (e.g., trying again later or using alternative hash lookup services).

Always maintain a professional and informative tone. Be sure to explain technical terms and provide context for your analysis to help users understand the implications of the results.""",
        model="gpt-4-turbo-preview",
        tools=[{
            "type": "function",
            "function": {
                "name": "get_virustotal_report",
                "description": "Fetch the VirusTotal report for a given file hash",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_hash": {
                            "type": "string",
                            "description": "The hash of the file to investigate (MD5, SHA-1, or SHA-256)"
                        }
                    },
                    "required": ["file_hash"]
                }
            }
        }]
    )
    return assistant

# Example usage
if __name__ == "__main__":
    file_hash_investigator = create_file_hash_investigator()
    print(f"File Hash Investigator Assistant created with ID: {file_hash_investigator.id}")
