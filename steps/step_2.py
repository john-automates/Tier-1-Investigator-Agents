import json
import os
from openai import OpenAI
from typing import Dict, Any

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Initialize OpenAI client with API key from environment variable
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def create_investigation_plan(detection_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a detailed OSINT-focused investigation plan based on the detection data.
    """
    try:
        prompt = f"""
        Based on the following detection information, create a detailed step-by-step plan for an OSINT (Open Source Intelligence) investigation of the Indicators of Compromise (IOCs). 
        Focus on gathering information from publicly available sources before any active system investigation.
        Each step should be specific, actionable, and focused on a particular aspect of OSINT investigation.

        Detection Information:
        {json.dumps(detection_data, indent=2)}

        Provide the OSINT investigation plan as a JSON object with the following structure:
        {{
            "step_1": {{
                "title": "Step title",
                "description": "Detailed description of the step",
                "ioc": "The specific IOC being investigated",
                "ioc_type": "Type of the IOC (e.g., File Hash, IP Address, Process Name)",
                "resources": [
                    {{
                        "name": "Resource name",
                        "url": "Resource URL"
                    }},
                    // ... more resources
                ]
            }},
            "step_2": {{
                // Similar structure
            }},
            // ... more steps as needed
        }}

        Ensure the plan covers all relevant IOCs and focuses on OSINT techniques before any internal system investigation.
        Include steps for searching threat intelligence databases, analyzing the file hash, investigating the IP address, and any other relevant OSINT activities.
        Provide specific, real-world resources (with URLs) for each step.
        """

        response = client.chat.completions.create(
            model="gpt-4o",
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in OSINT investigations."},
                {"role": "user", "content": prompt}
            ]
        )
        
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"Error creating OSINT investigation plan: {e}")
        return {}

def step_2(detection_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 2: Create a detailed OSINT-focused investigation plan based on the detection data.
    """
    investigation_plan = create_investigation_plan(detection_data)
    
    print("OSINT Investigation Plan:")
    print(json.dumps(investigation_plan, indent=2))
    
    return investigation_plan

if __name__ == "__main__":
    # For testing purposes
    sample_detection_data = {
        "detection_id": "DETECT-2024-10-05-001",
        "severity": "High",
        "detection_type": "Unauthorized Ransomware Activity",
        "iocs": {
            "process_name": "encryptor.exe",
            "file_hash": "3A7F1E2B4C5D6E7F8G9H0I1J2K3L4M5N6O7P8Q9R0S1T2U3V4W5X6Y7Z8A9B0C1D",
            "network_activity": "Outbound connection to 192.168.100.55:443"
        }
    }
    step_2(sample_detection_data)
