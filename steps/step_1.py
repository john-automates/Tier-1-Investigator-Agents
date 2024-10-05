import json
import os
from dotenv import load_dotenv
from openai import OpenAI
from typing import Dict, Any

# Load environment variables from .env file
load_dotenv()

# Initialize OpenAI client with API key from environment variable
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def read_detection_info() -> str:
    """Read detection information from detection.txt file."""
    try:
        with open("detection.txt", "r") as file:
            return file.read().strip()
    except FileNotFoundError:
        print("Error: detection.txt file not found.")
        return ""
    except Exception as e:
        print(f"Error reading detection.txt: {e}")
        return ""

def analyze_detection_info(detection_info: str) -> Dict[str, Any]:
    """
    Use OpenAI to analyze the detection information and return a structured JSON object.
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            response_format={ "type": "json_object" },
            messages=[
                {"role": "system", "content": "You are a helpful assistant that analyzes detection information and returns a structured JSON object."},
                {"role": "user", "content": f"Analyze the following detection information and return a JSON object with relevant fields: {detection_info}"}
            ]
        )
        
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"Error analyzing detection information: {e}")
        return {}

def step_1() -> Dict[str, Any]:
    """
    Step 1: Read detection information from file and analyze it.
    """
    detection_info = read_detection_info()
    if not detection_info:
        return {}
    
    analyzed_data = analyze_detection_info(detection_info)
    
    print("Analyzed detection information:")
    print(json.dumps(analyzed_data, indent=2))
    
    return analyzed_data

if __name__ == "__main__":
    step_1()
