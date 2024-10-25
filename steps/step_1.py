import json
import os
import base64
import re
import logging
from dotenv import load_dotenv
from openai import OpenAI
from typing import Dict, Any, Tuple

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file
load_dotenv()

# Initialize OpenAI client with API key from environment variable
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def read_detection_info() -> str:
    """Read detection information from detection.txt file."""
    try:
        with open("detection.txt", "r") as file:
            content = file.read().strip()
        if not content:
            logging.warning("detection.txt is empty.")
            return ""
        logging.info(f"Successfully read detection.txt. Content length: {len(content)} characters.")
        return content
    except FileNotFoundError:
        logging.error("Error: detection.txt file not found.")
        return ""
    except Exception as e:
        logging.error(f"Error reading detection.txt: {e}")
        return ""

def is_base64(s: str) -> bool:
    """Check if a string is base64 encoded."""
    pattern = r'^[A-Za-z0-9+/]+={0,2}$'
    return bool(re.match(pattern, s)) and len(s) % 4 == 0

def detect_and_decode_base64(text: str) -> Tuple[str, bool]:
    """
    Detect if the input string is base64 encoded and decode it if so.
    Returns a tuple of (decoded_text, was_encoded).
    """
    if is_base64(text):
        try:
            decoded = base64.b64decode(text).decode('utf-8')
            logging.info("Successfully decoded base64 content.")
            return decoded, True
        except Exception as e:
            logging.warning(f"Failed to decode potential base64 content: {e}")
    return text, False

def parse_detection_info(detection_info: str) -> Dict[str, Any]:
    """Parse the detection information into a structured dictionary."""
    lines = detection_info.split('\n')
    parsed_info = {}
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            parsed_info[key.strip()] = value.strip()
    return parsed_info

def analyze_detection_info(detection_info: str) -> Dict[str, Any]:
    """
    Parse the detection information without decoding base64 content.
    """
    parsed_info = parse_detection_info(detection_info)
    
    try:
        response = client.chat.completions.create(
            model="gpt-4-mini",  
            response_format={ "type": "json_object" },
            messages=[
                {"role": "system", "content": "You are a helpful assistant that analyzes detection information and returns a structured JSON object."},
                {"role": "user", "content": f"Analyze the following detection information and return a JSON object with relevant fields: {json.dumps(parsed_info)}"}
            ]
        )
        
        result = json.loads(response.choices[0].message.content)
        logging.info("Successfully analyzed detection information.")
        return result
    except Exception as e:
        logging.error(f"Error analyzing detection information: {e}")
        return parsed_info  # Return the parsed info even if analysis fails

def step_1() -> Dict[str, Any]:
    """
    Step 1: Read detection information from file and analyze it.
    """
    detection_info = read_detection_info()
    if not detection_info:
        logging.warning("No detection information found. Exiting step 1.")
        return {}
    
    analyzed_data = analyze_detection_info(detection_info)
    
    if analyzed_data:
        logging.info("Analyzed detection information:")
        logging.info(json.dumps(analyzed_data, indent=2))
    else:
        logging.warning("Failed to analyze detection information.")
    
    return analyzed_data

if __name__ == "__main__":
    logging.info("Starting step 1...")
    result = step_1()
    if result:
        logging.info("Step 1 completed successfully.")
    else:
        logging.warning("Step 1 completed with no results.")
