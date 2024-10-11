import json
import base64
import re
import logging
import os
from typing import Dict, Any, List, Tuple
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def is_base64(s: str) -> bool:
    """Check if a string is likely base64 encoded."""
    try:
        decoded = base64.b64decode(s)
        printable_ratio = sum(32 <= ord(chr(byte)) <= 126 for byte in decoded) / len(decoded)
        return printable_ratio > 0.8
    except:
        return False

def find_and_decode_base64(text: str) -> List[Tuple[str, str, str]]:
    """
    Find potential base64 encoded strings in the text and decode them.
    Returns a list of tuples (original_string, decoded_string, context).
    """
    words = re.findall(r'\b[\w+/]{20,}\b=*', text)
    results = []
    for word in words:
        if is_base64(word):
            try:
                decoded = base64.b64decode(word).decode('utf-8')
                context = text[max(0, text.index(word)-50):text.index(word)+len(word)+50]
                results.append((word, decoded, context))
            except:
                pass
    return results

def analyze_decoded_content(decoded_content: str) -> Dict[str, Any]:
    """
    Use OpenAI to analyze and explain the decoded base64 content.
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert. Analyze the following decoded content and provide a detailed explanation of each line. Return your analysis as a JSON object where each key is a line number and the value is the explanation for that line."},
                {"role": "user", "content": f"Analyze and explain the following decoded content line by line:\n\n{decoded_content}"}
            ]
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        logging.error(f"Error analyzing decoded content: {e}")
        return {"error": str(e)}

def process_detection_info(detection_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process the detection information to find, decode base64 strings, and analyze the decoded content.
    """
    processed_info = detection_info.copy()
    base64_findings = []

    for key, value in detection_info.items():
        if isinstance(value, str):
            findings = find_and_decode_base64(value)
            if findings:
                for original, decoded, context in findings:
                    analysis = analyze_decoded_content(decoded)
                    base64_findings.append({
                        'field': key,
                        'original': original,
                        'decoded': decoded,
                        'context': context,
                        'analysis': analysis
                    })

    if base64_findings:
        processed_info['base64_decoded'] = base64_findings

    return processed_info

def step_1_5(detection_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 1.5: Process the detection data to find, decode base64 strings, and analyze the decoded content.
    """
    processed_data = process_detection_info(detection_data)
    
    logging.info("Processed detection information:")
    logging.info(json.dumps(processed_data, indent=2))
    
    return processed_data

if __name__ == "__main__":
    # For testing purposes, you can use the output from step_1 here
    sample_detection_data = {
        "Detection INformation": "Seen executing on a windows host",
        "File Name": "software.exe",
        "File Hash": "1d31bd48b2e864c773ca6a3b9fd0019416809066",
        "IP Address": "13.224.189.18",
        "Powershell": "JHNvdXJjZT0iaHR0cHM6Ly9hbmlnYW1lLmdnLi9zb2Z0d2FyZS5leGUiOyAkZGVzdD0iQzpcdG1wXHNvZnR3YXJlLmV4ZSI7ICRoYXNoPSJBQkNERUYxMjM0NTY3ODkwLi4uIjsgSW52b2tlLVdlYlJlcXVlc3QgLVVyaSAkc291cmNlIC1PdXRGaWxlICRkZXN0OyBpZiAoKEdldC1GaWxlSGFzaCAkZGVzdCAtQWxnb3JpdGhtIFNIQTI1NikuSGFzaCAtZXEgJGhhc2gpIHsgU3RhcnQtTXBTY2FuIC1TY2FuUGF0aCAkZGVzdCAtU2NhblR5cGUgUXVpY2tTY2FuOyBTdGFydC1Qcm9jZXNzIC1GaWxlUGF0aCAkZGVzdCAtQXJndW1lbnRMaXN0ICIvc2lsZW50IiAtV2FpdCB9IGVsc2UgeyBXcml0ZS1FcnJvciAiSGFzaCBtaXNtYXRjaCEiIH0NCg=="
    }
    result = step_1_5(sample_detection_data)
    print(json.dumps(result, indent=2))