import os
import json
import logging
from dotenv import load_dotenv
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure Google Gemini API
gemini_api_key = os.getenv("GEMINI_API_KEY")
if not gemini_api_key:
    raise ValueError("GEMINI_API_KEY not found in environment variables.")

genai.configure(api_key=gemini_api_key)

# Create the Gemini model
generation_config = {
    "temperature": 0.7,
    "top_p": 0.95,
    "top_k": 40,
    "max_output_tokens": 8192,
}

model = genai.GenerativeModel(
    model_name="gemini-1.5-pro-002",
    generation_config=generation_config,
)

def read_report() -> str:
    """Read the contents of the report.txt file."""
    try:
        with open("report.txt", "r") as file:
            return file.read()
    except FileNotFoundError:
        logging.error("report.txt file not found.")
        return ""
    except Exception as e:
        logging.error(f"Error reading report.txt: {e}")
        return ""

def generate_overview(report_content: str) -> str:
    """
    Generate an overview of the report using Google Gemini.
    """
    try:
        prompt = f"""
        As a cybersecurity expert, please provide a comprehensive overview of the following investigation report. 
        Focus on the key findings, potential threats, and recommended actions. 
        Summarize the most important aspects of each step in the investigation process.

        Report Content:
        {report_content}

        Please structure your overview as follows:
        1. Executive Summary
        2. Key Findings
        3. Potential Threats
        4. Recommended Actions
        5. Conclusion
        """

        # Define safety settings to allow all content
        safety_settings = {
            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
        }

        response = model.generate_content(
            [prompt],
            safety_settings=safety_settings,
        )

        if response.text:
            logging.info("Successfully generated report overview.")
            return response.text
        else:
            logging.warning("Generated overview is empty.")
            return "Unable to generate overview. The response was empty."

    except Exception as e:
        logging.error(f"Error generating overview: {e}")
        return f"An error occurred while generating the overview: {str(e)}"

def step_4() -> str:
    """
    step 4: Generate an overview of the full investigation report.
    """
    logging.info("Starting step 4: Generating report overview")
    
    report_content = read_report()
    if not report_content:
        logging.error("Failed to read report content. Exiting step 4.")
        return "Failed to generate overview: No report content found."
    
    overview = generate_overview(report_content)
    
    # Write the overview to a new file
    try:
        with open("report_overview.txt", "w") as overview_file:
            overview_file.write(overview)
        logging.info("Overview written to report_overview.txt")
    except Exception as e:
        logging.error(f"Error writing overview to file: {e}")
    
    return overview

if __name__ == "__main__":
    result = step_4()
    print(result)