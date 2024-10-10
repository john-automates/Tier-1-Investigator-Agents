import json
import os
import time
import logging
from openai import OpenAI
from typing import Dict, Any
from dotenv import load_dotenv
from tools.ip_address_investigator.ip_shodan import check_ip_reputation, get_geolocation
from tools.file_hash_investigator.hash_virustotal import get_virustotal_report
from tools.website_crawler.crawl_website import advanced_search_scrape_and_summarize

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("investigation.log")
    ]
)

# Load environment variables
load_dotenv()

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Get assistant IDs from environment variables
IP_INVESTIGATOR_ID = os.getenv("IP_INVESTIGATOR_ID")

if not IP_INVESTIGATOR_ID:
    logging.error("IP_INVESTIGATOR_ID not found in environment variables.")
    raise EnvironmentError("IP_INVESTIGATOR_ID not found in environment variables.")

# Function mapping
FUNCTION_MAPPING = {
    "check_ip_reputation": check_ip_reputation,
    "get_geolocation": get_geolocation,
    "get_virustotal_report": get_virustotal_report,
    "advanced_search": advanced_search_scrape_and_summarize
}

def create_thread():
    try:
        thread = client.beta.threads.create()
        logging.info(f"Created thread with ID: {thread.id}")
        return thread
    except Exception as e:
        logging.error(f"Failed to create thread: {e}", exc_info=True)
        raise

def add_message_to_thread(thread_id: str, content: str):
    try:
        client.beta.threads.messages.create(
            thread_id=thread_id,
            role="user",
            content=f"Please provide your response in JSON format. Here's the content: {content}"
        )
        logging.info(f"Added message to thread {thread_id}")
    except Exception as e:
        logging.error(f"Failed to add message to thread {thread_id}: {e}", exc_info=True)
        raise

def run_assistant(assistant_id: str, thread_id: str):
    try:
        run = client.beta.threads.runs.create(
            thread_id=thread_id,
            assistant_id=assistant_id,
            instructions="Please provide your response in JSON format.",
        )
        logging.info(f"Started run with ID: {run.id} for assistant ID: {assistant_id}")
        return run.id
    except Exception as e:
        logging.error(f"Failed to start assistant run: {e}", exc_info=True)
        raise

def get_run_status(thread_id: str, run_id: str):
    try:
        run_status = client.beta.threads.runs.retrieve(thread_id=thread_id, run_id=run_id)
        logging.info(f"Run status for run ID {run_id}: {run_status.status}")
        return run_status
    except Exception as e:
        logging.error(f"Failed to retrieve run status for run ID {run_id}: {e}", exc_info=True)
        raise

def get_messages(thread_id: str):
    try:
        messages = client.beta.threads.messages.list(thread_id=thread_id)
        logging.info(f"Retrieved {len(messages.data)} messages from thread {thread_id}")
        return messages
    except Exception as e:
        logging.error(f"Failed to retrieve messages from thread {thread_id}: {e}", exc_info=True)
        raise

def handle_tool_calls(thread_id: str, run_id: str, tool_calls):
    tool_outputs = []
    for tool_call in tool_calls:
        function_name = tool_call.function.name
        arguments = json.loads(tool_call.function.arguments)
        logging.info(f"Handling tool call: {function_name} with arguments: {arguments}")
        
        if function_name in FUNCTION_MAPPING:
            try:
                result = FUNCTION_MAPPING[function_name](**arguments)
                tool_outputs.append({
                    "tool_call_id": tool_call.id,
                    "output": json.dumps(result)
                })
                logging.info(f"Tool call {function_name} completed successfully")
            except Exception as e:
                logging.error(f"Error in tool call {function_name}: {e}", exc_info=True)
                tool_outputs.append({
                    "tool_call_id": tool_call.id,
                    "output": json.dumps({"error": str(e)})
                })
        else:
            logging.warning(f"Unknown function call: {function_name}")
            tool_outputs.append({
                "tool_call_id": tool_call.id,
                "output": json.dumps({"error": f"Unknown function {function_name}"})
            })

    if tool_outputs:
        try:
            client.beta.threads.runs.submit_tool_outputs(
                thread_id=thread_id,
                run_id=run_id,
                tool_outputs=tool_outputs
            )
            logging.info("Tool outputs submitted successfully")
        except Exception as e:
            logging.error(f"Failed to submit tool outputs: {e}", exc_info=True)

def process_step(step: Dict[str, Any]) -> Dict[str, Any]:
    logging.info(f"Processing step: {step['title']}")
    
    thread = create_thread()
    add_message_to_thread(thread.id, json.dumps(step))
    
    run_id = run_assistant(IP_INVESTIGATOR_ID, thread.id)
    
    while True:
        run_status = get_run_status(thread.id, run_id)
        if run_status.status == 'completed':
            break
        elif run_status.status == 'requires_action':
            handle_tool_calls(thread.id, run_id, run_status.required_action.submit_tool_outputs.tool_calls)
        time.sleep(1)
    
    messages = get_messages(thread.id)
    for message in reversed(messages.data):
        if message.role == "assistant":
            try:
                return json.loads(message.content[0].text.value)
            except json.JSONDecodeError:
                logging.error("Failed to parse assistant's response as JSON")
                return {"error": "Failed to parse response"}
    
    return {"error": "No response from assistant"}

def step_3(investigation_plan: Dict[str, Any]) -> Dict[str, Any]:
    logging.info("Starting step 3 of the investigation process")
    results = {}
    
    for step_key, step in investigation_plan.items():
        results[step_key] = process_step(step)
        
        # Write intermediate results to report.txt
        with open("report.txt", "a") as report_file:
            report_file.write(f"\n--- {step_key}: {step['title']} ---\n")
            json.dump(results[step_key], report_file, indent=2)
            report_file.write("\n")
        
        logging.info(f"Completed {step_key}")
    
    logging.info("Completed step 3 of the investigation process")
    return results

if __name__ == "__main__":
    # Sample investigation plan for testing
    sample_plan = {
        "step_1": {
            "title": "Analyze File Hash",
            "ioc": "3A7F1E2B4C5D6E7F8G9H0I1J2K3L4M5N6O7P8Q9R0S1T2U3V4W5X6Y7Z8A9B0C1D",
            "ioc_type": "File Hash",
            "tool": {"name": "get_virustotal_report"}
        },
        "step_2": {
            "title": "Investigate IP Reputation",
            "ioc": "192.168.100.55",
            "ioc_type": "IP Address",
            "tool": {"name": "check_ip_reputation"}
        }
    }
    results = step_3(sample_plan)
    print(json.dumps(results, indent=2))