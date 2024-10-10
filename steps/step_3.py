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
openai_api_key = os.getenv("OPENAI_API_KEY")
if not openai_api_key:
    logging.error("OPENAI_API_KEY not found in environment variables.")
    raise EnvironmentError("OPENAI_API_KEY not found in environment variables.")

client = OpenAI(api_key=openai_api_key)

# Get assistant IDs from environment variables
LEAD_ASSISTANT_ID = os.getenv("LEAD_ASSISTANT_ID")
IP_INVESTIGATOR_ID = os.getenv("TIER1_ASSISTANT_ID")
FILE_HASH_INVESTIGATOR_ID = os.getenv("FILE_HASH_INVESTIGATOR_ID")

if not LEAD_ASSISTANT_ID:
    logging.error("LEAD_ASSISTANT_ID not found in environment variables.")
    raise EnvironmentError("LEAD_ASSISTANT_ID not found in environment variables.")
if not IP_INVESTIGATOR_ID:
    logging.warning("TIER1_ASSISTANT_ID not found in environment variables. IP Investigator may not function correctly.")
if not FILE_HASH_INVESTIGATOR_ID:
    logging.warning("FILE_HASH_INVESTIGATOR_ID not found in environment variables. File Hash Investigator may not function correctly.")

# Helper Functions

def create_thread():
    """Create a new thread for the investigation."""
    try:
        thread = client.beta.threads.create()
        logging.info(f"Created thread with ID: {thread.id}")
        return thread
    except Exception as e:
        logging.error(f"Failed to create thread: {e}", exc_info=True)
        raise

def add_message_to_thread(thread_id: str, content: str):
    """Add a message to the thread."""
    try:
        client.beta.threads.messages.create(
            thread_id=thread_id,
            role="user",
            content=content
        )
        logging.debug(f"Added message to thread {thread_id}: {content[:100]}...")  # Log first 100 characters
    except Exception as e:
        logging.error(f"Failed to add message to thread {thread_id}: {e}", exc_info=True)
        raise

def run_assistant(assistant_id: str, thread_id: str):
    """Run the assistant on the thread."""
    try:
        run = client.beta.threads.runs.create(
            thread_id=thread_id,
            assistant_id=assistant_id
        )
        logging.info(f"Started run with ID: {run.id} for assistant ID: {assistant_id}")
        return run.id
    except Exception as e:
        logging.error(f"Failed to start assistant run: {e}", exc_info=True)
        raise

def get_run_status(thread_id: str, run_id: str):
    """Get the status of a run."""
    try:
        run_status = client.beta.threads.runs.retrieve(thread_id=thread_id, run_id=run_id)
        logging.debug(f"Retrieved run status for run ID {run_id}: {run_status.status}")
        return run_status
    except Exception as e:
        logging.error(f"Failed to retrieve run status for run ID {run_id}: {e}", exc_info=True)
        raise

def get_messages(thread_id: str):
    """Get messages from the thread."""
    try:
        messages = client.beta.threads.messages.list(thread_id=thread_id)
        logging.debug(f"Retrieved {len(messages.data)} messages from thread {thread_id}.")
        return messages
    except Exception as e:
        logging.error(f"Failed to retrieve messages from thread {thread_id}: {e}", exc_info=True)
        raise

def get_virustotal_report_handler(file_hash: str) -> str:
    """
    Fetch the VirusTotal report for a given file hash using the File Hash Investigator's tools.
    """
    try:
        report = get_virustotal_report(file_hash)
        logging.debug(f"VirusTotal report for {file_hash}: {report}")
        return json.dumps(report)
    except Exception as e:
        logging.error(f"Error fetching VirusTotal report for {file_hash}: {e}", exc_info=True)
        return json.dumps({"error": str(e)})

def handle_investigate_ip_address(arguments: Dict[str, Any], tool_call_id: str) -> str:
    """
    Handle the 'investigate_ip_address' function call.
    """
    ip_address = arguments.get("ip_address")
    if not ip_address:
        logging.error(f"No 'ip_address' provided for tool call ID: {tool_call_id}")
        return json.dumps({"error": "Missing 'ip_address' argument."})
    
    logging.info(f"Investigating IP address: {ip_address}")
    try:
        reputation_data = check_ip_reputation(ip_address)
        geolocation_data = get_geolocation(ip_address)
        combined_result = {
            "reputation": reputation_data,
            "geolocation": geolocation_data
        }
        logging.debug(f"Combined IP result for {ip_address}: {combined_result}")
        return json.dumps(combined_result)
    except Exception as e:
        logging.error(f"Error investigating IP address {ip_address} for tool call ID {tool_call_id}: {e}", exc_info=True)
        return json.dumps({"error": str(e)})

def handle_get_virustotal_report(arguments: Dict[str, Any], tool_call_id: str) -> str:
    """
    Handle the 'get_virustotal_report' function call.
    """
    file_hash = arguments.get("file_hash")
    if not file_hash:
        logging.error(f"No 'file_hash' provided for tool call ID: {tool_call_id}")
        return json.dumps({"error": "Missing 'file_hash' argument."})
    
    logging.info(f"Fetching VirusTotal report for file hash: {file_hash}")
    report = get_virustotal_report_handler(file_hash)
    logging.debug(f"VirusTotal report for {file_hash}: {report}")
    return report

def handle_advanced_search(arguments: Dict[str, Any], tool_call_id: str) -> str:
    """
    Handle the 'advanced_search' function call.
    """
    query = arguments.get("query")
    if not query:
        logging.error(f"No 'query' provided for tool call ID: {tool_call_id}")
        return json.dumps({"error": "Missing 'query' argument."})
    
    logging.info(f"Performing advanced search for query: '{query}'")
    try:
        result = advanced_search_scrape_and_summarize(query)
        if isinstance(result, str):
            if "error" in result.lower():
                logging.warning(f"Advanced search returned an error for query: '{query}'.")
            else:
                logging.debug(f"Advanced search result: {result[:500]}...")  # Log first 500 characters
        return json.dumps({"summary": result})
    except Exception as e:
        logging.error(f"Error performing advanced search for query '{query}': {e}", exc_info=True)
        return json.dumps({"error": str(e)})

# Define a mapping between function names and their handlers
FUNCTION_HANDLERS = {
    "investigate_ip_address": handle_investigate_ip_address,
    "get_virustotal_report": handle_get_virustotal_report,
    "advanced_search": handle_advanced_search  # Correctly mapped key
}

def handle_tool_calls(thread_id: str, run_id: str, tool_calls):
    """
    Handle multiple tool calls by delegating them to the appropriate handlers.
    """
    tool_outputs = []
    for tool_call in tool_calls:
        function_name = tool_call.function.name
        tool_call_id = tool_call.id
        try:
            arguments = json.loads(tool_call.function.arguments)
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON arguments for tool call ID: {tool_call_id}: {e}")
            tool_outputs.append({
                "tool_call_id": tool_call_id,
                "output": json.dumps({"error": "Invalid JSON arguments."})
            })
            continue

        logging.info(f"Received tool call: '{function_name}' with ID: {tool_call_id} and arguments: {arguments}")

        handler = FUNCTION_HANDLERS.get(function_name)
        if handler:
            try:
                output = handler(arguments, tool_call_id)
                logging.info(f"Handler output for tool call ID '{tool_call_id}': {output}")
                tool_outputs.append({
                    "tool_call_id": tool_call_id,
                    "output": output
                })
            except Exception as e:
                logging.error(f"Error handling tool call '{function_name}' with ID '{tool_call_id}': {e}", exc_info=True)
                tool_outputs.append({
                    "tool_call_id": tool_call_id,
                    "output": json.dumps({"error": str(e)})
                })
        else:
            logging.warning(f"Unknown function call: '{function_name}' for tool call ID: {tool_call_id}")
            tool_outputs.append({
                "tool_call_id": tool_call_id,
                "output": json.dumps({"error": f"Unknown function '{function_name}'."})
            })

    if tool_outputs:
        logging.info(f"Submitting tool outputs: {json.dumps(tool_outputs, indent=2)}")
        try:
            client.beta.threads.runs.submit_tool_outputs(
                thread_id=thread_id,
                run_id=run_id,
                tool_outputs=tool_outputs
            )
            logging.info("Tool outputs submitted successfully.")
        except Exception as e:
            logging.error(f"Failed to submit tool outputs: {e}", exc_info=True)

def step_3(investigation_plan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute step 3 of the investigation process by processing each step in the investigation plan sequentially.
    """
    logging.info("Starting step 3 of the investigation process (Sequential Processing)")
    final_results = {}
    report_lines = []

    # Initialize or clear report.txt at the beginning
    with open("report.txt", "a") as report_file:
        report_file.write("\n\n--- Step 3: Investigation Results ---\n")
    logging.info("Initialized report.txt for step 3.")

    for step_key, step in investigation_plan.items():
        logging.info(f"Processing {step_key}: {step['title']}")

        try:
            thread = create_thread()
        except Exception as e:
            logging.error(f"Failed to create thread for {step_key}: {e}", exc_info=True)
            final_results[step_key] = {"error": "Failed to create thread."}
            continue  # Proceed to the next step

        # Add the current step to the thread
        try:
            add_message_to_thread(thread.id, f"Here's the investigation step: {json.dumps(step, indent=2)}")
            logging.debug(f"Added {step_key} to thread {thread.id}.")
        except Exception as e:
            logging.error(f"Failed to add {step_key} to thread {thread.id}: {e}", exc_info=True)
            final_results[step_key] = {"error": f"Failed to add step to thread: {e}"}
            continue  # Proceed to the next step

        # Add the investigation instructions to the thread
        instructions = (
            f"Please perform the following investigation step: {step['title']}. "
            f"IOC: {step['ioc']} (Type: {step['ioc_type']}). "
            "Provide the results in JSON format."
        )
        try:
            add_message_to_thread(thread.id, instructions)
            logging.debug(f"Added instructions for {step_key} to thread.")
        except Exception as e:
            logging.error(f"Failed to add instructions to thread {thread.id}: {e}", exc_info=True)
            final_results[step_key] = {"error": f"Failed to add instructions: {e}"}
            continue  # Proceed to the next step

        # Run the lead assistant
        try:
            run_id = run_assistant(LEAD_ASSISTANT_ID, thread.id)
        except Exception as e:
            logging.error(f"Failed to start lead assistant run for {step_key}: {e}", exc_info=True)
            final_results[step_key] = {"error": "Failed to start lead assistant run."}
            continue  # Proceed to the next step

        # Wait for the run to complete
        while True:
            try:
                run_status = get_run_status(thread.id, run_id)
            except Exception as e:
                logging.error(f"Failed to get run status for run ID {run_id} of {step_key}: {e}", exc_info=True)
                final_results[step_key] = {"error": "Failed to get run status."}
                break  # Exit the loop for this step

            logging.info(f"Run status for {step_key}: {run_status.status}")
            if run_status.status == 'completed':
                logging.info(f"Run for {step_key} completed.")
                break
            elif run_status.status == 'requires_action':
                tool_calls = run_status.required_action.submit_tool_outputs.tool_calls
                function_names = [call.function.name for call in tool_calls]
                logging.info(f"Run for {step_key} requires action with tool calls: {function_names}")
                handle_tool_calls(thread.id, run_id, tool_calls)
            else:
                logging.info(f"Run for {step_key} is still in progress.")
            # Add a small delay to avoid excessive API calls
            time.sleep(1)

        # Get the investigation results
        try:
            messages = get_messages(thread.id)
            logging.info(f"Retrieved {len(messages.data)} messages from thread {thread.id} for {step_key}.")
        except Exception as e:
            logging.error(f"Failed to retrieve messages from thread {thread.id} for {step_key}: {e}", exc_info=True)
            final_results[step_key] = {"error": "Failed to retrieve investigation results."}
            continue  # Proceed to the next step

        # Extract the final report from the assistant's messages
        investigation_results = {}
        for message in reversed(messages.data):
            if message.role == "assistant":
                logging.info(f"Processing assistant message for {step_key}.")
                try:
                    if isinstance(message.content, str):
                        # Direct JSON string
                        investigation_results = json.loads(message.content)
                        logging.info(f"Parsed JSON content from assistant message for {step_key}.")
                    elif isinstance(message.content, list):
                        # Extract text from TextContentBlock objects
                        content_str = ''.join([
                            segment.text.value for segment in message.content
                            if hasattr(segment, 'text') and hasattr(segment.text, 'value')
                        ])
                        logging.debug(f"Extracted content string from TextContentBlock for {step_key}: {content_str[:500]}...")
                        # Parse the JSON string
                        investigation_results = json.loads(content_str)
                        logging.info(f"Parsed JSON content from TextContentBlock for {step_key}.")
                    else:
                        # Fallback to summary
                        content_str = str(message.content)
                        investigation_results = {"summary": content_str}
                        logging.warning(f"Fallback summary created from message content for {step_key}.")
                    logging.info(f"Final investigation results for {step_key}: {json.dumps(investigation_results, indent=2)}")
                    break  # Exit after processing the latest assistant message
                except (json.JSONDecodeError, AttributeError) as e:
                    logging.error(f"Failed to parse message content for {step_key}: {e}", exc_info=True)
                    investigation_results = {"summary": "Failed to parse investigation results."}
                    break

        final_results[step_key] = investigation_results

        # Optionally, write intermediate results to report.txt
        report_line = f"--- {step_key}: {step['title']} ---\n{json.dumps(investigation_results, indent=2)}\n\n"
        report_lines.append(report_line)
        try:
            with open("report.txt", "a") as report_file:
                report_file.write(report_line)
            logging.info(f"Written results for {step_key} to report.txt.")
        except Exception as e:
            logging.error(f"Failed to write results to report.txt for {step_key}: {e}", exc_info=True)

    logging.info("Completed step 3 of the investigation process.")
    return final_results

# Example usage (Uncomment the following lines to run the script directly)
if __name__ == "__main__":
    # Configure logging for standalone execution
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Define your investigation plan here
    investigation_plan = {
        "step_4": {
            "title": "Advanced Web Search on Process Name",
            "ioc": "encryptor.exe",
            "ioc_type": "Process Name",
            "results": {}
        },
        "step_5": {
            "title": "Investigate Registry Changes",
            "ioc": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "ioc_type": "Registry Key",
            "results": {}
        }
    }
    final_results = step_3(investigation_plan)
    # Optionally, print the final results
    print(json.dumps(final_results, indent=2))