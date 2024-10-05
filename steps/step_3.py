import json
import os
import time
import logging
from openai import OpenAI
from typing import Dict, Any
from dotenv import load_dotenv
from tools.ip_address_investigator.ip_shodan import check_ip_reputation, get_geolocation

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Get assistant IDs from environment variables
LEAD_ASSISTANT_ID = os.getenv("LEAD_ASSISTANT_ID")
IP_INVESTIGATOR_ID = os.getenv("IP_INVESTIGATOR_ID")

def create_thread():
    """Create a new thread for the investigation."""
    return client.beta.threads.create()

def add_message_to_thread(thread_id: str, content: str):
    """Add a message to the thread."""
    client.beta.threads.messages.create(
        thread_id=thread_id,
        role="user",
        content=content
    )

def run_assistant(assistant_id: str, thread_id: str):
    """Run the assistant on the thread."""
    run = client.beta.threads.runs.create(
        thread_id=thread_id,
        assistant_id=assistant_id
    )
    return run.id

def get_run_status(thread_id: str, run_id: str):
    """Get the status of a run."""
    return client.beta.threads.runs.retrieve(thread_id=thread_id, run_id=run_id)

def get_messages(thread_id: str):
    """Get messages from the thread."""
    return client.beta.threads.messages.list(thread_id=thread_id)

def investigate_ip_address(ip_address: str) -> str:
    """Use the IP Address Investigator's tools to investigate an IP address."""
    reputation_data = check_ip_reputation(ip_address)
    geolocation_data = get_geolocation(ip_address)
    
    combined_result = {
        "reputation": reputation_data,
        "geolocation": geolocation_data
    }
    
    return json.dumps(combined_result)

def handle_tool_calls(thread_id: str, run_id: str, tool_calls):
    """Handle multiple tool calls."""
    tool_outputs = []
    for tool_call in tool_calls:
        function_name = tool_call.function.name
        arguments = json.loads(tool_call.function.arguments)
        logger.info(f"Handling tool call: {function_name} with arguments {arguments}")
        
        if function_name == "investigate_ip_address":
            ip_address = arguments["ip_address"]
            logger.info(f"Investigating IP address: {ip_address}")
            reputation_data = check_ip_reputation(ip_address)
            geolocation_data = get_geolocation(ip_address)
            combined_result = {
                "reputation": reputation_data,
                "geolocation": geolocation_data
            }
            tool_outputs.append({
                "tool_call_id": tool_call.id,
                "output": json.dumps(combined_result)
            })
            logger.info(f"Combined result: {combined_result}")
        
        elif function_name == "check_ip_reputation":
            ip_address = arguments["ip_address"]
            logger.info(f"Checking reputation for IP address: {ip_address}")
            reputation_data = check_ip_reputation(ip_address)
            tool_outputs.append({
                "tool_call_id": tool_call.id,
                "output": json.dumps(reputation_data)
            })
            logger.info(f"Reputation data: {reputation_data}")
        
        elif function_name == "get_geolocation":
            ip_address = arguments["ip_address"]
            logger.info(f"Getting geolocation for IP address: {ip_address}")
            geolocation_data = get_geolocation(ip_address)
            tool_outputs.append({
                "tool_call_id": tool_call.id,
                "output": json.dumps(geolocation_data)
            })
            logger.info(f"Geolocation data: {geolocation_data}")
        
        else:
            logger.warning(f"Unknown function call: {function_name}")
    
    if tool_outputs:
        logger.info(f"Submitting tool outputs: {tool_outputs}")
        client.beta.threads.runs.submit_tool_outputs(
            thread_id=thread_id,
            run_id=run_id,
            tool_outputs=tool_outputs
        )

def step_3(investigation_plan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 3: Coordinate the investigation using the lead agent and sub-assistants.
    """
    if not LEAD_ASSISTANT_ID:
        return {"error": "Lead Assistant ID not found in environment variables"}

    thread = create_thread()
    logger.info(f"Created thread with ID: {thread.id}")

    # Add the investigation plan to the thread
    add_message_to_thread(thread.id, f"Here's the investigation plan: {json.dumps(investigation_plan, indent=2)}")
    add_message_to_thread(
        thread.id,
        "Please coordinate the investigation based on this plan and provide the results in JSON format. For steps with IOC type 'IP Address', use the investigate_ip_address function to delegate to the IP Address Investigator."
    )
    logger.info("Added investigation plan and instructions to thread.")

    # Run the lead agent
    run_id = run_assistant(LEAD_ASSISTANT_ID, thread.id)
    logger.info(f"Started run with ID: {run_id}")

    # Wait for the run to complete
    while True:
        run_status = get_run_status(thread.id, run_id)
        logger.info(f"Run status: {run_status.status}")
        if run_status.status == 'completed':
            logger.info("Run completed.")
            break
        elif run_status.status == 'requires_action':
            tool_calls = run_status.required_action.submit_tool_outputs.tool_calls
            logger.info(f"Run requires action with tool calls: {[call.function.name for call in tool_calls]}")
            handle_tool_calls(thread.id, run_id, tool_calls)
        else:
            logger.info("Run is still in progress.")
        # Add a small delay to avoid excessive API calls
        time.sleep(1)

    # Get the investigation results
    messages = get_messages(thread.id)
    logger.info(f"Retrieved {len(messages.data)} messages from thread.")

    # Extract the final report from the assistant's messages
    investigation_results = {}
    for message in reversed(messages.data):
        if message.role == "assistant":
            logger.info(f"Message content type: {type(message.content)}")
            logger.info(f"Message content: {message.content}")
            try:
                if isinstance(message.content, str):
                    # Direct JSON string
                    investigation_results = json.loads(message.content)
                elif isinstance(message.content, list):
                    # Extract text from TextContentBlock objects
                    content_str = ''.join([
                        segment.text.value for segment in message.content
                        if hasattr(segment, 'text') and hasattr(segment.text, 'value')
                    ])
                    logger.info(f"Extracted content string: {content_str}")
                    # Parse the JSON string
                    investigation_results = json.loads(content_str)
                else:
                    # Fallback to summary
                    content_str = str(message.content)
                    investigation_results = {"summary": content_str}
                logger.info(f"Final investigation results: {investigation_results}")
                break
            except (json.JSONDecodeError, AttributeError) as e:
                logger.error(f"Failed to parse message content: {e}")
                investigation_results = {"summary": "Failed to parse investigation results."}
                break

    return investigation_results


if __name__ == "__main__":
    # For testing purposes
    sample_investigation_plan = {
        "step_1": {
            "title": "Investigate IP Address",
            "ioc": "192.168.100.55",
            "ioc_type": "IP Address"
        }
    }
    results = step_3(sample_investigation_plan)
    print(json.dumps(results, indent=2))
