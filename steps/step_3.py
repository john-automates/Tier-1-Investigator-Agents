import json
import os
from openai import OpenAI
from typing import Dict, Any
from dotenv import load_dotenv
from agents.create.create_lead_agent import create_lead_agent
from agents.create.create_ip_address_investigator import create_ip_address_investigator

# Load environment variables
load_dotenv()

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

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

def investigate_ip_address(ip_address: str):
    """Simulate IP address investigation using the IP Address Investigator."""
    # In a real implementation, this would use the actual IP Address Investigator
    return {
        "reputation": "suspicious",
        "geolocation": {
            "country": "Unknown",
            "city": "Unknown"
        }
    }

def step_3(investigation_plan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 3: Coordinate the investigation using the lead agent and sub-assistants.
    """
    lead_agent = create_lead_agent()
    ip_investigator = create_ip_address_investigator()

    if not lead_agent or not ip_investigator:
        return {"error": "Failed to create agents"}

    thread = create_thread()
    
    # Add the investigation plan to the thread
    add_message_to_thread(thread.id, f"Here's the investigation plan: {json.dumps(investigation_plan, indent=2)}")
    add_message_to_thread(thread.id, "Please coordinate the investigation based on this plan. Use your sub-assistants as needed to gather detailed information about specific IOCs.")

    # Run the lead agent
    run_id = run_assistant(lead_agent.id, thread.id)

    # Wait for the run to complete
    while True:
        run_status = get_run_status(thread.id, run_id)
        if run_status.status == 'completed':
            break
        elif run_status.status == 'requires_action':
            for tool_call in run_status.required_action.submit_tool_outputs.tool_calls:
                if tool_call.function.name == "investigate_ip_address":
                    ip_address = json.loads(tool_call.function.arguments)["ip_address"]
                    result = investigate_ip_address(ip_address)
                    client.beta.threads.runs.submit_tool_outputs(
                        thread_id=thread.id,
                        run_id=run_id,
                        tool_outputs=[{
                            "tool_call_id": tool_call.id,
                            "output": json.dumps(result)
                        }]
                    )
        # Add a small delay to avoid excessive API calls
        import time
        time.sleep(1)

    # Get the investigation results
    messages = get_messages(thread.id)
    
    # Extract the final report from the assistant's messages
    investigation_results = {}
    for message in reversed(messages.data):
        if message.role == "assistant":
            try:
                investigation_results = json.loads(message.content[0].text.value)
                break
            except json.JSONDecodeError:
                investigation_results = {"summary": message.content[0].text.value}
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
