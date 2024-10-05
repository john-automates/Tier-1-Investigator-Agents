import os
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Define fake tools
fake_tools = [
    {
        "type": "function",
        "function": {
            "name": "analyze_logs",
            "description": "Analyze log files for anomalies",
            "parameters": {
                "type": "object",
                "properties": {
                    "log_file": {
                        "type": "string",
                        "description": "Path to the log file"
                    }
                },
                "required": ["log_file"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "gather_threat_intel",
            "description": "Gather threat intelligence on indicators",
            "parameters": {
                "type": "object",
                "properties": {
                    "indicator": {
                        "type": "string",
                        "description": "Threat indicator (e.g., IP address, domain)"
                    }
                },
                "required": ["indicator"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "compile_findings",
            "description": "Compile findings from the investigation",
            "parameters": {
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "description": "List of findings from the investigation"
                    }
                },
                "required": ["findings"]
            }
        }
    }
]

# Create assistants
def create_assistant(name, instructions, tools):
    assistant = client.beta.assistants.create(
        name=name,
        instructions=instructions,
        tools=tools,
        model="gpt-4o-mini"
    )
    return assistant

# Lead Analyst Assistant
lead_analyst = create_assistant(
    "Lead Analyst Assistant",
    "You are the Lead Analyst overseeing security investigations. Your role is to delegate tasks, coordinate the investigation, and compile findings.",
    fake_tools
)

# Threat Intelligence Assistant
threat_intel = create_assistant(
    "Threat Intelligence Assistant",
    "You are the Threat Intelligence specialist. Your role is to gather and analyze information on threat indicators such as IP addresses and domains.",
    fake_tools
)

# Log Analysis Assistant
log_analyst = create_assistant(
    "Log Analysis Assistant",
    "You are the Log Analysis expert. Your role is to analyze logs and detection data for anomalies and suspicious activities.",
    fake_tools
)

# Display assistant IDs
print("Assistant IDs:")
print(f"Lead Analyst Assistant: {lead_analyst.id}")
print(f"Threat Intelligence Assistant: {threat_intel.id}")
print(f"Log Analysis Assistant: {log_analyst.id}")

print("\nPlease add these IDs to your .env file with the following variable names:")
print("LEAD_ANALYST_ID")
print("THREAT_INTEL_ID")
print("LOG_ANALYST_ID")