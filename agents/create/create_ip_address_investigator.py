import os
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def create_ip_address_investigator():
    """
    Create an IP Address Investigator assistant with fake tools for demonstration.
    """
    try:
        assistant = client.beta.assistants.create(
            name="IP Address Investigator",
            instructions="""
            You are an IP Address Investigator specialized in OSINT techniques. 
            Your role is to investigate IP addresses using various online tools and resources.
            When given an IP address, use your tools to gather information and provide a detailed report.
            """,
            model="gpt-4-turbo-preview",
            tools=[{
                "type": "function",
                "function": {
                    "name": "check_ip_reputation",
                    "description": "Check the reputation of an IP address",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "ip_address": {
                                "type": "string",
                                "description": "The IP address to investigate"
                            }
                        },
                        "required": ["ip_address"]
                    }
                }
            }, {
                "type": "function",
                "function": {
                    "name": "get_geolocation",
                    "description": "Get the geolocation information for an IP address",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "ip_address": {
                                "type": "string",
                                "description": "The IP address to geolocate"
                            }
                        },
                        "required": ["ip_address"]
                    }
                }
            }]
        )
        return assistant
    except Exception as e:
        print(f"Error creating IP Address Investigator: {e}")
        return None

if __name__ == "__main__":
    ip_investigator = create_ip_address_investigator()
    if ip_investigator:
        print(f"IP Address Investigator created successfully. ID: {ip_investigator.id}")
    else:
        print("Failed to create IP Address Investigator.")
