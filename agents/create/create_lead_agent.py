import os
from openai import OpenAI
from dotenv import load_dotenv
from tools.website_crawler.crawl_website import crawl_website, advanced_search_and_scrape

# Load environment variables
load_dotenv()

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def create_lead_agent():
    """
    Create a lead assistant to manage sub-assistants for the investigation process.
    """
    try:
        assistant = client.beta.assistants.create(
            name="Lead Investigator",
            instructions="""
            You are the lead investigator in charge of coordinating the OSINT investigation process.
            Your role is to manage and delegate tasks to specialized sub-assistants, interpret their findings,
            and provide a comprehensive analysis of the investigation results.
            
            You have access to the following specialized assistants and tools:
            1. IP Address Investigator (via the investigate_ip_address function)
            2. Advanced Search and Crawl (via the advanced_search_and_crawl function)
            
            Use these assistants and tools when needed to gather detailed information about specific IOCs, websites, and topics.
            Synthesize the information from all sources to create a cohesive investigation report.
            """,
            model="gpt-4-turbo-preview",
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "investigate_ip_address",
                        "description": "Delegate IP address investigation to the IP Address Investigator",
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
                },
                {
                    "type": "function",
                    "function": {
                        "name": "advanced_search_and_scrape",
                        "description": "Perform an advanced Google search, retrieve the top 3 results, and scrape each resulting website",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "query": {
                                    "type": "string",
                                    "description": "The search query"
                                }
                            },
                            "required": ["query"]
                        }
                    }
                }
            ]
        )
        return assistant
    except Exception as e:
        print(f"Error creating lead agent: {str(e)}")
        return None

if __name__ == "__main__":
    lead_agent = create_lead_agent()
    if lead_agent:
        print(f"Lead agent created successfully. ID: {lead_agent.id}")
    else:
        print("Failed to create lead agent.")
