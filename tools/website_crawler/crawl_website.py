from firecrawl import FirecrawlApp
import os
from dotenv import load_dotenv
from googleapiclient.discovery import build
import time
import json
from urllib.parse import urlparse
import google.generativeai as genai

# Load environment variables
load_dotenv()

# Initialize Firecrawl client
firecrawl_api_key = os.getenv("FIRECRAWL_API_KEY")
if not firecrawl_api_key:
    raise ValueError("FIRECRAWL_API_KEY not found in environment variables.")

firecrawl = FirecrawlApp(api_key=firecrawl_api_key)

# Initialize Google Custom Search API client
google_api_key = os.getenv("GOOGLE_API_KEY")
google_cse_id = "f254e33a704b54ff0"  # Replace with your Custom Search Engine ID

if not google_api_key:
    raise ValueError("GOOGLE_API_KEY not found in environment variables.")

google_service = build("customsearch", "v1", developerKey=google_api_key)

# Configure Google Gemini API
gemini_api_key = os.getenv("GEMINI_API_KEY")
if not gemini_api_key:
    raise ValueError("GEMINI_API_KEY not found in environment variables.")

genai.configure(api_key=gemini_api_key)

# Create the Gemini model without safety settings
generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 64,
    "max_output_tokens": 8192,
    "response_mime_type": "text/plain",  # Use text/plain for easier debugging
}

model = genai.GenerativeModel(
    model_name="gemini-1.5-flash",
    generation_config=generation_config,
)

def perform_google_search(query: str, num_results: int = 1) -> list:
    """
    Perform a Google search and return the top results.

    Args:
        query (str): The search query.
        num_results (int): Number of results to return (default: 3).

    Returns:
        list: A list of dictionaries containing the title and URL of each result.
    """
    try:
        results = google_service.cse().list(q=query, cx=google_cse_id, num=num_results).execute()
        items = results.get("items", [])
        if not items:
            print("No search results found.")
        return [{"title": item["title"], "url": item["link"]} for item in items]
    except Exception as e:
        print(f"Error performing Google search: {str(e)}")
        return []

def ensure_url_has_scheme(url: str) -> str:
    """
    Ensure the URL has a scheme (http or https).

    Args:
        url (str): The URL to check.

    Returns:
        str: The URL with a scheme.
    """
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        return "https://" + url
    return url

def scrape_website(url: str) -> dict:
    """
    Scrape a website using Firecrawl and return the markdown content.

    Args:
        url (str): The URL of the website to scrape.

    Returns:
        dict: The scraped markdown content or an error message.
    """
    try:
        # Ensure the URL has a scheme
        url = ensure_url_has_scheme(url)
        print(f"Scraping URL: {url}")

        params = {
            "formats": ["markdown"]  # Specify desired formats
        }

        # Log the parameters being sent
        print(f"Scrape parameters: {json.dumps(params, indent=2)}")

        # Correct usage: pass URL and params separately
        scrape_result = firecrawl.scrape_url(url, params=params)

        # Log the full response from Firecrawl
        print(f"Scrape response: {json.dumps(scrape_result, indent=2)}")

        # Determine if scraping was successful
        if isinstance(scrape_result, dict):
            if "markdown" in scrape_result:
                markdown = scrape_result.get("markdown", "")
                if markdown:
                    print(f"Successfully scraped markdown for URL: {url}")
                    return {"markdown": markdown}
                else:
                    print(f"Markdown content is empty for URL: {url}")
                    return {"error": "Markdown content is empty in the response."}
            elif "data" in scrape_result and "markdown" in scrape_result["data"]:
                # Handle case where response has a 'data' field
                markdown = scrape_result["data"].get("markdown", "")
                if markdown:
                    print(f"Successfully scraped markdown for URL: {url}")
                    return {"markdown": markdown}
                else:
                    print(f"Markdown content is empty in 'data' for URL: {url}")
                    return {"error": "Markdown content is empty in the 'data' field."}
            elif "error" in scrape_result:
                error_message = scrape_result["error"]
                print(f"Scraping failed for URL: {url} with error: {error_message}")
                return {"error": f"Scraping failed: {error_message}"}
            else:
                print(f"Unexpected response structure for URL: {url}")
                return {"error": "Unknown error. Unexpected response structure."}
        else:
            print(f"Scrape result is not a dictionary for URL: {url}")
            return {"error": "Unknown error. Scrape result is not a dictionary."}

    except Exception as e:
        error_message = str(e)
        print(f"Exception during scraping URL: {url} - {error_message}")
        if "429" in error_message:
            return {"error": "Rate limit exceeded. Please try again later or upgrade your Firecrawl plan."}
        elif "400" in error_message:
            return {"error": "Invalid request. Please check the Firecrawl API documentation for the correct request format."}
        else:
            return {"error": f"Error scraping website: {error_message}"}

def summarize_results(query: str, scraping_json: str) -> str:
    """
    Summarize the scraping results using Google Gemini.

    Args:
        query (str): The original search query.
        scraping_json (str): The JSON string of scraped results.

    Returns:
        str: The summarized text.
    """
    try:
        print("Preparing prompt for summarization...")
        print(f"Query: {query}")
        print(f"Scraping JSON (first 500 characters): {scraping_json[:500]}...")  # Print first 500 characters for brevity

        prompt = f"Please provide a summary about '{query}' and cite your sources from the JSON below:\n{scraping_json}"

        # Start a chat session with the Gemini model
        chat_session = model.start_chat(history=[])

        # Send the prompt without safety settings
        response = chat_session.send_message(prompt)

        # Check if the response was blocked or successful
        if hasattr(response, 'text') and response.text:
            print("Summarization successful.")
            return response.text
        else:
            print("The summarization request was blocked due to safety settings.")
            return "The summarization request was blocked due to safety settings."

    except Exception as e:
        print(f"Error during summarization: {str(e)}")
        import traceback
        traceback.print_exc()
        return "An error occurred during summarization."

def advanced_search_scrape_and_summarize(query: str) -> str:
    """
    Perform an advanced Google search, retrieve the top results,
    scrape each resulting website, and summarize the findings.

    Args:
        query (str): The search query.

    Returns:
        str: The summarized result.
    """
    print(f"Performing advanced search for query: {query}")
    search_results = perform_google_search(query)
    
    if not search_results:
        print("No search results to scrape.")
        return "No results found."

    aggregated_content = {
        "query": query,
        "results": []
    }

    for idx, result in enumerate(search_results, start=1):
        title = result.get('title', 'No Title')
        url = result.get('url', '')
        print(f"\nProcessing result {idx}: {title} - {url}")
        
        site_content = scrape_website(url)
        
        if 'markdown' in site_content:
            content = site_content['markdown']
        else:
            content = site_content.get('error', "Unknown error occurred.")
        
        result_data = {
            "title": title,
            "url": url,
            "content": content
        }
        aggregated_content["results"].append(result_data)
        
        # Add a delay between requests to avoid rate limiting
        time.sleep(3)

    # Convert aggregated_content to JSON string for summarization
    scraping_json = json.dumps(aggregated_content, indent=2)

    # Summarize the results using Google Gemini
    summary = summarize_results(query, scraping_json)

    return summary

# Example usage
if __name__ == "__main__":
    test_query = "encryptor.exe"
    print(f"Starting advanced search, scrape, and summarize for query: '{test_query}'\n")
    final_summary = advanced_search_scrape_and_summarize(test_query)
    print("\nFinal Summary:")
    print(final_summary)
