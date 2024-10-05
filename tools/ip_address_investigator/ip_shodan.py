import os
import shodan
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Shodan API client
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
api = shodan.Shodan(SHODAN_API_KEY)

def check_ip_reputation(ip_address: str) -> dict:
    """
    Check the reputation of an IP address using Shodan.
    """
    try:
        # Get all available information for the IP
        result = api.host(ip_address)

        # Extract relevant information
        reputation_data = {
            "ip": result.get("ip_str"),
            "organization": result.get("org", "N/A"),
            "country": result.get("country_name", "N/A"),
            "city": result.get("city", "N/A"),
            "open_ports": result.get("ports", []),
            "vulns": result.get("vulns", []),
            "last_update": result.get("last_update", "N/A"),
            "hostnames": result.get("hostnames", []),
            "domains": result.get("domains", []),
        }

        # Add a simple reputation score based on vulnerabilities and open ports
        vuln_count = len(reputation_data["vulns"])
        port_count = len(reputation_data["open_ports"])
        #print reputation_data
        print(reputation_data)
        
        if vuln_count > 5 or port_count > 10:
            reputation_data["reputation"] = "High Risk"
        elif vuln_count > 0 or port_count > 5:
            reputation_data["reputation"] = "Medium Risk"
        else:
            reputation_data["reputation"] = "Low Risk"

        return reputation_data

    except shodan.APIError as e:
        return {"error": f"Shodan API Error: {str(e)}"}

def get_geolocation(ip_address: str) -> dict:
    """
    Get the geolocation information for an IP address using Shodan.
    """
    try:
        # Get all available information for the IP
        result = api.host(ip_address)

        # Extract geolocation information
        geolocation_data = {
            "ip": result.get("ip_str"),
            "country": result.get("country_name", "N/A"),
            "country_code": result.get("country_code", "N/A"),
            "city": result.get("city", "N/A"),
            "region_code": result.get("region_code", "N/A"),
            "latitude": result.get("latitude", "N/A"),
            "longitude": result.get("longitude", "N/A"),
            "isp": result.get("isp", "N/A"),
            "asn": result.get("asn", "N/A"),
            "organization": result.get("org", "N/A")
        }
        print(geolocation_data)
        return geolocation_data

    except shodan.APIError as e:
        return {"error": f"Shodan API Error: {str(e)}"}

if __name__ == "__main__":
    # Test the functions
    test_ip = "8.8.8.8"  # Google's public DNS
    reputation_result = check_ip_reputation(test_ip)
    print("IP Reputation:")
    print(reputation_result)
    
    geolocation_result = get_geolocation(test_ip)
    print("\nGeolocation:")
    print(geolocation_result)
