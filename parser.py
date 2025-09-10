import json
import re
from typing import Any, Optional, Union

def parse_whois_json(whois_data: dict[str, Any]) -> dict[str, Any]:
    """
    Parses a dictionary of WHOIS data to extract key information.

    This function is inspired by the logic in the richardpenman/whois library
    but adapted for JSON/dictionary input. It traverses the JSON structure
    to find values, even if they are nested.

    Args:
        whois_data: A dictionary containing the WHOIS lookup data,
                    typically loaded from a JSON response.

    Returns:
        A dictionary containing the parsed, usable variables.
    """
    parsed_data: dict[str, Optional[Union[str, list[str]]]] = {
        "createdDate": None,
        "updatedDate": None,
        "expiresDate": None,
        "registrarName": None,
        "whoisServer": None,
        "registrant": None,
        "country": None,
        "countryCode": None,
        "registrarIANAID": None,
        "nameservers": None,
    }

    # Helper function to recursively search for a key in the data structure
    def _find_key_recursively(data: Any, target_key: str) -> Optional[Any]:
        if isinstance(data, dict):
            if target_key in data:
                return data[target_key]
            for value in data.values():
                result = _find_key_recursively(value, target_key)
                if result is not None:
                    return result
        elif isinstance(data, list):
            for item in data:
                result = _find_key_recursively(item, target_key)
                if result is not None:
                    return result
        return None

    # Helper to get the first available value from a list of keys using recursive search
    def _get_value(*keys: str) -> Optional[Any]:
        for key in keys:
            value = _find_key_recursively(whois_data, key)
            if value is not None:
                return value
        return None

    # Date fields
    parsed_data["createdDate"] = _get_value("creation_date", "creationDate", "created_date", "created")
    parsed_data["updatedDate"] = _get_value("updated_date", "updatedDate", "last_updated", "updated")
    parsed_data["expiresDate"] = _get_value("expiration_date", "expirationDate", "expires_date", "expires", "expiry_date")

    # Registrar information
    parsed_data["registrarName"] = _get_value("registrar", "registrar_name", "registrarName")
    parsed_data["whoisServer"] = _get_value("whois_server", "whoisServer")
    parsed_data["registrarIANAID"] = _get_value("registrar_iana_id", "registrarIANAID", "ianaid")

    # Registrant information
    registrant_info = _get_value("registrant", "registrant_name", "registrantName")

    registrant_name = None
    if isinstance(registrant_info, dict):
        # If the value is a dictionary, search for name or organization within it.
        registrant_name = registrant_info.get("name") or registrant_info.get("organization")
    elif isinstance(registrant_info, str):
        # If it's a simple string, use it directly.
        registrant_name = registrant_info
    
    parsed_data["registrant"] = registrant_name
    parsed_data["country"] = _get_value("registrant_country", "country")
    
    # Handle both spellings for country code
    country_code = _get_value("registrant_country_code", "country_code", "countryCode")
    parsed_data["countryCode"] = country_code
    
    # Nameservers (often a list, string, or structured data)
    # Search for the main nameserver block first. Note 'hostNames' is NOT in this initial search.
    raw_nameservers = _get_value("name_servers", "nameservers", "nserver", "nameServers", "nameserver_info")
    
    nameserver_list = []
    if raw_nameservers:
        # Create a list to iterate over, regardless of the input type
        items_to_process = []
        if isinstance(raw_nameservers, str):
            # If it's a string, split it by common delimiters
            items_to_process = re.split(r'[,\s\n]+', raw_nameservers)
        elif isinstance(raw_nameservers, list):
            items_to_process = raw_nameservers
        elif isinstance(raw_nameservers, dict):
            # If it's a dictionary, look for a 'hostNames' key *within* it
            hostnames = raw_nameservers.get("hostNames")
            if hostnames and isinstance(hostnames, list):
                items_to_process = hostnames
        
        # Process the list of items
        for item in items_to_process:
            if not item:
                continue
            if isinstance(item, str):
                nameserver_list.append(item.lower().strip())
            elif isinstance(item, dict):
                # If it's a dictionary, look for a 'name' or 'hostname'
                name = item.get("name") or item.get("hostname")
                if name and isinstance(name, str):
                    nameserver_list.append(name.lower().strip())

    # Remove duplicates and format as a comma-separated string
    if nameserver_list:
        seen = set()
        unique_ns = [x for x in nameserver_list if x and not (x in seen or seen.add(x))]
        parsed_data["nameservers"] = ", ".join(unique_ns)
    else:
        parsed_data["nameservers"] = None
        
    return parsed_data

# --- Example Usage ---
    # This structure now includes a nested 'hostNames' key to test the update.
    sample_json_data = """
    {
        "domain_name": "google.com",
        "registrar": "MarkMonitor Inc.",
        "whois_server": "whois.markmonitor.com",
        "dates": {
            "creation_date": "1997-09-15T04:00:00Z",
            "expiration_date": "2028-09-14T04:00:00Z",
            "updated_date": "2019-09-09T15:39:04Z"
        },
        "nameserver_info": {
            "hostNames": [
                "NS1.GOOGLE.COM",
                "NS2.GOOGLE.COM",
                "NS3.GOOGLE.COM",
                "NS4.GOOGLE.COM"
            ]
        },
        "status": "clientDeleteProhibited clientTransferProhibited clientUpdateProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited",
        "registrant": {
            "organization": "Google LLC",
            "location": {
                 "registrant_country": "United States",
                 "country_code": "US"
            }
        },
        "registrarIANAID": "292"
    }
    """

    # 1. Load the JSON string into a Python dictionary
    try:
        whois_dict = json.loads(sample_json_data)

        # 2. Pass the dictionary to the parsing function
        parsed_info = parse_whois_json(whois_dict)

        # 3. Print the extracted variables
        print("--- Parsed WHOIS Information ---")
        for key, value in parsed_info.items():
            print(f"{key}: {value}")
        print("---------------------------------")

        # Example of accessing a specific variable
        print(f"\nRegistrar's Name: {parsed_info.get('registrarName')}")
        print(f"Nameservers: {parsed_info.get('nameservers')}")

    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")



