USAGE
=====
whois_dict = json.loads(sample_json_data)

parsed_info = parse_whois_json(whois_dict)


print("--- Parsed WHOIS Information ---")
for key, value in parsed_info.items():
    print(f"{key}: {value}")
print("---------------------------------")

# Example of accessing a specific variable

print(f"\nRegistrar's Name: {parsed_info.get('registrarName')}")

print(f"Nameservers: {parsed_info.get('nameservers')}")

