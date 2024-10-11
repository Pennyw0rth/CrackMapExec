def parse_result_attributes(ldap_response):
    parsed_response = []
    for entry in ldap_response:
        # SearchResultReferences may be returned
        if entry["type"] != "searchResEntry":
            continue
        attribute_map = {}
        for attribute in entry["attributes"]:
            if "description" in attribute:
                attribute_map[str(attribute)] = "" if entry['attributes'][attribute] == [] else str(entry['attributes'][attribute][0])
            elif "pwdLastSet" in attribute:
                attribute_map[str(attribute)] = str(entry['attributes'][attribute])
            else:    
                attribute_map[str(attribute)] = entry['attributes'][attribute]
        parsed_response.append(attribute_map)
    return parsed_response