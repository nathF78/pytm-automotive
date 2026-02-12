import csv
import json



def csv_to_tab(csv_source_path : str) -> list[str] :
    # Initialize the list to store the data
    data = []

    # Open the CSV file for reading
    with open(csv_file_path, mode='r', encoding='utf-8') as csv_file:
        # Create a CSV reader object
        csv_reader = csv.reader(csv_file, delimiter=',')

        # Loop through each row in the CSV file and add it to the data list
        for row in csv_reader:
            data.append(row)

    return data


def json_to_dict(json_path : str) -> dict :
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        return data


csv_file_path = "./data/R155 - Mitigation measures.csv"

mitigation_data = csv_to_tab(csv_file_path)

mitigation_data_supplement = []

# Clean the file from "&"
for row in mitigation_data :
    if "&" in row[0] :
        row[0], new_ref = row[0].split("&")
        row[0]= row[0].split()[0]
        mitigation_data_supplement.append([new_ref]+row[1:])

print(mitigation_data_supplement)
# mitigation_data = mitigation_data + mitigation_data_supplement

json_file_path = "output/raw_threat_output.json"

json_dict = json_to_dict(json_file_path)

output_json_file_path = "./output/threat_with_mitigations.json"

for entry in json_dict :
    # Clean the JSON SID to remove brackets: "[1.1]" -> "1.1"
    clean_sid = entry["SID"].strip("[]")

    # Iterate through your tab rows to find a match
    for row in mitigation_data:
        tab_id = row[0]       # "1.1"
        mitigation_id = row[2] # "M10"
        mitigation_text = row[3] # "The vehicle shall verify..."
        
        # Check if IDs match
        if clean_sid == tab_id:
            print(f"Match found for SID {clean_sid}")
            # Format the new mitigation string: "[M10] Text..."
            new_mitigation = f"[{mitigation_id}] {mitigation_text}"
            
            # Check if there is existing text to determine how to append
            if entry["mitigations"]:
                # Add a new line separator if mitigations already exist
                entry["mitigations"] += f"\n{new_mitigation}"
            else:
                # If empty, just set it
                entry["mitigations"] = new_mitigation


with open(output_json_file_path, mode='w', encoding='utf-8') as json_file:
    # Convert the data list to a JSON string and write it to the file
    json.dump(json_dict, json_file, indent=4)