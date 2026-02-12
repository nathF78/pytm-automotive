import csv
import json


def create_threat_entry(sid, description, details, target_list = [], condition = "", mitigation = "", reference = "", severity = "", likelihood = ""):
    """
    Helper function to build the dictionary dynamically.
    """
    
    
    
    entry = {
        "SID": f"[{sid}]",
        "target": target_list,
        "description": description, # Placeholder or passed variable
        "details": details,
        "Likelihood Of Attack": likelihood,
        "severity": severity,
        "condition": condition,
        "prerequisites": "",
        "mitigations": mitigation,
        "example": "",
        "references": reference
    }
    return entry

details_format = "[{id}] {high_level} - {sub_level}"

def convert_csv_to_json(csv_file_path: str) -> list[str]:
    # Initialize the list to store the data
    data = []

    # Open the CSV file for reading
    with open(csv_file_path, mode='r', encoding='utf-8') as csv_file:
        # Create a CSV reader object
        csv_reader = csv.reader(csv_file, delimiter=',')

        # Loop through each row in the CSV file and add it to the data list
        for row in csv_reader:
            data.append(row)

    
    json_raw = []
    high_level = ""
    high_level_id = -1
    sub_level = ""
    sub_level_id = -1
    example= ""
    example_id = -1
    
    for row in data :

        if row[3] == "" or row[4] == "":
            print("Example is missing, ignoring the row... This behaviour is normal for the first row of the tab.")
            continue
        
        example_id = row[3]
        example = row[4]

        
        if row[0] != "" :
            high_level_id, high_level = row[0].split(" ", 1)

        if row[1] != "" :
            sub_level_id = row[1]
            sub_level = row[2]


        formatted_details = details_format.format(id=high_level_id, high_level=high_level, sub_level = sub_level)

        threat_entry = create_threat_entry(example_id, example, formatted_details, target_list=["Server"], condition="True")
        print("Adding entry " + str(example_id) + " to the JSON file")

        json_raw.append(threat_entry)
    
    print("Success !")
    return json_raw

        # print("high_level_id: " + sub_level_id + "\n\t high_level: " + high_level + "\n sub_level_id: " +sub_level_id + "\n\t sub_level: " + sub_level )


csv_file_path = "./data/R155 - Annex 5.csv"
json_file_path = "./output/raw_threat_output.json"
json_raw = convert_csv_to_json(csv_file_path)

with open(json_file_path, mode='w', encoding='utf-8') as json_file:
    # Convert the data list to a JSON string and write it to the file
    json.dump(json_raw, json_file, indent=4)

