import json

input_file = "asrg-cve.json"       # Your original file
output_file = "cves_filtered.json"  # File with only relevance:true

with open(input_file, "r", encoding="utf-8") as infile, \
     open(output_file, "w", encoding="utf-8") as outfile:
    
    count_in = 0
    count_out = 0
    
    for line in infile:
        count_in += 1
        try:
            data = json.loads(line)
            if data.get("_source", {}).get("relevance", False):
                outfile.write(line)
                count_out += 1
        except json.JSONDecodeError:
            print(f"Skipping invalid JSON line: {count_in}")

print(f"✅ Done! Kept {count_out} out of {count_in} lines.")
print(f"Filtered file saved as {output_file}")
