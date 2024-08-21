import re


system_log = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"

def antivirus_log(log):
    # First extracting the portion of the log string after the last '|'
    first_part = log.split('|')[-1]
    
    # Writing the regular expression pattern to match key-value pairs
    # (\w+) matches the key, and ([^|]+?) matches the value up to the next key or the end of the string
    pattern = r'(\w+)=([^|]+?)(?=\s\w+=|$)'
    
    # To find all key-value pairs in the extracted part using the regular expression pattern
    matches = re.findall(pattern, first_part)
    
    # Creating an empty dictionary to store the final results
    final_result = {}
    
    # Loop through the matches and populate the dictionary
    for key, value in matches:
        final_result[key] = value.strip()  # To Strip any leading/trailing whitespace from the value
        
    # Format the dictionary to get the results in a required format
    formatted_result = ',\n'.join(f"{key}: {value}" for key, value in final_result.items())
    
    return f"{{\n{formatted_result}\n}}"

# Calling the antivirus_log function with system_log as a input
print(antivirus_log(system_log))
