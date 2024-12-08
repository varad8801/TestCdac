import re
import pandas as pd

# for Reading the log file
file = open("sample.log", "r")
log_data = file.read()
file.close()

#splting log  for Creating a DataFrame
pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?) (.*?) HTTP/1\.1" (\d+) (\d+)(?: "(.*?)")?'
matches = re.findall(pattern, log_data)
columns = ["IP", "Timestamp", "Method", "Path", "Status", "Size", "Message"]
df = pd.DataFrame(matches, columns=columns)
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#Q1. Count Requests per IP Address:
print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
requests_per_ip = df["IP"].value_counts().reset_index()
requests_per_ip.columns = ["IP Address", "Request Count"]
print(requests_per_ip)
requests_per_ip.to_csv("requests_per_ip.csv", index=False)

#Q2. Identify the Most Frequently Accessed Endpoint:
print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
most_accessed_endpoint = df["Path"].value_counts().idxmax()
access_count = df["Path"].value_counts().max()
print(f"Most Frequently Accessed Endpoint:\n{most_accessed_endpoint} (Accessed {access_count} times)")

most_accessed_df = pd.DataFrame(
    {"Endpoint": [most_accessed_endpoint], "Access Count": [access_count]}
)
most_accessed_df.to_csv("most_accessed_endpoints.csv", index=False)

#Q3. Detect Suspicious Activity:
print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
failed_logins = df[(df["Status"] == 401) & (df["Message"].str.contains("Invalid credentials", na=False))]
failed_login_counts = failed_logins["IP"].value_counts()

threshold = 10
flagged_ips = failed_login_counts[failed_login_counts > threshold].reset_index()
flagged_ips.columns = ["IP Address", "Failed Login Count"]
print(flagged_ips)
flagged_ips.to_csv("suspicious_activity.csv", index=False)

# Combineinto a single CSV file
with open("log_analysis_results.csv", "w") as outfile:
    outfile.write("Requests per IP\n")
    requests_per_ip.to_csv(outfile, index=False)
    outfile.write("\nMost Accessed Endpoint\n")
    most_accessed_df.to_csv(outfile, index=False)
    outfile.write("\nSuspicious Activity\n")
    flagged_ips.to_csv(outfile, index=False)
