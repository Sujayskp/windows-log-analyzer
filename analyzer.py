import win32evtlog  # From pywin32
import pandas as pd
from datetime import datetime
from colorama import Fore, Style

# Define your log source
server = 'localhost'
log_type = 'Security'  # Other examples: System, Application

# Connect to the log
handle = win32evtlog.OpenEventLog(server, log_type)

flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

total = win32evtlog.GetNumberOfEventLogRecords(handle)

events = []

print(Fore.CYAN + f"Total Events: {total}, Reading logs..." + Style.RESET_ALL)

while True:
    records = win32evtlog.ReadEventLog(handle, flags, 0)
    if not records:
        break
    for event in records:
        event_id = event.EventID
        source = str(event.SourceName)
        time = event.TimeGenerated.Format()
        message = str(event.StringInserts)

        # Detecting common suspicious event IDs
        suspicious = False
        if event_id in [4625, 4648, 4688, 4720, 4726]:
            suspicious = True

        events.append({
            'Time': time,
            'EventID': event_id,
            'Source': source,
            'Suspicious': suspicious,
            'Details': message
        })

# Convert to DataFrame for analysis
df = pd.DataFrame(events)
df_suspicious = df[df['Suspicious'] == True]

print(Fore.RED + "\nSuspicious Events Found:" + Style.RESET_ALL)
print(df_suspicious[['Time', 'EventID', 'Source']])

# Save report
df_suspicious.to_csv("report.txt", index=False)

print(Fore.GREEN + "\nReport saved to report.txt" + Style.RESET_ALL)
