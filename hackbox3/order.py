import os
import re
from datetime import datetime

# Work in current directory
folder = os.getcwd()

# Regex for screenshot filenames
pattern = re.compile(r"Screenshot (\d{4}-\d{2}-\d{2}) at (\d{1,2}\.\d{2}\.\d{2})\s?([APM]{2})")

files = []
for fname in os.listdir(folder):
    match = pattern.search(fname)
    if match:
        date_str, time_str, ampm = match.groups()
        time_str = time_str.replace(".", ":")
        dt_str = f"{date_str} {time_str} {ampm}"
        dt = datetime.strptime(dt_str, "%Y-%m-%d %I:%M:%S %p")
        files.append((dt, fname))

# Sort files by datetime
files.sort(key=lambda x: x[0])

# Rename sequentially
for i, (_, fname) in enumerate(files, start=1):
    ext = os.path.splitext(fname)[1]
    new_name = f"{i}{ext}"
    os.rename(fname, new_name)
    print(f"{fname} → {new_name}")

print("✅ Done! Screenshots renamed in chronological order.")
