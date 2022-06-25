import os

# Check if file gets detected by the scanner
def scanFileOnly(filepath, scanner):
    data = None
    with open(filepath, 'rb') as file:
        data = file.read()
    detected = scanner.scan(data, os.path.basename(filepath))
    if detected:
        print(f"File is detected")
    else:
        print(f"File is not detected")
