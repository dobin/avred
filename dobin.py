from pe_utils import *
from find import bytes_detection


"""
attempts to locate the part in a PE file that causes the antivirus detection
"""
def findDetectedSections(pe, scanner):
    detected_sections = []

    for section in pe.sections:
        new_pe = deepcopy(pe)
        hide_section(new_pe, section.name)

        status = scanner.scan(new_pe.data)
        section.detected =  status

        if not status:
            logging.info(f"Section {section.name} triggers the antivirus")
            detected_sections += [section]

    sectionCount = len(detected_sections)
    print(f"{sectionCount} section(s) trigger the antivirus")
    for section in detected_sections:
        print(f"  section: {section.name}")

    return detected_sections


def investigate(pe, scanner):
    detected = scanner.scan(pe.data)
    if not detected:
        logging.error(f"{pe.filename} is not detected by {scanner.scanner_name}")
        return

    # identify which sections get detected
    detected_sections = findDetectedSections(pe, scanner)

    # analyze each section
    matches = []
    for section in detected_sections:
        logging.info(f"Launching bytes analysis on section {section.name}: {section.addr}-{section.addr+section.size}")
        match = _detection(scanner, pe.data, section.addr, section.addr+section.size)
        matches.append(match)

    return matches


def makePatchedFile(fileData, offset, size):
    patch = bytes(chr(0),'ascii') * int(size)
    goat = fileData[:offset] + patch + fileData[offset+size:]
    return goat


SIG_SIZE = 128

def _detection(scanner, fileData, sectionStart, sectionEnd):
    size = sectionEnd - sectionStart
    chunkSize = int(size // 2)

    logging.info(f"Testing: {sectionStart}-{sectionEnd} with size {sectionEnd-sectionStart} (chunkSize {chunkSize} bytes)")
    #logging.info(f"Testing Top: {sectionStart}-{sectionStart+chunkSize} (chunkSize {chunkSize} bytes)")
    #logging.info(f"Testing Bot: {sectionStart+chunkSize}-{sectionStart+chunkSize+chunkSize} (chunkSize {chunkSize} bytes)")

    if chunkSize < 2:
        logging.error(f"Very small chunksize for a signature, problem?")
        return []

    chunkTopNull = makePatchedFile(fileData, sectionStart, chunkSize)
    chunkBotNull = makePatchedFile(fileData, sectionStart+chunkSize, chunkSize)

    detectTopNull = scanner.scan(chunkTopNull)
    detectBotNull = scanner.scan(chunkBotNull)

    if detectTopNull and detectBotNull:
        # Both halves are detected
        # Continue scanning both halves independantly, but with each other halve
        # zeroed out (instead of the complete file)
        logging.error("Both halves are detected!")
        ret = []
        _detection(scanner, chunkBotNull, sectionStart, sectionStart+chunkSize)
        _detection(scanner, chunkTopNull, sectionStart+chunkSize, sectionEnd)

    elif not detectTopNull and not detectBotNull:
        if chunkSize < SIG_SIZE:
            # No more detections
            logging.info("No more detection")
            logging.info(f"Result: {sectionStart}-{sectionEnd} ({sectionEnd-sectionStart} bytes)")

            print("Result:")
            data = fileData[sectionStart:sectionStart+size]
            print(hexdump.hexdump(data, result='return'))
        else: 
            logging.info("No detections anymore, but too big. Continue anyway...")
            _detection(scanner, fileData, sectionStart, sectionStart+chunkSize)
            _detection(scanner, fileData, sectionStart+chunkSize, sectionEnd)

        #print("TopNull:")
        #data = chunkBotNull[sectionStart:sectionStart+chunkSize]
        #print(hexdump.hexdump(data, result='return'))

        #print("BotNull:")
        #data = chunkTopNull[sectionStart+chunkSize:sectionStart+chunkSize+chunkSize]
        #print(hexdump.hexdump(data, result='return'))

    elif not detectTopNull:
        # Detection in the top half
        #logging.info("Do Top")
        return _detection(scanner, fileData, sectionStart, sectionStart+chunkSize)
    elif not detectBotNull:
        # Detection in the bottom half
        #logging.info(f"Do Bot")
        return _detection(scanner, fileData, sectionStart+chunkSize, sectionEnd)

    return []