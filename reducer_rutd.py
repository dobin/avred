import hexdump
import logging
from intervaltree import Interval, IntervalTree

SIG_SIZE = 128


def makePatchedFile(fileData, offset, size):
    patch = bytes(chr(0),'ascii') * int(size)
    goat = fileData[:offset] + patch + fileData[offset+size:]
    return goat


def scanData(scanner, fileData, sectionStart, sectionEnd):
    ret = []
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
        
        ret += scanData(scanner, chunkBotNull, sectionStart, sectionStart+chunkSize)
        ret += scanData(scanner, chunkTopNull, sectionStart+chunkSize, sectionEnd)

    elif not detectTopNull and not detectBotNull:
        # both parts arent detected anymore

        if chunkSize < SIG_SIZE:
            # Small enough, no more detections
            logging.info("No more detection")
            logging.info(f"Result: {sectionStart}-{sectionEnd} ({sectionEnd-sectionStart} bytes)")
            ret += [ Interval(sectionStart, sectionStart+size) ]

            #print("Result:")
            #data = fileData[sectionStart:sectionStart+size]
            #print(hexdump.hexdump(data, result='return'))
        else: 
            # make it smaller still
            logging.info("No detections anymore, but too big. Continue anyway...")
            ret += scanData(scanner, fileData, sectionStart, sectionStart+chunkSize)
            ret += scanData(scanner, fileData, sectionStart+chunkSize, sectionEnd)

        #print("TopNull:")
        #data = chunkBotNull[sectionStart:sectionStart+chunkSize]
        #print(hexdump.hexdump(data, result='return'))

        #print("BotNull:")
        #data = chunkTopNull[sectionStart+chunkSize:sectionStart+chunkSize+chunkSize]
        #print(hexdump.hexdump(data, result='return'))

    elif not detectTopNull:
        # Detection in the top half
        #logging.info("Do Top")
        ret += scanData(scanner, fileData, sectionStart, sectionStart+chunkSize)
    elif not detectBotNull:
        # Detection in the bottom half
        #logging.info(f"Do Bot")
        ret += scanData(scanner, fileData, sectionStart+chunkSize, sectionEnd)

    return ret