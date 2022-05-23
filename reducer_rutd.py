import hexdump
import logging
from intervaltree import Interval, IntervalTree

SIG_SIZE = 128


def makePatchedFile(fileData, offset, size):
    patch = bytes(chr(0),'ascii') * int(size)
    goat = fileData[:offset] + patch + fileData[offset+size:]
    return goat


def scanData(scanner, fileData, sectionStart, sectionEnd):
    # just a wrapper for scanSection()
    it = IntervalTree()
    scanSection(scanner, fileData, sectionStart, sectionEnd, it)
    it.merge_overlaps(strict=False)
    return it


# recursive
def scanSection(scanner, fileData, sectionStart, sectionEnd, it):
    size = sectionEnd - sectionStart
    chunkSize = int(size // 2)
    
    logging.debug(f"Testing: {sectionStart}-{sectionEnd} with size {sectionEnd-sectionStart} (chunkSize {chunkSize} bytes)")
    #logging.debug(f"Testing Top: {sectionStart}-{sectionStart+chunkSize} (chunkSize {chunkSize} bytes)")
    #logging.debug(f"Testing Bot: {sectionStart+chunkSize}-{sectionStart+chunkSize+chunkSize} (chunkSize {chunkSize} bytes)")

    if chunkSize < 2:
        logging.debug(f"Very small chunksize for a signature, weird. Ignoring. {sectionStart}-{sectionEnd}")
        return

    chunkTopNull = makePatchedFile(fileData, sectionStart, chunkSize)
    chunkBotNull = makePatchedFile(fileData, sectionStart+chunkSize, chunkSize)

    detectTopNull = scanner.scan(chunkTopNull)
    detectBotNull = scanner.scan(chunkBotNull)

    if detectTopNull and detectBotNull:
        # Both halves are detected
        # Continue scanning both halves independantly, but with each other halve
        # zeroed out (instead of the complete file)
        logging.debug("--> Both halves are detected!")
        
        scanSection(scanner, chunkBotNull, sectionStart, sectionStart+chunkSize, it)
        scanSection(scanner, chunkTopNull, sectionStart+chunkSize, sectionEnd, it)

    elif not detectTopNull and not detectBotNull:
        # both parts arent detected anymore

        if chunkSize < SIG_SIZE:
            # Small enough, no more detections
            logging.debug("No more detection")
            logging.info(f"Result: {sectionStart}-{sectionEnd} ({sectionEnd-sectionStart} bytes)")
            it.add ( Interval(sectionStart, sectionStart+size) )

            #print("Result:")
            #data = fileData[sectionStart:sectionStart+size]
            #print(hexdump.hexdump(data, result='return'))
        else: 
            # make it smaller still. Take complete data (not nulled)
            logging.debug("--> No detections anymore, but too big. Continue anyway...")
            scanSection(scanner, fileData, sectionStart, sectionStart+chunkSize, it)
            scanSection(scanner, fileData, sectionStart+chunkSize, sectionEnd, it)

        #print("TopNull:")
        #data = chunkBotNull[sectionStart:sectionStart+chunkSize]
        #print(hexdump.hexdump(data, result='return'))

        #print("BotNull:")
        #data = chunkTopNull[sectionStart+chunkSize:sectionStart+chunkSize+chunkSize]
        #print(hexdump.hexdump(data, result='return'))

    elif not detectTopNull:
        # Detection in the top half
        logging.debug("--> Do Top")
        scanSection(scanner, fileData, sectionStart, sectionStart+chunkSize, it)
    elif not detectBotNull:
        # Detection in the bottom half
        logging.debug("--> Do Bot")
        scanSection(scanner, fileData, sectionStart+chunkSize, sectionEnd, it)

    return