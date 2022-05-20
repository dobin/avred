#!/usr/bin/python

import logging
import pe_utils

from collections import deque
from concurrent import futures
from intervaltree import Interval, IntervalTree

"""
dependecies: hexdump, intervaltree
todo:
 * pefile -> locate code section
 * sliding window algorithm in order to find a smaller section

"""

interval_tree = IntervalTree()
START_LEAP = 2048
MIN_LEAP = 4 # 4 is like the minimum to work
MAX_THREADS = 10


"""
    used for the progress bar and helps
    estimate the work to be done
"""
def count_max_chunks(size):
    if size <= MIN_LEAP:
        return 0

    return 1 + 2 * count_max_chunks(size//2)



"""
    remove the intervals for which we have a more precise one
    for instance, if we have [10:20] and [0:500], the last one is useless.
    Problem: if [0:5][6:10], it is not correct to delete interval [0:10]
"""
def filter_matches(good_res):
    filtered = IntervalTree() # good_res.copy()

    for match in good_res:
        # if not filtered.containsi(*match):
        #    continue

        # filtered.remove_overlap(match)
        if len(good_res.envelop(match.begin, match.end)) <= 1:
            filtered.add(match)

    return filtered


"""
    replace each half of a file with null bytes and check if it impacts
    the detection verdict. If it does, the half is added to a queue in order
    to improve the precision.
    Problem if each half is detected for now

    buffer:          complete file
    ResultQueue:     to store results
    current_offset:  where in the buffer we are (initially begin of section)
    end:             offset end of the section
    counter:         just informative
    scannner:        which scanner we use
"""
def sigseek(buffer, ResultQueue, current_offset, end, counter, scanner):
    leap = (end - current_offset) // 2
    patch = bytes(chr(0),'ascii') * int(leap)
    nb_chunk = (end - current_offset) // leap if not leap == 0 else 0
    detected_chunks = 0
    bufs = []

    # nb_chunk will always be 2

    #logging.info(f"\t\t[+] {nb_chunk} chunks to process")

    while current_offset < end and leap >= MIN_LEAP:
        #progress.set_postfix(current_offset=current_offset+leap, refresh=True)
        logging.info(f"[-] Patching buffer {len(buffer)} {counter}: offset={current_offset} leap={leap}")
        goat = buffer[:current_offset] + patch + buffer[current_offset+leap:]
        bufs += [goat]

        if not scanner.scan(goat):
            #has_lead = True
            logging.info(f"[+] Found signature between {current_offset} and {current_offset+leap}")
            ResultQueue.append(Interval(int(current_offset), current_offset+leap))
        else:
            #logging.info(f"[-] Current offset = {current_offset}")
            detected_chunks += 1

        current_offset += leap

    if detected_chunks == nb_chunk and detected_chunks > 0:
        logging.info(f"[!] File appears to be detected with several patterns ({detected_chunks})")
        sigseek(bufs[0], ResultQueue, current_offset, end, counter+1000, scanner)
        sigseek(bufs[1], ResultQueue, current_offset-leap, end, counter+5000, scanner)
    elif detected_chunks == 1:
        branch_skipped = count_max_chunks(leap)


def process_file(data, scanner, start = 0, end=-1):
    global interval_tree

    ResultQueue = deque()
    interval_tree = IntervalTree()

    max(len(data), end)
    #total = count_max_chunks(end)
    #logging.info(f"[*] Number of chunks to process: {total}")
    ResultQueue.append(Interval(start, end))
    counter = 0

    with futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as exec:
        to_do = []
        #last_size = 0

        while len(ResultQueue) > 0 or len(to_do) > 0:
            if len(ResultQueue) == 0:
                #logging.debug("\t\t[-] Waiting on results...")
                next(futures.as_completed(to_do)).result()

            counter += 1

            #logging.debug(f"\t\t[*] {len(ResultQueue)} elements in queue...")

            for i in ResultQueue:
                interval_tree.add(i)

            if len(ResultQueue) > 0:
                match = ResultQueue.pop()
            else:
                return

            #last_size = match.end - match.begin
            futur = exec.submit(sigseek, data, ResultQueue, match.begin, match.end, counter, scanner)
            to_do = [futur]


def bytes_detection(data, scanner, start=0, end=-1):
    process_file(data, scanner, start, end)

    good_res = filter_matches(interval_tree)
    good_res.merge_overlaps(strict=False)

    return good_res
