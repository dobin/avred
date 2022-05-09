#!/usr/bin/python

import logging
import string
import sys
from collections import deque
from concurrent import futures

import hexdump
from capstone import *
from intervaltree import Interval, IntervalTree
from tqdm import tqdm

import config
import pe_utils

logging.basicConfig(filename='debug.log',
                    filemode='a',
                    format='[%(levelname)-8s][%(asctime)s][%(filename)s:%(lineno)3d] %(funcName)s() :: %(message)s',
                    datefmt='%Y/%m/%d %H:%M',
                    level=logging.DEBUG)

"""
dependecies: hexdump, intervaltree
todo:
 * pefile -> locate code section
 * sliding window algorithm in order to find a smaller section

"""

ResultQueue = deque()
interval_tree = IntervalTree()
START_LEAP = 2048
MIN_LEAP = 16
IGNORE_START = 0
IGNORE_END = 0x256 #todo use pefile to find the start of code
GOAT_FILE = '/tmp/metsrv.x64.dll'
WDEFENDER_INSTALL_PATH = config.get_value("loadlibrary_path_dir")
MAX_THREADS = 10
DEBUG_LEVEL = 1
buffer = []
goat = []
res = {}
has_lead = False
#progress = 0
cs = Cs(CS_ARCH_X86, CS_MODE_64)
cs.detail = True
cs.skipdata = True



def print_disass(base, code_size, raw_code):
    code_base = base
    if code_base == 0:
        code_base = 0x1000

    for i in cs.disasm(raw_code, code_base):
        if i > 256:
            break
        logging.info("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


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

        try:
            # filtered.remove_overlap(match)
            if len(good_res.envelop(match.begin, match.end)) <= 1:
                filtered.add(match)
        except Exception as e:
            logging.warning(f"Exception encountered ({e.args}). Spawning IPython shell to debug...")
            import traceback
            traceback.format_exc()
            if not "IPython" in sys.modules:
                import IPython
                IPython.embed()


    return filtered

"""
    get strings from binary blob
"""
def strings(binary, min=4):
    result = ""
    for c in binary:
        c = chr(c)
        if c in string.printable[:-5]:
            result += c
            continue
        if len(result) >= min:
            yield result
        result = ""
    if len(result) >= min:  # catch result at EOF
        yield result


"""
    replace each half of a file with null bytes and check if it impacts
    the detection verdict. If it does, the half is added to a queue in order
    to improve the precision.
    Problem if each half is detected for now
"""
def sigseek(buffer, current_offset, end, counter, scanner):
    #global progress
    leap = (end - current_offset) // 2
    patch = bytes(chr(0),'ascii')*int(leap)
    nb_chunk = (end - current_offset) // leap if not leap == 0 else 0
    detected_chunks = 0
    bufs = []

    #logging.info(f"\t\t[+] {nb_chunk} chunks to process")

    while current_offset < end and leap >= MIN_LEAP:
        #progress.set_postfix(current_offset=current_offset+leap, refresh=True)
        logging.info(f"[+] Patching buffer of size = {len(buffer)}, offset = {current_offset}, leap = {leap}")
        goat = buffer[:current_offset] + patch + buffer[current_offset+leap:]
        bufs += [goat]

        #filepath = GOAT_FILE + "_"+str(counter)
        #with open(filepath,'wb') as fw:
        #    fw.write(goat)

        if not scanner.scan(goat):
            has_lead = True
            logging.info(f"[+] Found signature between {current_offset} and {current_offset+leap}")
            ResultQueue.append(Interval(int(current_offset), current_offset+leap))
            #progress.update(1)

        else:
            logging.info(f"[-] Current offset = {current_offset}")
            detected_chunks += 1

        current_offset += leap

    if detected_chunks == nb_chunk and detected_chunks > 0:
        logging.info(f"[!] File appears to be detected with several patterns ({detected_chunks})")
        sigseek(bufs[0], current_offset, end, counter+1000, scanner)
        sigseek(bufs[1], current_offset-leap, end, counter+5000, scanner)
    elif detected_chunks == 1:
        branch_skipped = count_max_chunks(leap)
        #progress.update(branch_skipped)


def locate_found_signatures(filename, interval_tree):
    pe = pe_utils.PE()
    pe.filename=filename
    sections = pe_utils.get_sections(pe)

    for interval in interval_tree:
        for section in sections:
            if interval.begin >= section.addr and interval.end < section.addr + section.size:
                logging.info(f"Signature in {section.name} section ({interval.begin} to {interval.end})")
#            else:
#                section_begin = next(section for section in sections if
#                                    section.addr <= interval.begin < (section.addr + section.size))
#
#                section_end = next(section for section in sections if
#                                    section.addr <= interval.end < (section.addr + section.size))
#                logging.info(f"Signature crossing two sections: {section_begin.name} and {section_end.name}  ({interval.begin} to {interval.end})")

"""
    pretty print the results with hexdumps
"""
def clean_results(filename):
    global START_LEAP
    global buffer

    logging.info(f"[*] Got {len(interval_tree)} signatures, filtering...")
    good_res = filter_matches(interval_tree)
    logging.info(f"[*] Filtered {len(interval_tree) - len(good_res)} signatures...")
    locate_found_signatures(filename, good_res)

    logging.info(f"[*] Got {len(good_res)} signatures...")
    logging.info("[+] Here are the potential findings:")

    for i in sorted(good_res):
        leap = i.end - i.begin

        if not leap < len(buffer) // 2:
            logging.info(f"\t\t[-] Skipping because leap ({leap}) is bigger than initial value")
            continue

        dump_path = "/tmp/goat_"+str(i.begin)+"-"+str(i.end)+".bin"
        sig = buffer[i.begin:i.end]

        #patch = leap * bytes(chr(0),'ascii')
        #goat = buffer[:i.begin] + patch + buffer[i.end:]

        with open(dump_path, "wb") as fd:
            #fd.write(goat)
            fd.write(sig)

        print(f"[*] Signature between {i.begin} and {i.end} dumped at {dump_path}:")
        print(hexdump.hexdump(sig, result='return'))

        #logging.info("[*] Strings:")
        #for s in strings(sig):
        #    logging.info(f"> {s}")
        #    pass

        #try:
        #    logging.info("[*] Disassembly (x64):")
        #    print_disass(i.begin, leap, sig)
        #except:
        #    logging.error("Disassembly failed")

    #logging.info("[*] Done")

"""
    used for the progress bar and helps
    estimate the work to be done
"""
def count_max_chunks(size):
    if size <= MIN_LEAP:
        return 0

    return 1 + 2 * count_max_chunks(size//2)


"""
    main function
"""
def process_file(sample_file, scanner, start = 0, end=-1):
    global interval_tree
    global ResultQueue
    global buffer
    #global progress

    with open(sample_file, 'rb') as f:
        buffer = f.read()

    max(len(buffer), end)
    #total = count_max_chunks(end)
    #logging.info(f"[*] Number of chunks to process: {total}")
    #progress = tqdm(total=total, leave=False)
    ResultQueue.append(Interval(start, end))
    counter = 0

    with futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as exec:
        to_do = []
        last_size = 0

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

            last_size = match.end - match.begin
            futur = exec.submit(sigseek, buffer, match.begin, match.end, counter, scanner)
            to_do = [futur]
    #progress.clear()
    #progress.close()


def bytes_detection(filename, scanner, start=0, end=-1):
    sample_file = filename

    pe = pe_utils.PE()
    pe.filename = sample_file
    new_pe = pe_utils.backup_pe(pe)
    process_file(new_pe.filename, scanner, start, end)
    
    good_res = filter_matches(interval_tree)
    return good_res

        #clean_results(filename)
        #logging.info("[*] Done ! Press any to exit...")


if __name__ == "__main__":
    if len(sys.argv) > 1:
       sample_file = sys.argv[1]

    else:
        exit(-1)

    bytes_detection(sample_file)



