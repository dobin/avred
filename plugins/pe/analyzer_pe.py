import logging
from copy import deepcopy
from myutils import *
import time
import datetime
from typing import List, Tuple

from reducer import Reducer
from model.model_base import Scanner, ScanInfo, ScanSpeed
from model.model_data import Match
from model.model_code import Section
from plugins.pe.file_pe import FilePe
from scanning import scanIsHash


def analyzeFilePe(filePe: FilePe, scanner: Scanner, reducer: Reducer, analyzerOptions={}) -> Tuple[Match, ScanInfo]:
    """Scans a PE file given with filePe with Scanner scanner. Returns all matches and ScanInfo"""
    scanSpeed = analyzerOptions.get("scanSpeed", ScanSpeed.Normal)
    scanInfo = ScanInfo(scanner.scanner_name, scanSpeed)

    # prepare the reducer with the file
    timeStart = time.time()
    matches = scanForMatchesInPe(filePe, scanner, reducer)
    scanInfo.scanDuration = round(time.time() - timeStart)
    scanInfo.chunksTested = reducer.chunks_tested
    scanInfo.matchesAdded = reducer.matchesAdded

    return matches, scanInfo


def scanForMatchesInPe(filePe: FilePe, scanner: Scanner, reducer: Reducer) -> List[Match]:
    """Scans a PE file given with filePe with Scanner scanner. Returns all matches"""
    matches: List[Match] = []

    # identify which sections get detected
    scan_sections = filePe.getScanSections()
    detected_sections = []
    logging.info("Section Detection: Zero section (leave all others intact)")
    detected_sections = findDetectedSections(filePe, scan_sections, scanner)
    logging.info(f"{len(detected_sections)} section(s) trigger the antivirus independantly")
    for section in detected_sections:
        logging.info(f"  section: {section.name}")

    moreMatches: List[Match] = []
    if len(detected_sections) == 0:
        logging.info("Section analysis failed. Fall back to non-section-aware reducer (flat-scan)")
        # start at .text section, which is usually the first one. Offset 512
        # this will skip scanning of PE headers, which gives unecessary false positives
        offsetStart = filePe.peSectionsBag.getSectionByName(".text").physaddr
        offsetEnd = filePe.Data().getLength()
        moreMatches = reducer.scan(offsetStart, offsetEnd)
        matches += moreMatches
    else:
        # analyze each detected section
        for section in detected_sections:
            # check first if its hash based (rare)
            logging.info("Check if hash on section:{} start:{} size:{}".format(section.name, section.physaddr, section.size))
            if scanIsHash(filePe, scanner, section.physaddr, section.size):
                logging.info("Section {} appears to be hash checked.")
                matches.append(Match(len(matches), section.physaddr, section.size, 0))
            else:
                logging.info(f"Section {section.name} is not identified by hash")
                logging.info(f"Launching bytes analysis on section: {section.name} ({section.physaddr}-{section.physaddr+section.size})")
                moreMatches = reducer.scan(
                    offsetStart=section.physaddr, 
                    offsetEnd=section.physaddr+section.size)
                matches += moreMatches
                if len(moreMatches) > 0:
                    section.detected = True

    return sorted(matches)


def findDetectedSections(filePe: FilePe, scan_sections: List[Section], scanner) -> List[Section]:
    """hide each section of filePe, return the ones which wont be detected anymore (have a dominant influence)"""
    detected_sections: List[Section] = []

    for idx, section in enumerate(scan_sections):
        if not section.scan:
            logging.warn("Wanted to scan a scan_section, but its set to not to be scanned: {}".format(section.name))
            continue

        filePeCopy = deepcopy(filePe)
        filePeCopy.hideSection(section)
        detected = scanner.scannerDetectsBytes(filePeCopy.DataAsBytes(), filePeCopy.filename)
        if not detected:
            # always store scan result
            section.detected = True
            detected_sections += [section]

        logging.info(f"Hide: {section.name} -> Detected: {detected} (to scan: {section.scan})")

    return detected_sections
