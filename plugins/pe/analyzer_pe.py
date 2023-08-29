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
    isolate = analyzerOptions.get("isolate", False)
    scanSpeed = analyzerOptions.get("scanSpeed", ScanSpeed.Normal)
    scanInfo = ScanInfo(scanner.scanner_name, scanSpeed)

    # prepare the reducer with the file
    timeStart = time.time()
    matches, scanPipe = scanForMatchesInPe(filePe, scanner, reducer, isolate)
    scanInfo.scanDuration = round(time.time() - timeStart)
    scanInfo.scannerPipe = scanPipe
    scanInfo.chunksTested = reducer.chunks_tested
    scanInfo.matchesAdded = reducer.matchesAdded

    return matches, scanInfo


def scanForMatchesInPe(filePe: FilePe, scanner: Scanner, reducer: Reducer, isolate=False) -> Tuple[List[Match], str]:
    """Scans a PE file given with filePe with Scanner scanner. Returns all matches"""
    scanStages = []
    matches: List[Match] = []

    # identify which sections get detected
    # default is to not-isolate
    detected_sections = []
    if isolate:
        logging.info("Section Detection: Isolating sections (zero all others)")
        scanStages.append('ident:zero-nontarget-sections')
        detected_sections = findDetectedSectionsIsolate(filePe, scanner)
    else:
        logging.info("Section Detection: Zero section (leave all others intact)")
        scanStages.append('ident:zero-target-section')
        detected_sections = findDetectedSections(filePe, scanner)
    logging.info(f"{len(detected_sections)} section(s) trigger the antivirus independantly")
    for section in detected_sections:
        logging.info(f"  section: {section.name}")

    moreMatches: List[Match] = []
    if len(detected_sections) == 0:
        logging.info("Section analysis failed. Fall back to non-section-aware reducer (flat-scan)")
        scanStages.append('scan:flat_1')
        
        # start at .text section, which is usually the first one. Offset 512
        # this will skip scanning of PE headers, which gives unecessary false positives
        offsetStart = filePe.sectionsBag.getSectionByName(".text").addr
        offsetEnd = filePe.Data().getLength()
        moreMatches = reducer.scan(offsetStart, offsetEnd)
        matches += moreMatches
    else:
        # analyze each detected section
        scanStages.append('scan:by-section')
        for section in detected_sections:
            # check first if its hash based (rare)
            logging.info("Check if hash on section:{} start:{} size:{}".format(section.name, section.addr, section.size))
            if scanIsHash(filePe, scanner, section.addr, section.size):
                logging.info("Section {} appears to be hash checked.")
                matches.append(Match(len(matches), section.addr, section.size, 0))
            else:
                logging.info(f"Section {section.name} is not identified by hash")
                logging.info(f"Launching bytes analysis on section: {section.name} ({section.addr}-{section.addr+section.size})")
                moreMatches = reducer.scan(
                    offsetStart=section.addr, 
                    offsetEnd=section.addr+section.size)
                matches += moreMatches

        # there are instances where the section-based scanning does not yield any result.
        if len(moreMatches) == 0:
            # do it again with a flat-scan
            logging.info("Section based analysis failed, no matches. Fall back to non-section-aware reducer (flat-scan)")
            scanStages.append('scan:flat_2')
            moreMatches = reducer.scan(
                offsetStart=filePe.sectionsBag.getSectionByName(".text").addr, # start at .code, skip header(s)
                offsetEnd=filePe.Data().getLength())
            matches += moreMatches

    return sorted(matches), " -> ".join(scanStages)


def findDetectedSections(filePe: FilePe, scanner) -> List[Section]:
    """hide each section of filePe, return the ones which wont be detected anymore (have a dominant influence)"""
    detected_sections: List[Section] = []

    for idx, section in enumerate(filePe.sectionsBag.sections):
        filePeCopy = deepcopy(filePe)
        filePeCopy.hideSection(section)
        detected = scanner.scannerDetectsBytes(filePeCopy.DataAsBytes(), filePeCopy.filename)
        if not detected:
            # always store scan result
            filePe.sectionsBag.sections[idx].detected = True

            # only return if we should scan it
            if section.scan:
                detected_sections += [section]

        logging.info(f"Hide: {section.name} -> Detected: {detected} (to scan: {section.scan})")

    return detected_sections


def findDetectedSectionsIsolate(filePe: FilePe, scanner) -> List[Section]:
    """for each section, hide everything except it (isolate), and return which one gets detected (have a dominant influence)"""
    detected_sections = []

    for idx, section in enumerate(filePe.sectionsBag.sections):
        filePeCopy = deepcopy(filePe)
        filePeCopy.hideAllSectionsExcept(section.name)
        detected = scanner.scannerDetectsBytes(filePeCopy.DataAsBytes(), filePeCopy.filename)

        if not detected:
            # always store scan result
            filePe.sectionsBag.sections[idx].detected = True

            # only return if we should scan it
            if section.scan:
                detected_sections += [section]

        logging.info(f"Hide all except: {section.name} -> Detected: {detected}  (to scan: {section.scan})")

    return detected_sections
