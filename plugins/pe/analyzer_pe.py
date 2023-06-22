import logging
from copy import deepcopy
from utils import *
from reducer import Reducer
from typing import List, Tuple

from model.model_base import Scanner
from model.model_data import Match
from model.model_code import Section
from plugins.pe.file_pe import FilePe


def analyzeFilePe(filePe: FilePe, scanner: Scanner, analyzerOptions={}) -> Tuple[Match, str]:
    """Scans a PE file given with filePe with Scanner scanner. Returns all matches."""
    isolate = analyzerOptions.get("isolate", False)

    matches, scannerInfo = scanForMatchesInPe(filePe, scanner, isolate,)
    return matches, scannerInfo


def scanForMatchesInPe(filePe: FilePe, scanner, isolate=False) -> Tuple[List[Match], str]:
    scannerInfos = []
    matches: List[Match] = []

    # identify which sections get detected
    # default is to not-isolate
    detected_sections = []
    if isolate:
        logging.info("Section Detection: Isolating sections (zero all others)")
        scannerInfos.append('zero-nontarget-sections')
        detected_sections = findDetectedSectionsIsolate(filePe, scanner)
    else:
        logging.info("Section Detection: Zero section (leave all others intact)")
        scannerInfos.append('zero-target-section')
        detected_sections = findDetectedSections(filePe, scanner)
    logging.info(f"{len(detected_sections)} section(s) trigger the antivirus independantly")
    for section in detected_sections:
        logging.info(f"  section: {section.name}")

    # prepare the reducer with the file, and reduce it
    reducer = Reducer(filePe, scanner)
    moreMatches: List[Match] = []
    if len(detected_sections) == 0:
        logging.info("Section analysis failed. Fall back to non-section-aware reducer")
        scannerInfos.append('flat-scan1')
        moreMatches = reducer.scan(
            offsetStart=filePe.sectionsBag.getSectionByName(".text").addr, # start at .code, skip header(s)
            offsetEnd=filePe.Data().getLength())
    else:
        # analyze each detected section
        for section in detected_sections:
            logging.info(f"Launching bytes analysis on section: {section.name} ({section.addr}-{section.addr+section.size})")
            moreMatches = reducer.scan(
                offsetStart=section.addr, 
                offsetEnd=section.addr+section.size)

        if len(matches) > 0:
            # only append section-scan indicator if it yielded results, see below
            scannerInfos.append('section-scan')
        else:
            # there are instances where the section-based scanning does not yield any result.
            # do it again without it
            logging.info("Section based analysis failed, no matches. Fall back to non-section-aware reducer")
            scannerInfos.append('flat-scan2')
            moreMatches = reducer.scan(
                offsetStart=filePe.sectionsBag.getSectionByName(".text").addr, # start at .code, skip header(s)
                offsetEnd=filePe.Data().getLength())

    matches += moreMatches
    return sorted(matches), ",".join(scannerInfos)


def findDetectedSections(filePe: FilePe, scanner) -> List[Section]:
    """hide each section of filePe, return the ones which wont be detected anymore (have a dominant influence)"""
    detected_sections: List[Section] = []

    for section in filePe.sectionsBag.sections:
        if not section.scan:
            continue
        filePeCopy = deepcopy(filePe)

        #logging.info("Hide section: {}  start: {}  size: {}".format(section.name, section.addr, section.size))
        filePeCopy.hideSection(section)
        status = scanner.scannerDetectsBytes(filePeCopy.DataAsBytes(), filePeCopy.filename)
        if not status:
            detected_sections += [section]

        logging.info(f"Hide: {section.name} -> Detected: {status}")

    return detected_sections


def findDetectedSectionsIsolate(filePe: FilePe, scanner) -> List[Section]:
    """for each section, hide everything except it (isolate), and return which one gets detected (have a dominant influence)"""
    detected_sections = []

    for section in filePe.sectionsBag.sections:
        if not section.scan:
            continue
        filePeCopy = deepcopy(filePe)
        filePeCopy.hideAllSectionsExcept(section.name)
        status = scanner.scannerDetectsBytes(filePeCopy.DataAsBytes(), filePeCopy.filename)

        if status:
            detected_sections += [section]

        logging.info(f"Hide all except: {section.name} -> Detected: {status}")

    return detected_sections
