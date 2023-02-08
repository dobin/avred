from model.model import *
from typing import List


def verificationAnalyzer(verifications: List[Verification]) -> VerifyConclusion:
    # 0 MIDDLE8 ISOLATED
    # 1 FULL ISOLATED
    # 2 MIDDLE8 INCREMENTAL
    # 3 FULL INCREMENTAL
    # 4 FULL DECREMENTAL

    verifyResults = []
    res = VerifyStatus.BAD

    for idx, val in enumerate(verifications[0].testEntries):
        # best: Partial modification of an isolated match
        if verifications[0].testEntries[idx].scanResult is ScanResult.NOT_DETECTED:
            res = VerifyStatus.GOOD

        # ok: Full modification of an isolated match
        elif verifications[1].testEntries[idx].scanResult is ScanResult.NOT_DETECTED:
            res = VerifyStatus.OK

        # ok: 
        else:
            if len(verifications) >= 5:
                if idx == 0 or idx == 1:
                    # check FIRST_TWO (first two entries have same result)
                    if verifications[5].testEntries[idx].scanResult is ScanResult.NOT_DETECTED:
                        res = VerifyStatus.OK

                if idx == len(verifications) or idx == len(verifications) - 1:
                    # check LAST_TWO (last two entries have same result)
                    if verifications[5].testEntries[idx].scanResult is ScanResult.NOT_DETECTED:
                        res = VerifyStatus.OK
        
        verifyResults.append(res)

    verifyConclusion = VerifyConclusion(verifyResults)
    return verifyConclusion
