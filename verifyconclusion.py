from model.model import *
from typing import List


def verificationAnalyzer(verifications: List[Verification]) -> VerifyConclusion:
    # 0 MIDDLE8 ISOLATED
    # 1 FULL ISOLATED
    # 2 MIDDLE8 INCREMENTAL
    # 3 FULL INCREMENTAL
    # 4 FULL DECREMENTAL

    verifyResults = []
    res = VerifyStatus.UNKNOWN

    for idx, val in enumerate(verifications[0].testEntries):
        if not verifications[0].testEntries[idx]:
            res = VerifyStatus.GOOD

        elif not verifications[1].testEntries[idx]:
            res = VerifyStatus.OK

        else:
            res = VerifyStatus.BAD
        
        verifyResults.append(res)

    verifyConclusion = VerifyConclusion(verifyResults)
    return verifyConclusion
