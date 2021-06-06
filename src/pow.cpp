// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2021 Uladzimir (t.me/crypto_dev)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
//#include <logging.h>

//pos: find last block index up to pindex
const CBlockIndex *GetLastBlockIndex(const CBlockIndex *pindex, const Consensus::Params &params, bool fProofOfStake) {
    if (fProofOfStake) {
        while (pindex && pindex->pprev && !pindex->IsProofOfStake()) {
            pindex = pindex->pprev;
        }
    } else {
        while (pindex && pindex->pprev && pindex->IsProofOfStake())
            pindex = pindex->pprev;
    }

    return pindex;
}

uint32_t GetNextWorkRequired(const CBlockIndex *pindexLast, const CBlockHeader *pblock, const Consensus::Params &params) {
    assert(pindexLast != nullptr);
    bool fProofOfStake = pblock->IsProofOfStake();
    arith_uint256 bnOld, bnNew, bnLimit = fProofOfStake ? params.posLimit : params.powLimit;
    const CBlockIndex* pPrev = pindexLast;
    while (pPrev && (pPrev->IsProofOfStake() != fProofOfStake)) pPrev = pPrev->pprev;
    int64_t srcTimes = 0;
    int64_t destTimes = fProofOfStake ? params.nPosTargetTimespan : params.nPowTargetTimespan;
    int destBlockCount = destTimes / (fProofOfStake ? params.nPosTargetSpacing : params.nPowTargetSpacing);
//  LogPrintf ("__diff: cnt = %d\n", destBlockCount);
    if (pPrev && (pindexLast->nHeight - pPrev->nHeight > destBlockCount)) {
//  LogPrintf ("__diff: >>>\n");
        bnNew = arith_uint256().SetCompact(pPrev->nBits) << 3;
        if (bnNew > bnLimit) bnNew = bnLimit;
        return bnNew.GetCompact();
    }
    for (int i = 0; i < destBlockCount; i++) {
        if (pPrev == nullptr) return bnLimit.GetCompact();
        if (i == 0) { bnOld.SetCompact (pPrev->nBits); }
        bnNew += arith_uint256().SetCompact(pPrev->nBits);
        const CBlockIndex* pPrevPrev = pPrev->pprev;
        while (pPrevPrev && (pPrevPrev->IsProofOfStake() != fProofOfStake)) pPrevPrev = pPrevPrev->pprev;
        if (pPrevPrev == nullptr) return bnLimit.GetCompact();
        srcTimes += std::max(pPrev->GetBlockTime() - pPrevPrev->GetBlockTime(), (int64_t)0);
        pPrev = pPrevPrev;
    }
//  LogPrintf ("__diff: srс %d vs dest %d\n", srcTimes, destTimes);
    bnNew /= destBlockCount * destTimes;
    bnNew *= srcTimes;
    if (bnNew > (bnOld << 2)) bnNew = bnOld << 2;
    if (bnNew < (bnOld >> 3)) bnNew = bnOld >> 3;
    if (bnNew > bnLimit) bnNew = bnLimit;
    return bnNew.GetCompact();
}
