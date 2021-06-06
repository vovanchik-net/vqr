// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2021 Uladzimir (t.me/crypto_dev)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/fees.h>

#include <policy/policy.h>
#include <txmempool.h>
#include <util.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/wallet.h>

CAmount GetRequiredFee(unsigned int nTxBytes)
{
    return GetRequiredFeeRate().GetFee(nTxBytes);
}

CAmount GetMinimumFee(unsigned int nTxBytes, const CCoinControl& coin_control, const CTxMemPool& pool)
{
    return GetMinimumFeeRate(coin_control, pool).GetFee(nTxBytes);
}

CAmount GetMinimumFee(unsigned int nTxBytes, const CTxMemPool& pool)
{
    return GetMinimumFeeRate(pool).GetFee(nTxBytes);
}

CFeeRate GetMinimumFeeRate(const CCoinControl& coin_control, const CTxMemPool& pool)
{
    int siz = (1*1024*1024*3) / 4;
    CFeeRate feeRate = 10000 * ((pool.GetTotalTxSize() + siz) / siz);
    if (coin_control.fOverrideFeeRate && coin_control.m_feerate)
        feeRate = std::max(*coin_control.m_feerate, feeRate);
    return std::max(feeRate, GetRequiredFeeRate());
}

CFeeRate GetRequiredFeeRate()
{
    return std::max(CFeeRate(10000), ::minRelayTxFee);
}

CFeeRate GetMinimumFeeRate(const CTxMemPool& pool)
{
    CCoinControl coin_control;
    return GetMinimumFeeRate(coin_control, pool);
}

// GetDiscardRate -> dustRelayFee
