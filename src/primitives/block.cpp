// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2021 Uladzimir (t.me/crypto_dev)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>
#include <crypto/common.h>
#include <chainparams.h>

uint256 CBlockHeader::GetPoWHash() const {
    CHashWriter writer(SER_GETHASH, PROTOCOL_VERSION);
    ::Serialize(writer, *this);
    return writer.GetHash();
}

uint256 CBlockHeader::GetPoSHash(const COutPoint &out) const {
    CHashWriter writer(SER_GETHASH, PROTOCOL_VERSION);
    writer << out.n << hashPrevBlock << out.hash << nTime << nBits << (uint32_t)0;
    return writer.GetHash();
}

uint256 CBlockHeader::GetHash() const {
    CHashWriter writer(SER_GETHASH, PROTOCOL_VERSION);
    ::Serialize(writer, *this);
    return writer.GetHash();
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
