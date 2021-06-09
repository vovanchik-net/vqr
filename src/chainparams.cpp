// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2021 Uladzimir (t.me/crypto_dev)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>
#include <uint256.h>
#include <arith_uint256.h>

#include <assert.h>

#include <chainparamsseeds.h>

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 332127900 << 
        // Mine coins with your mind! https://t.me/VirtualQuestRoom
        ParseHex("4d696e6520636f696e73207769746820796f7572206d696e64212068747470733a2f2f742e6d652f5669727475616c5175657374526f6f6d");
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey << 
        ParseHex("0375e4ed2563156bf9eac1f070ba6c2b7fd5b5e1ad88e04d08f44581cb8223e2d6") << OP_CHECKSIG;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 11;
        consensus.BIP66Height = 11;
        consensus.CSVHeight = 11;
        consensus.WitnessHeight = -1;

        consensus.powLimit = (~arith_uint256 (0)) >> 24;
        consensus.nPowTargetTimespan = 1 * 60 * 60;
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.posLimit = (~arith_uint256 (0)) >> 16;
        consensus.nPosTargetTimespan = 1 * 60 * 60;
        consensus.nPosTargetSpacing = 2.5 * 60;
        consensus.nCoinAgeTick = 2 * 60 * 60;

        consensus.LastPoWHeight = 250;
        consensus.nMasternodePaymentsStartBlock = 1000;
        consensus.nMasternodePaymentsPercent = 20;
        consensus.nMasternodeAmountLock = 100;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork =
            uint256S("0x00"); // 0

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid =
            uint256S("0x00"); // 0

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x56;
        pchMessageStart[1] = 0x51;
        pchMessageStart[2] = 0x52;
        pchMessageStart[3] = 0x43;
        nDefaultPort = 9987;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock (1622948766, 14483663, 0x1e00ffff, 1, 2.5 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("0x000000cf62a52687bab15c359c367b698edca7090b1468aae58b20cdefe63487"));
        assert(genesis.hashMerkleRoot ==
               uint256S("0x43f4af08ec6c49709828c670e1fee467ba3b179c5f1a896defc4ec99ed50d305"));
        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.clear();
        vSeeds.emplace_back("seed.vovanchik.net");
        vSeeds.emplace_back("seed1.vovanchik.net");
        vSeeds.emplace_back("seed2.vovanchik.net");

        base58Prefixes[PUBKEY_ADDRESS] = {0x03, 0x9F, 0x98};
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 173);
        base58Prefixes[SECRET_KEY] = {0x07, 0x23, 0xa9};
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "vqr";

        vFixedSeeds.clear();
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {0, uint256S("0x000000cf62a52687bab15c359c367b698edca7090b1468aae58b20cdefe63487")},
            }
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 11;
        consensus.BIP66Height = 11;
        consensus.CSVHeight = 11;
        consensus.WitnessHeight = -1;

        consensus.powLimit = (~arith_uint256 (0)) >> 24;
        consensus.nPowTargetTimespan = 1 * 60 * 60;
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.posLimit = (~arith_uint256 (0)) >> 16;
        consensus.nPosTargetTimespan = 1 * 60 * 60;
        consensus.nPosTargetSpacing = 2.5 * 60;
        consensus.nCoinAgeTick = 2 * 60 * 60;

        consensus.LastPoWHeight = 250;
        consensus.nMasternodePaymentsStartBlock = 1000;
        consensus.nMasternodePaymentsPercent = 20;
        consensus.nMasternodeAmountLock = 100;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xff;
        pchMessageStart[1] = 0xd2;
        pchMessageStart[2] = 0xc8;
        pchMessageStart[3] = 0x07;
        nDefaultPort = 9987;
        nPruneAfterHeight = 100000;
 
        genesis = CreateGenesisBlock (1622678400, 4463749, 0x1e00ffff, 1, 2.5 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("0x0000000440b7c81e63789188a4a52030f656de441e6b698f1128d6676ad975e6"));
        assert(genesis.hashMerkleRoot ==
               uint256S("0x43f4af08ec6c49709828c670e1fee467ba3b179c5f1a896defc4ec99ed50d305")); 

        vSeeds.clear();
        vSeeds.emplace_back("seed.vovanchik.net");
        vSeeds.emplace_back("seed1.vovanchik.net");
        vSeeds.emplace_back("seed2.vovanchik.net");
        vFixedSeeds.clear();
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        base58Prefixes[PUBKEY_ADDRESS] = {0x0e, 0xe5};
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] = {0x11, 0x30};
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94}; 
        
        bech32_hrp = "test";

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {0, uint256S("0x0000000440b7c81e63789188a4a52030f656de441e6b698f1128d6676ad975e6")},
            }
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
