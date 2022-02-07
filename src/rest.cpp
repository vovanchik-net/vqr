// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2021 Uladzimir (t.me/crypto_dev)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <core_io.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <validation.h>
#include <txdb.h>
#include <net.h>
#include <net_processing.h>
#include <key_io.h>
#include <httpserver.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <streams.h>
#include <sync.h>
#include <txmempool.h>
#include <utilstrencodings.h>
#include <version.h>
#include <policy/policy.h>
#include <consensus/validation.h>
#include <masternode.h>

#include <boost/algorithm/string.hpp>

#include <univalue.h>

static const size_t MAX_GETUTXOS_OUTPOINTS = 15; //allow a max of 15 outpoints to be queried at once

enum class RetFormat {
    UNDEF,
    BINARY,
    HEX,
    JSON,
};

static const struct {
    RetFormat rf;
    const char* name;
} rf_names[] = {
      {RetFormat::UNDEF, ""},
      {RetFormat::BINARY, "bin"},
      {RetFormat::HEX, "hex"},
      {RetFormat::JSON, "json"},
};

struct CCoin {
    uint32_t nHeight;
    CTxOut out;

    ADD_SERIALIZE_METHODS;

    CCoin() : nHeight(0) {}
    explicit CCoin(Coin&& in) : nHeight(in.nHeight), out(std::move(in.out)) {}

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        uint32_t nTxVerDummy = 0;
        READWRITE(nTxVerDummy);
        READWRITE(nHeight);
        READWRITE(out);
    }
};

static bool RESTERR(HTTPRequest* req, enum HTTPStatusCode status, std::string message)
{
    req->WriteHeader("Content-Type", "text/plain");
    req->WriteReply(status, message + "\r\n");
    return false;
}

static RetFormat ParseDataFormat(std::string& param, const std::string& strReq)
{
    const std::string::size_type pos = strReq.rfind('.');
    if (pos == std::string::npos)
    {
        param = strReq;
        return rf_names[3].rf;
    }

    param = strReq.substr(0, pos);
    const std::string suff(strReq, pos + 1);

    for (unsigned int i = 0; i < ARRAYLEN(rf_names); i++)
        if (suff == rf_names[i].name)
            return rf_names[i].rf;

    /* If no suffix is found, return original string.  */
    param = strReq;
    return rf_names[0].rf;
}

static std::string AvailableDataFormatsString()
{
    std::string formats;
    for (unsigned int i = 0; i < ARRAYLEN(rf_names); i++)
        if (strlen(rf_names[i].name) > 0) {
            formats.append(".");
            formats.append(rf_names[i].name);
            formats.append(", ");
        }

    if (formats.length() > 0)
        return formats.substr(0, formats.length() - 2);

    return formats;
}

static bool ParseHashStr(const std::string& strReq, uint256& v)
{
    if (!IsHex(strReq) || (strReq.size() != 64))
        return false;

    v.SetHex(strReq);
    return true;
}

static bool CheckWarmup(HTTPRequest* req)
{
    std::string statusmessage;
    if (RPCIsInWarmup(&statusmessage))
         return RESTERR(req, HTTP_SERVICE_UNAVAILABLE, "Service temporarily unavailable: " + statusmessage);
    return true;
}

static bool rest_headers(HTTPRequest* req,
                         const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string param;
    const RetFormat rf = ParseDataFormat(param, strURIPart);
    std::vector<std::string> path;
    boost::split(path, param, boost::is_any_of("/"));

    if (path.size() != 2)
        return RESTERR(req, HTTP_BAD_REQUEST, "No header count specified. Use /rest/headers/<count>/<hash>.<ext>.");

    long count = strtol(path[0].c_str(), nullptr, 10);
    if (count < 1 || count > 2000)
        return RESTERR(req, HTTP_BAD_REQUEST, "Header count out of range: " + path[0]);

    std::string hashStr = path[1];
    uint256 hash;
    if (!ParseHashStr(hashStr, hash))
        return RESTERR(req, HTTP_BAD_REQUEST, "Invalid hash: " + hashStr);

    std::vector<const CBlockIndex *> headers;
    headers.reserve(count);
    {
        LOCK(cs_main);
        const CBlockIndex* pindex = LookupBlockIndex(hash);
        while (pindex != nullptr && chainActive.Contains(pindex)) {
            headers.push_back(pindex);
            if (headers.size() == (unsigned long)count)
                break;
            pindex = chainActive.Next(pindex);
        }
    }

    CDataStream ssHeader(SER_NETWORK, PROTOCOL_VERSION);
    for (const CBlockIndex *pindex : headers) {
        ssHeader << pindex->GetBlockHeader();
    }

    switch (rf) {
    case RetFormat::BINARY: {
        std::string binaryHeader = ssHeader.str();
        req->WriteHeader("Content-Type", "application/octet-stream");
        req->WriteReply(HTTP_OK, binaryHeader);
        return true;
    }

    case RetFormat::HEX: {
        std::string strHex = HexStr(ssHeader.begin(), ssHeader.end()) + "\n";
        req->WriteHeader("Content-Type", "text/plain");
        req->WriteReply(HTTP_OK, strHex);
        return true;
    }
    case RetFormat::JSON: {
        UniValue jsonHeaders(UniValue::VARR);
        {
            LOCK(cs_main);
            for (const CBlockIndex *pindex : headers) {
                jsonHeaders.push_back(blockheaderToJSON(pindex));
            }
        }
        std::string strJSON = jsonHeaders.write() + "\n";
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strJSON);
        return true;
    }
    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: .bin, .hex)");
    }
    }
}

static bool rest_block(HTTPRequest* req,
                       const std::string& strURIPart,
                       bool showTxDetails)
{
    if (!CheckWarmup(req))
        return false;
    std::string hashStr;
    const RetFormat rf = ParseDataFormat(hashStr, strURIPart);

    uint256 hash;
    if (!ParseHashStr(hashStr, hash))
        return RESTERR(req, HTTP_BAD_REQUEST, "Invalid hash: " + hashStr);

    CBlock block;
    CBlockIndex* pblockindex = nullptr;
    {
        LOCK(cs_main);
        pblockindex = LookupBlockIndex(hash);
        if (!pblockindex) {
            return RESTERR(req, HTTP_NOT_FOUND, hashStr + " not found");
        }

        if (IsBlockPruned(pblockindex))
            return RESTERR(req, HTTP_NOT_FOUND, hashStr + " not available (pruned data)");

        if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
            return RESTERR(req, HTTP_NOT_FOUND, hashStr + " not found");
    }

    CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION | RPCSerializationFlags());
    ssBlock << block;

    switch (rf) {
    case RetFormat::BINARY: {
        std::string binaryBlock = ssBlock.str();
        req->WriteHeader("Content-Type", "application/octet-stream");
        req->WriteReply(HTTP_OK, binaryBlock);
        return true;
    }

    case RetFormat::HEX: {
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end()) + "\n";
        req->WriteHeader("Content-Type", "text/plain");
        req->WriteReply(HTTP_OK, strHex);
        return true;
    }

    case RetFormat::JSON: {
        UniValue objBlock;
        {
            LOCK(cs_main);
            objBlock = blockToJSON(block, pblockindex, showTxDetails);
        }
        std::string strJSON = objBlock.write() + "\n";
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strJSON);
        return true;
    }

    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: " + AvailableDataFormatsString() + ")");
    }
    }
}

static bool rest_block_extended(HTTPRequest* req, const std::string& strURIPart)
{
    return rest_block(req, strURIPart, true);
}

static bool rest_block_notxdetails(HTTPRequest* req, const std::string& strURIPart)
{
    return rest_block(req, strURIPart, false);
}

// A bit of a hack - dependency on a function defined in rpc/blockchain.cpp
UniValue getblockchaininfo(const JSONRPCRequest& request);

static bool rest_chaininfo(HTTPRequest* req, const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string param;
    const RetFormat rf = ParseDataFormat(param, strURIPart);

    switch (rf) {
    case RetFormat::JSON: {
        JSONRPCRequest jsonRequest;
        jsonRequest.params = UniValue(UniValue::VARR);
        UniValue chainInfoObject = getblockchaininfo(jsonRequest);
        std::string strJSON = chainInfoObject.write() + "\n";
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strJSON);
        return true;
    }
    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: json)");
    }
    }
}

static bool rest_mempool_info(HTTPRequest* req, const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string param;
    const RetFormat rf = ParseDataFormat(param, strURIPart);

    switch (rf) {
    case RetFormat::JSON: {
        UniValue mempoolInfoObject = mempoolInfoToJSON();

        std::string strJSON = mempoolInfoObject.write() + "\n";
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strJSON);
        return true;
    }
    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: json)");
    }
    }
}

static bool rest_mempool_contents(HTTPRequest* req, const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string param;
    const RetFormat rf = ParseDataFormat(param, strURIPart);

    switch (rf) {
    case RetFormat::JSON: {
        UniValue mempoolObject = mempoolToJSON(true);

        std::string strJSON = mempoolObject.write() + "\n";
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strJSON);
        return true;
    }
    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: json)");
    }
    }
}

static bool rest_tx(HTTPRequest* req, const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string hashStr;
    const RetFormat rf = ParseDataFormat(hashStr, strURIPart);

    uint256 hash;
    if (!ParseHashStr(hashStr, hash))
        return RESTERR(req, HTTP_BAD_REQUEST, "Invalid hash: " + hashStr);

    CTransactionRef tx;
    uint256 hashBlock = uint256();
    if (!GetTransaction(hash, tx, Params().GetConsensus(), hashBlock, true))
        return RESTERR(req, HTTP_NOT_FOUND, hashStr + " not found");

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | RPCSerializationFlags());
    ssTx << tx;

    switch (rf) {
    case RetFormat::BINARY: {
        std::string binaryTx = ssTx.str();
        req->WriteHeader("Content-Type", "application/octet-stream");
        req->WriteReply(HTTP_OK, binaryTx);
        return true;
    }

    case RetFormat::HEX: {
        std::string strHex = HexStr(ssTx.begin(), ssTx.end()) + "\n";
        req->WriteHeader("Content-Type", "text/plain");
        req->WriteReply(HTTP_OK, strHex);
        return true;
    }

    case RetFormat::JSON: {
        UniValue objTx(UniValue::VOBJ);
        TxToUniv(*tx, hashBlock, objTx);
        std::string strJSON = objTx.write() + "\n";
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strJSON);
        return true;
    }

    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: " + AvailableDataFormatsString() + ")");
    }
    }
}

static bool rest_getutxos(HTTPRequest* req, const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string param;
    const RetFormat rf = ParseDataFormat(param, strURIPart);

    std::vector<std::string> uriParts;
    if (param.length() > 1)
    {
        std::string strUriParams = param.substr(1);
        boost::split(uriParts, strUriParams, boost::is_any_of("/"));
    }

    // throw exception in case of an empty request
    std::string strRequestMutable = req->ReadBody();
    if (strRequestMutable.length() == 0 && uriParts.size() == 0)
        return RESTERR(req, HTTP_BAD_REQUEST, "Error: empty request");

    bool fInputParsed = false;
    bool fCheckMemPool = false;
    std::vector<COutPoint> vOutPoints;

    // parse/deserialize input
    // input-format = output-format, rest/getutxos/bin requires binary input, gives binary output, ...

    if (uriParts.size() > 0)
    {
        //inputs is sent over URI scheme (/rest/getutxos/checkmempool/txid1-n/txid2-n/...)
        if (uriParts[0] == "checkmempool") fCheckMemPool = true;

        for (size_t i = (fCheckMemPool) ? 1 : 0; i < uriParts.size(); i++)
        {
            uint256 txid;
            int32_t nOutput;
            std::string strTxid = uriParts[i].substr(0, uriParts[i].find('-'));
            std::string strOutput = uriParts[i].substr(uriParts[i].find('-')+1);

            if (!ParseInt32(strOutput, &nOutput) || !IsHex(strTxid))
                return RESTERR(req, HTTP_BAD_REQUEST, "Parse error");

            txid.SetHex(strTxid);
            vOutPoints.push_back(COutPoint(txid, (uint32_t)nOutput));
        }

        if (vOutPoints.size() > 0)
            fInputParsed = true;
        else
            return RESTERR(req, HTTP_BAD_REQUEST, "Error: empty request");
    }

    switch (rf) {
    case RetFormat::HEX: {
        // convert hex to bin, continue then with bin part
        std::vector<unsigned char> strRequestV = ParseHex(strRequestMutable);
        strRequestMutable.assign(strRequestV.begin(), strRequestV.end());
    }

    case RetFormat::BINARY: {
        try {
            //deserialize only if user sent a request
            if (strRequestMutable.size() > 0)
            {
                if (fInputParsed) //don't allow sending input over URI and HTTP RAW DATA
                    return RESTERR(req, HTTP_BAD_REQUEST, "Combination of URI scheme inputs and raw post data is not allowed");

                CDataStream oss(SER_NETWORK, PROTOCOL_VERSION);
                oss << strRequestMutable;
                oss >> fCheckMemPool;
                oss >> vOutPoints;
            }
        } catch (const std::ios_base::failure& e) {
            // abort in case of unreadable binary data
            return RESTERR(req, HTTP_BAD_REQUEST, "Parse error");
        }
        break;
    }

    case RetFormat::JSON: {
        if (!fInputParsed)
            return RESTERR(req, HTTP_BAD_REQUEST, "Error: empty request");
        break;
    }
    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: " + AvailableDataFormatsString() + ")");
    }
    }

    // limit max outpoints
    if (vOutPoints.size() > MAX_GETUTXOS_OUTPOINTS)
        return RESTERR(req, HTTP_BAD_REQUEST, strprintf("Error: max outpoints exceeded (max: %d, tried: %d)", MAX_GETUTXOS_OUTPOINTS, vOutPoints.size()));

    // check spentness and form a bitmap (as well as a JSON capable human-readable string representation)
    std::vector<unsigned char> bitmap;
    std::vector<CCoin> outs;
    std::string bitmapStringRepresentation;
    std::vector<bool> hits;
    bitmap.resize((vOutPoints.size() + 7) / 8);
    {
        auto process_utxos = [&vOutPoints, &outs, &hits](const CCoinsView& view, const CTxMemPool& mempool) {
            for (const COutPoint& vOutPoint : vOutPoints) {
                Coin coin;
                bool hit = !mempool.isSpent(vOutPoint) && view.GetCoin(vOutPoint, coin);
                hits.push_back(hit);
                if (hit) outs.emplace_back(std::move(coin));
            }
        };

        if (fCheckMemPool) {
            // use db+mempool as cache backend in case user likes to query mempool
            LOCK2(cs_main, mempool.cs);
            CCoinsViewCache& viewChain = *pcoinsTip;
            CCoinsViewMemPool viewMempool(&viewChain, mempool);
            process_utxos(viewMempool, mempool);
        } else {
            LOCK(cs_main);  // no need to lock mempool!
            process_utxos(*pcoinsTip, CTxMemPool());
        }

        for (size_t i = 0; i < hits.size(); ++i) {
            const bool hit = hits[i];
            bitmapStringRepresentation.append(hit ? "1" : "0"); // form a binary string representation (human-readable for json output)
            bitmap[i / 8] |= ((uint8_t)hit) << (i % 8);
        }
    }

    switch (rf) {
    case RetFormat::BINARY: {
        // serialize data
        // use exact same output as mentioned in Bip64
        CDataStream ssGetUTXOResponse(SER_NETWORK, PROTOCOL_VERSION);
        ssGetUTXOResponse << chainActive.Height() << chainActive.Tip()->GetBlockHash() << bitmap << outs;
        std::string ssGetUTXOResponseString = ssGetUTXOResponse.str();

        req->WriteHeader("Content-Type", "application/octet-stream");
        req->WriteReply(HTTP_OK, ssGetUTXOResponseString);
        return true;
    }

    case RetFormat::HEX: {
        CDataStream ssGetUTXOResponse(SER_NETWORK, PROTOCOL_VERSION);
        ssGetUTXOResponse << chainActive.Height() << chainActive.Tip()->GetBlockHash() << bitmap << outs;
        std::string strHex = HexStr(ssGetUTXOResponse.begin(), ssGetUTXOResponse.end()) + "\n";

        req->WriteHeader("Content-Type", "text/plain");
        req->WriteReply(HTTP_OK, strHex);
        return true;
    }

    case RetFormat::JSON: {
        UniValue objGetUTXOResponse(UniValue::VOBJ);

        // pack in some essentials
        // use more or less the same output as mentioned in Bip64
        objGetUTXOResponse.pushKV("chainHeight", chainActive.Height());
        objGetUTXOResponse.pushKV("chaintipHash", chainActive.Tip()->GetBlockHash().GetHex());
        objGetUTXOResponse.pushKV("bitmap", bitmapStringRepresentation);

        UniValue utxos(UniValue::VARR);
        for (const CCoin& coin : outs) {
            UniValue utxo(UniValue::VOBJ);
            utxo.pushKV("height", (int32_t)coin.nHeight);
            utxo.pushKV("value", ValueFromAmount(coin.out.nValue));

            // include the script in a json output
            UniValue o(UniValue::VOBJ);
            ScriptPubKeyToUniv(coin.out.scriptPubKey, o, true);
            utxo.pushKV("scriptPubKey", o);
            utxos.push_back(utxo);
        }
        objGetUTXOResponse.pushKV("utxos", utxos);

        // return json string
        std::string strJSON = objGetUTXOResponse.write() + "\n";
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strJSON);
        return true;
    }
    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: " + AvailableDataFormatsString() + ")");
    }
    }
}

static const struct {
    const char* prefix;
    bool (*handler)(HTTPRequest* req, const std::string& strReq);
} uri_prefixes[] = {
      {"/rest/tx/", rest_tx},
      {"/rest/block/notxdetails/", rest_block_notxdetails},
      {"/rest/block/", rest_block_extended},
      {"/rest/chaininfo", rest_chaininfo},
      {"/rest/mempool/info", rest_mempool_info},
      {"/rest/mempool/contents", rest_mempool_contents},
      {"/rest/headers/", rest_headers},
      {"/rest/getutxos", rest_getutxos},
};

// restapi

static bool API_ERROR (HTTPRequest* req, std::string message) {
    UniValue root (UniValue::VOBJ);
    root.pushKV("status", "error");
    root.pushKV("errmsg", message);
    std::string strJSON = root.write() + "\n";
    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(HTTP_OK, strJSON);
    return true;
}

static bool API_OK (HTTPRequest* req, UniValue& json) {
    json.pushKV("status", "ok");
    std::string strJSON = json.write() + "\n";
    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(HTTP_OK, strJSON);
    return true;
}

UniValue GetNetworkHash () {
    CBlockIndex *pb = chainActive.Tip();
    int lookup = 24;
    if (pb == nullptr || !pb->nHeight) return 0;
    if (lookup > pb->nHeight) lookup = pb->nHeight;
    CBlockIndex *pb0 = pb;
//    while(pb0->IsProofOfStake()) pb0 = pb0->pprev;
    int64_t minTime = pb0->GetBlockTime();
    int64_t maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
//        while (pb0->IsProofOfStake()) pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }
    if (minTime == maxTime) return 0;
    arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork;
    int64_t timeDiff = maxTime - minTime;
    return workDiff.getdouble() / timeDiff;
}

bool api_chain (HTTPRequest* req, const std::string& strURIPart) {
    if (!CheckWarmup(req)) return false;

    UniValue root (UniValue::VOBJ);
    root.pushKV("bestblockhash",        chainActive.Tip()->GetBlockHash().GetHex()); 
    root.pushKV("blocks",               (int)chainActive.Height());
    root.pushKV("headers",              pindexBestHeader ? pindexBestHeader->nHeight : -1);
    root.pushKV("difficulty_pow",       GetDifficulty(false));
    root.pushKV("difficulty_pos",       GetDifficulty(true));
    root.pushKV("initialblockdownload", IsInitialBlockDownload());
    root.pushKV("progress",             GuessVerificationProgress(Params().TxData(), chainActive.Tip()));
    root.pushKV("chainwork",            chainActive.Tip()->nChainWork.GetHex()); 
    root.pushKV("size_on_disk",         CalculateCurrentUsage()); 
    root.pushKV("networkhash",          GetNetworkHash());
    root.pushKV("mempool_size",         (uint64_t)mempool.size());
    return API_OK (req, root);
}

bool api_net (HTTPRequest* req, const std::string& strURIPart) {
    if (!CheckWarmup(req)) return false;

    UniValue root (UniValue::VOBJ);
    root.pushKV("connection",   (int)g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL));
    UniValue nodes (UniValue::VARR);
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("id", "self");
        obj.pushKV("version", PROTOCOL_VERSION);
        obj.pushKV("subversion", strSubVersion);
        obj.pushKV("synced_headers", pindexBestHeader ? pindexBestHeader->nHeight : -1);
        obj.pushKV("synced_blocks", (int)chainActive.Height()); 
        nodes.push_back(obj);
    }
    std::vector<CNodeStats> vstats;
    g_connman->GetNodeStats(vstats);
    for (const CNodeStats& stats : vstats) {
        CNodeStateStats statestats;
        bool fStateStats = GetNodeStateStats(stats.nodeid, statestats);
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("id", stats.nodeid);
        obj.pushKV("addr", stats.addrName);
        obj.pushKV("version", stats.nVersion);
        obj.pushKV("subversion", stats.cleanSubVer);
        obj.pushKV("bytessent", stats.nSendBytes);
        obj.pushKV("bytesrecv", stats.nRecvBytes);         
        obj.pushKV("lastsend", stats.nLastSend);
        obj.pushKV("lastrecv", stats.nLastRecv);
        obj.pushKV("inbound", stats.fInbound); 
        obj.pushKV("synced_headers", statestats.nSyncHeight);
        obj.pushKV("synced_blocks", statestats.nCommonHeight); 
        obj.pushKV("banscore", statestats.nMisbehavior);
        nodes.push_back(obj);
    }
    root.pushKV("nodes", nodes);

    UniValue ipport (UniValue::VARR);
    std::vector<CAddress> vAddr = g_connman->GetAddresses();
    for (const CAddress &addr : vAddr) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("addr", addr.ToStringIPPort());
        obj.pushKV("time", (int)addr.nTime);
        ipport.push_back(obj);
    }
    root.pushKV("addresses", ipport);
    return API_OK (req, root);
}

void getTxData (UniValue& obj, const CTransactionRef tx, uint256 hashBlock) {
    obj.pushKV("hash", tx->GetHash().GetHex());
    obj.pushKV("size", (int)::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION));
    obj.pushKV("version", tx->nVersion);
    obj.pushKV("locktime", (int64_t)tx->nLockTime);
    if (!hashBlock.IsNull()) obj.pushKV("blockhash", hashBlock.GetHex());
    UniValue vin(UniValue::VARR);
    for (unsigned int i = 0; i < tx->vin.size(); i++) {
        const CTxIn& txin = tx->vin[i];
        UniValue in(UniValue::VOBJ);
        if (tx->IsCoinBase())
            in.pushKV("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
        else {
            in.pushKV("tx_id", txin.prevout.hash.GetHex());
            in.pushKV("tx_out", (int64_t)txin.prevout.n);
            CTransactionRef intx;
            uint256 inhashBlock = uint256();
            if (GetTransaction(txin.prevout.hash, intx, Params().GetConsensus(), inhashBlock, true)) {
                if (intx->vout.size() >= txin.prevout.n + 1) {
                    CTxDestination addr;
                    if (ExtractDestination(intx->vout[txin.prevout.n].scriptPubKey, addr))
                        in.pushKV("address", EncodeDestination(addr));
                    in.pushKV("value", ValueFromAmount(intx->vout[txin.prevout.n].nValue));
                }  
            }
        }
        vin.push_back(in);
    }
    obj.pushKV("input", vin);
    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx->vout.size(); i++) {
        const CTxOut& txout = tx->vout[i];
        UniValue out(UniValue::VOBJ);
        CTxDestination addr;
        if (ExtractDestination(txout.scriptPubKey, addr))
            out.pushKV("address", EncodeDestination(addr));
        out.pushKV("value", ValueFromAmount(txout.nValue));
        vout.push_back(out);
    }
    obj.pushKV("output", vout);
}

bool api_mempool (HTTPRequest* req, const std::string& strURIPart) {
    if (!CheckWarmup(req)) return false;

    UniValue root (UniValue::VOBJ);
    root.pushKV("size",             (int64_t) mempool.size()); 
    root.pushKV("bytes",            (int64_t) mempool.GetTotalTxSize());
    root.pushKV("usage",            (int64_t) mempool.DynamicMemoryUsage());
    size_t maxmempool = gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    root.pushKV("mempoolminfee",    ValueFromAmount(std::max(mempool.GetMinFee(maxmempool), ::minRelayTxFee).GetFeePerK()));
    root.pushKV("minrelaytxfee",    ValueFromAmount(::minRelayTxFee.GetFeePerK())); 
    {
        LOCK(mempool.cs);
        UniValue sub (UniValue::VOBJ);
        for (const CTxMemPoolEntry& e : mempool.mapTx) {
            UniValue obj(UniValue::VOBJ);
            getTxData (obj, e.GetSharedTx(), uint256());
            sub.push_back(obj);
        }
        root.pushKV("tx", sub);
    }
    return API_OK (req, root);
}

bool api_masternode (HTTPRequest* req, const std::string& strURIPart) {
    if (!CheckWarmup(req)) return false;

    UniValue obj(UniValue::VOBJ);
    std::map<COutPoint, CMasternode> mapMasternodes = mnodeman.GetFullMasternodeMap();
    for (const auto& mnpair : mapMasternodes) {
        const CMasternode& mn = mnpair.second;
        UniValue objMN(UniValue::VOBJ);
        objMN.pushKV("address", mn.addr.ToString());
        objMN.pushKV("payee", EncodeDestination(mn.pubKeyCollateralAddress.GetID()));
        objMN.pushKV("status", mn.GetStatus());
        objMN.pushKV("protocol", mn.nProtocolVersion);
        objMN.pushKV("lastseen", (int64_t)mn.lastPing.sigTime);
        objMN.pushKV("activeseconds", (int64_t)(mn.lastPing.sigTime - mn.sigTime));
        objMN.pushKV("lastpaidtime", mn.GetLastPaidTime());
        objMN.pushKV("lastpaidblock", mn.GetLastPaidBlock());
        obj.pushKV(mnpair.first.ToString(), objMN);
    }
    UniValue root (UniValue::VOBJ);
    root.pushKV("count", mnodeman.size()); 
    root.pushKV("mn", obj);
    return API_OK (req, root);
}

std::string getHeaderData (UniValue& obj, const CBlockIndex* pi, bool full_tx) {
    CBlock block;
    if (!pi) return " not found";
    if (IsBlockPruned(pi)) return " not available (pruned data)";
    if (!ReadBlockFromDisk(block, pi, Params().GetConsensus())) return " not found";
    obj.pushKV("hash", pi->GetBlockHash().GetHex());
    int confirmations = -1;
    if (chainActive.Contains(pi)) confirmations = chainActive.Height() - pi->nHeight + 1;
    obj.pushKV("confirmations", confirmations);
    obj.pushKV("height", pi->nHeight);
    obj.pushKV("versionHex", strprintf("0x%08x", block.nVersion));
    obj.pushKV("merkleroot", block.hashMerkleRoot.GetHex());
    obj.pushKV("time", block.GetBlockTime());
    obj.pushKV("nonce", (uint64_t)block.nNonce);
    obj.pushKV("bits", strprintf("%08x", block.nBits));
    obj.push_back(Pair("difficulty", GetDifficulty(false, pi)));
    if (pi->pprev) obj.pushKV("prevblockhash", pi->pprev->GetBlockHash().GetHex());
    CBlockIndex *pnext = chainActive.Next(pi);
    if (pnext) obj.pushKV("nextblockhash", pnext->GetBlockHash().GetHex());
    obj.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    obj.pushKV("chainwork", pi->nChainWork.GetHex());
    obj.pushKV("nTx", (uint64_t)pi->nTx);
    obj.pushKV("type", pi->IsProofOfStake() ? "proof-of-stake" : "proof-of-work");
    UniValue utx (UniValue::VARR);
    for(const auto& tx : block.vtx) {
        if (full_tx) {
            UniValue obj(UniValue::VOBJ);
            getTxData (obj, tx, uint256());
            utx.push_back(obj);
        } else {
            utx.push_back(tx->GetHash().GetHex());
        }
    }
    obj.pushKV("tx", utx);
    return "";
}

bool api_header (HTTPRequest* req, const std::string& strURIPart) {
    if (!CheckWarmup(req)) return false;
    const CBlockIndex* pi = NULL;
    int count = 20;
    const std::string::size_type pos = strURIPart.rfind('_');
    std::string s1;
    uint32_t nn;
    if (pos == std::string::npos) { s1 = strURIPart; } else {
        s1 = strURIPart.substr(0, pos);
        if (s1 == "") return API_ERROR (req, "header hash is null");
        std::string s2 = strURIPart.substr(pos + 1);
        if (ParseUInt32(s2, &nn) && (nn < 599)) { count = nn; } else
            return API_ERROR (req, "header count is invalid (" + strURIPart + ")");        
    }
    if (ParseUInt32(s1, &nn)) {
        pi = chainActive[nn];
        if (!pi) return API_ERROR (req, "header index " + strURIPart + " not found");
    } else if (IsHex(s1)) {
        uint256 hash;
        hash.SetHex(s1);
        pi = LookupBlockIndex(hash);
        if (!pi) return API_ERROR (req, "header hash " + strURIPart + " not found");
    } else if (s1 == "") {
        pi = chainActive[chainActive.Height() <= count ? 0 : chainActive.Height() - count];
        if (!pi) return API_ERROR (req, "header hash " + strURIPart + " not found");
    } else return API_ERROR (req, "params " + strURIPart + " is invalid");
    UniValue root (UniValue::VOBJ);
    while (pi != nullptr && chainActive.Contains(pi)) {
        UniValue obj (UniValue::VOBJ);
        std::string ret = getHeaderData (obj, pi, false);
        if (ret != "") return API_ERROR (req, strprintf("[%d]: %s", pi->nHeight, ret));
        root.pushKV(strprintf("%d", pi->nHeight), obj);
        if (count-- <= 0) break;
        pi = chainActive.Next(pi);
    }
    return API_OK (req, root);
}

bool api_block (HTTPRequest* req, const std::string& strURIPart) {
    if (!CheckWarmup(req)) return false;
    const CBlockIndex* pi = NULL;
    uint32_t nn;
    if (ParseUInt32(strURIPart, &nn)) {
        pi = chainActive[nn];
        if (!pi) return API_ERROR (req, "block index " + strURIPart + " not found");
    } else if (IsHex(strURIPart)) {
        uint256 hash;
        hash.SetHex(strURIPart);
        pi = LookupBlockIndex(hash);
        if (!pi) return API_ERROR (req, "block hash " + strURIPart + " not found");
    } else if (strURIPart == "") {
        pi = chainActive.Tip();
        if (!pi) return API_ERROR (req, "block index " + strURIPart + " not found");
    } else return API_ERROR (req, "params " + strURIPart + " is invalid");
    UniValue root (UniValue::VOBJ);
    UniValue obj (UniValue::VOBJ);
    std::string ret = getHeaderData (obj, pi, true);
    if (ret != "") return API_ERROR (req, strprintf("[%d]: %s", pi->nHeight, ret));
    root.pushKV(strprintf("%d", pi->nHeight), obj);
    return API_OK (req, root);
}

bool api_tx (HTTPRequest* req, const std::string& strURIPart) {
    if (!CheckWarmup(req)) return false;
    uint256 hash;
    if (!ParseHashStr(strURIPart, hash))
        return API_ERROR (req, "tx hash " + strURIPart + " is invalid");
    CTransactionRef tx;
    uint256 hashBlock = uint256();
    if (!GetTransaction(hash, tx, Params().GetConsensus(), hashBlock, true))
        return API_ERROR (req, "tx hash " + strURIPart + " not found");
    UniValue root (UniValue::VOBJ);
    getTxData (root, tx, hashBlock);
    CBlockIndex* pi = LookupBlockIndex(hashBlock);
    if (pi) {
        root.pushKV("blockhash", pi->GetBlockHash().GetHex());
        int confirmations = -1;
        if (chainActive.Contains(pi)) confirmations = chainActive.Height() - pi->nHeight + 1;
        root.pushKV("blockconfirmations", confirmations);
        root.pushKV("blockheight", pi->nHeight);
        root.pushKV("blocktime", pi->GetBlockTime());
    } else {
        root.pushKV("blockhash", hashBlock.GetHex());
        root.pushKV("blockconfirmations", (int)-1);
        root.pushKV("blockheight", (int)-1);
        root.pushKV("blocktime", (int)0);
    }
    return API_OK (req, root);
}

bool heightSort(std::pair<CAddressKey, CAddressValue> a, std::pair<CAddressKey, CAddressValue> b) {
    return a.second.height > b.second.height;
}

bool api_address (HTTPRequest* req, const std::string& strURIPart) {
    if (!CheckWarmup(req)) return false;
    int index = 0;
    const std::string::size_type pos = strURIPart.rfind('_');
    std::string sss;
    if (pos == std::string::npos) { sss = strURIPart; } else {
        sss = strURIPart.substr(0, pos);
        if (sss == "") return API_ERROR (req, "address is null");
        uint32_t nn = 0;
        std::string s2 = strURIPart.substr(pos + 1);
        if (ParseUInt32(s2, &nn) && (nn < 9999)) { index = nn; } else
            return API_ERROR (req, "address count " + strURIPart + " is invalid");
    }
    if (!IsValidDestination(DecodeDestination(sss))) 
        return API_ERROR (req, "address " + strURIPart + " is invalid");
    std::vector<std::pair<CAddressKey, CAddressValue>> info;
    if (!pblocktree->ReadAddress(GetScriptForDestination(DecodeDestination(sss)), info))
        return API_ERROR (req, "address " + strURIPart + " not found");
    UniValue coins(UniValue::VARR);
    CAmount receive_amount = 0, send_amount = 0;
    int total_in = 0, total_out = 0, total_pos = 0; index *= 200;
    std::sort(info.begin(), info.end(), heightSort);
    bool only_unspent = req->GetURI().find("/api/unspent/") != std::string::npos;
    for (auto it : info) {
        bool isspent = it.second.spend_height != 0;
        if (only_unspent && isspent) continue;
        if (only_unspent && it.second.iscoinbase && (chainActive.Height() - it.second.height < COINBASE_MATURITY)) continue;
        UniValue output(UniValue::VOBJ);
        total_in++;
        receive_amount += it.second.value;
        output.pushKV("value", ValueFromAmount(it.second.value));
        output.pushKV("tx_hash", it.first.out.hash.GetHex());
        output.pushKV("tx_out", (int64_t)it.first.out.n);
        output.pushKV("height", (int64_t)it.second.height);
        const CBlockIndex* pi = chainActive[it.second.height];
        if (pi) output.pushKV("time", pi->GetBlockTime());
        if (it.first.stype == 0) output.pushKV("script", HexStr(it.first.script.begin(), it.first.script.end()));
        if (isspent) {
            total_out++;
            send_amount += it.second.value;
            output.pushKV("spent_tx_hash", it.second.spend_hash.GetHex());
            output.pushKV("spent_tx_out", (int64_t)it.second.spend_n);
            output.pushKV("spent_height", (int64_t)it.second.spend_height);
            const CBlockIndex* pi = chainActive[it.second.spend_height];
            if (pi) output.pushKV("spent_time", pi->GetBlockTime());
        }
        total_pos++;
        if ((index <= total_pos) && (total_pos < index + 200)) coins.push_back(output);
    }
    UniValue objTx(UniValue::VOBJ);
    objTx.pushKV("address", sss);
    objTx.pushKV("value", ValueFromAmount(receive_amount - send_amount));
    if (!only_unspent) {
        objTx.pushKV("receive_count", total_in);
        objTx.pushKV("send_count", total_out);
        objTx.pushKV("receive_amount", ValueFromAmount(receive_amount));
        objTx.pushKV("send_amount", ValueFromAmount(send_amount));
    }
    objTx.pushKV("offset", index);
    objTx.pushKV("count", total_pos);
    objTx.pushKV("height", (int64_t)chainActive.Height());
    objTx.pushKV("coins", coins);
    return API_OK (req, objTx);
}

bool api_send (HTTPRequest* req, const std::string& strURIPart) {
    if (!CheckWarmup(req)) return false;
    if (req->GetRequestMethod() != HTTPRequest::POST)
        return API_ERROR (req, "only POST requests");
    UniValue uniRequest;
    if (!uniRequest.read(req->ReadBody()))
        return API_ERROR (req, "POST json incorrect");
    UniValue txdata = find_value(uniRequest, "txdata");
    if (txdata.isNull())
        return API_ERROR (req, "json txdata not found");

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, txdata.get_str()))
        return API_ERROR (req, "json txdata incorrect");
    CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
    UniValue root (UniValue::VOBJ);
    const uint256& hashTx = tx->GetHash();
    bool fHaveChain = false;
    {
        LOCK(cs_main);
        CCoinsViewCache &view = *pcoinsTip;
        for (size_t o = 0; !fHaveChain && o < tx->vout.size(); o++) {
            const Coin& existingCoin = view.AccessCoin(COutPoint(hashTx, o));
            fHaveChain = !existingCoin.IsSpent();
            if (fHaveChain) break;
        }
    }
    if (fHaveChain) {
        root.pushKV("status", "transaction already in blockchain");
    } else if (mempool.exists(hashTx)) {
        root.pushKV("status", "transaction already in mempool");
    } else {
        CValidationState state;
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, std::move(tx), &fMissingInputs,
                    nullptr /* plTxnReplaced */, false /* bypass_limits */, maxTxFee)) {
            if (state.IsInvalid()) {
                return API_ERROR (req, FormatStateMessage(state));
            } else {
                if (fMissingInputs)
                    return API_ERROR (req, "tx " + hashTx.ToString() + " missing inputs");
                return API_ERROR (req, FormatStateMessage(state));
            }
        } else {
            if (g_connman) {
                CInv inv(MSG_TX, hashTx);
                g_connman->ForEachNode([&inv](CNode* pnode) { pnode->PushInventory(inv); });
            }
            root.pushKV("status", "transaction added to mempool");
        }
    }
    return API_OK (req, root);
}

static const struct {
    const char* prefix;
    bool (*handler)(HTTPRequest* req, const std::string& strReq);
} api_uri_prefixes[] = {
      {"/api/chain", api_chain}, 
      {"/api/net", api_net},
      {"/api/mempool", api_mempool},
      {"/api/masternode", api_masternode},
      {"/api/header/", api_header},     // start_hash, start_hash/num_header, start_index, start_index/num_header
      {"/api/block/", api_block},       // hash, index
      {"/api/tx/", api_tx},             // hash
      {"/api/address/", api_address},   // address
      {"/api/unspent/", api_address},   // unspent
      {"/api/send/", api_send},         // TX HEX
};

bool StartREST()
{
    if (gArgs.GetBoolArg("-server", false)) {
        for (unsigned int i = 0; i < ARRAYLEN(uri_prefixes); i++)
            RegisterHTTPHandler(uri_prefixes[i].prefix, false, uri_prefixes[i].handler);
    }
    if (gArgs.GetBoolArg("-restapi", false)) {
        for (unsigned int i = 0; i < ARRAYLEN(api_uri_prefixes); i++)
            RegisterHTTPHandler(api_uri_prefixes[i].prefix, false, api_uri_prefixes[i].handler);
    }
    return true;
}

void InterruptREST()
{
}

void StopREST()
{
    if (gArgs.GetBoolArg("-server", false)) {
        for (unsigned int i = 0; i < ARRAYLEN(uri_prefixes); i++)
            UnregisterHTTPHandler(uri_prefixes[i].prefix, false);
    }
    if (gArgs.GetBoolArg("-restapi", false)) {
        for (unsigned int i = 0; i < ARRAYLEN(api_uri_prefixes); i++)
            UnregisterHTTPHandler(api_uri_prefixes[i].prefix, false);
    }
}
