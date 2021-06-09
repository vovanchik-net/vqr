// Copyright (c) 2014-2019 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <activemasternode.h>
#include <base58.h>
#include <clientversion.h>
#include <init.h>
#include <netbase.h>
#include <validation.h>
#include <util.h>
#include <utilmoneystr.h>
#include <txmempool.h>
#include <key_io.h>

#include <governance.h>
#include <masternode.h>

#include <rpc/server.h>

#include <wallet/coincontrol.h>
#include <wallet/rpcwallet.h>
#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#endif // ENABLE_WALLET

#include <fstream>
#include <iomanip>
#include <univalue.h>

std::string FormatVersion (uint32_t ver) {
    return strprintf("%d.%d.%d.%d", ver / 1000000, (ver / 10000) % 100, (ver / 100) % 100, ver % 100);
}

void masternode_help() {
    throw std::runtime_error(
        "masternode \"command\" ...\n"
        "Set of commands to execute masternode related actions\n"
        "\nArguments:\n"
        "1. \"command\"        (string or set of strings, required) The command to execute\n"
        "\nAvailable commands:\n"
        "  count        - Get information about number of masternodes\n"
        "  current      - DEPRECATED Print info on current masternode winner to be paid the next block (calculated locally)\n"
#ifdef ENABLE_WALLET
        "  outputs      - Print masternode compatible outputs\n"
#endif // ENABLE_WALLET
        "  status       - Print masternode status information\n"
        "  list         - Print list of all known masternodes (see masternodelist for more info)\n"
        "  genkey       - Generate private key\n"
        "  winners      - Print list of masternode winners\n"
        "  create       - Create masternode\n"
        );
}

UniValue masternode(const JSONRPCRequest& request) {
    std::string strCommand;
    if (!request.params[0].isNull()) {
        strCommand = request.params[0].get_str();
    }

    if (request.fHelp && strCommand.empty()) {
        masternode_help();
    }

    if (strCommand == "list") {
        JSONRPCRequest newRequest;
        newRequest.params.setArray();
        // forward params but skip "list"
        for (unsigned int i = 1; i < request.params.size(); i++) {
            newRequest.params.push_back(request.params[i]);
        }
//        return masternodelist(newRequest);
    } else if (strCommand == "connect") {
        if (request.params.size() < 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Masternode address required");

        std::string strAddress = request.params[1].get_str();

        CService addr;
        if (!Lookup(strAddress.c_str(), addr, 0, false))
            throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Incorrect masternode address %s", strAddress));

        // TODO: Pass CConnman instance somehow and don't use global variable.
        g_connman->OpenMasternodeConnection(CAddress(addr, NODE_NETWORK));
        bool ret = false;
        g_connman->ForEachNode([&ret, &addr](CNode* pnode) {
            if ((CService)pnode->addr == addr) {
                if (pnode->fMasternode) ret = true;
            }
        });
        if (!ret)
            throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Couldn't connect to masternode %s", strAddress));

        return "successfully connected"; 
    } else if (strCommand == "count") {
        int total = mnodeman.size();
        int enabled = mnodeman.CountEnabled();

        UniValue obj(UniValue::VOBJ);
        obj.pushKV("total", total);
        obj.pushKV("enabled", enabled);
        return obj;
    } else if (strCommand == "current") {
        if (!fMasternodeMode)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "This is not a masternode");
        int nCount;
        int nHeight;
        CMasternodeBase mnInfo;
        CBlockIndex* pindex = nullptr;
        {
            LOCK(cs_main);
            pindex = chainActive.Tip();
        }
        nHeight = pindex->nHeight + 1;
        mnodeman.UpdateLastPaid(pindex);

        if(!mnodeman.GetNextMasternodeInQueueForPayment(nHeight, true, nCount, mnInfo))
            return "unknown";

        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("height",        nHeight));
        obj.push_back(Pair("IP:port",       mnInfo.addr.ToString()));
        obj.push_back(Pair("protocol",      mnInfo.nProtocolVersion));
        obj.push_back(Pair("outpoint",      mnInfo.outpoint.ToString()));
        obj.push_back(Pair("payee",         EncodeDestination(mnInfo.pubKeyCollateralAddress.GetID())));
        obj.push_back(Pair("lastseen",      mnInfo.nTimeLastPing));
        obj.push_back(Pair("activeseconds", mnInfo.nTimeLastPing - mnInfo.sigTime));
        return obj; 
#ifdef ENABLE_WALLET
    } else if (strCommand == "outputs") {
        // Find possible candidates
        if (GetWallets().size() == 0)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallets not found");
        
        std::shared_ptr<CWallet> pwallet = GetWallets()[0];
        if (!pwallet)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallets not found");
            
        std::vector<COutput> vPossibleCoins;
        pwallet->AvailableCoins(vPossibleCoins, true, nullptr, 0, MAX_MONEY, MAX_MONEY, 0, 1, 9999999);
        UniValue obj(UniValue::VOBJ);
        for (const auto& out : vPossibleCoins) {
            if (out.tx->tx->vout[out.i].nValue != Params().GetConsensus().nMasternodeAmountLock * COIN) continue;
            obj.push_back(Pair(out.tx->GetHash().ToString(), strprintf("%d", out.i)));
        }

        return obj; 
#endif // ENABLE_WALLET
    } else if (strCommand == "status") {
        if (!fMasternodeMode)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "This is not a masternode");

        UniValue mnObj(UniValue::VOBJ);

        mnObj.push_back(Pair("outpoint", activeMasternode.outpoint.ToString()));
        mnObj.push_back(Pair("service", activeMasternode.service.ToString()));

        CMasternode mn;
        if(mnodeman.Get(activeMasternode.outpoint, mn)) {
            mnObj.push_back(Pair("payee", EncodeDestination(mn.pubKeyCollateralAddress.GetID())));
        }

        mnObj.push_back(Pair("status", activeMasternode.GetStatus()));
        return mnObj;
    } else if (strCommand == "winners") {
        int nHeight;
        {
            LOCK(cs_main);
            CBlockIndex* pindex = chainActive.Tip();
            if(!pindex) return NullUniValue;

            nHeight = pindex->nHeight;
        }

        int nLast = 10;
        std::string strFilter = "";

        if (request.params.size() >= 2) {
            nLast = atoi(request.params[1].get_str());
        }

        if (request.params.size() == 3) {
            strFilter = request.params[2].get_str();
        }

        if (request.params.size() > 3)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'masternode winners ( \"count\" \"filter\" )'");

        UniValue obj(UniValue::VOBJ);

        for(int i = nHeight - nLast; i < nHeight + 20; i++) {
            std::string strPayment = mnpayments.GetRequiredPaymentsString(i);
            if (strFilter !="" && strPayment.find(strFilter) == std::string::npos) continue;
            obj.push_back(Pair(strprintf("%d", i), strPayment));
        }

        return obj;
    } else if (strCommand == "genkey") {
        CKey secret;
        secret.MakeNewKey(false);
        return EncodeSecret(secret);
    } else if (strCommand == "create") {
        if (GetWallets().size() == 0)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallets not found");
        
        std::shared_ptr<CWallet> pwallet = GetWallets()[0];
        if (!pwallet)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallets not found");

        int nn = 0;
        std::vector<COutput> vPossibleCoins;
        pwallet->AvailableCoins(vPossibleCoins, true, nullptr, 0, MAX_MONEY, MAX_MONEY, 0, 1, 9999999);
        UniValue obj(UniValue::VOBJ);
        for (const auto& out : vPossibleCoins) {
            if (out.tx->tx->vout[out.i].nValue != Params().GetConsensus().nMasternodeAmountLock * COIN) continue;
            bool found = false;
            for (const auto& mne : masternodeConfig.getEntries()) {
                if ((out.tx->GetHash().ToString() == mne.getTxHash()) && 
                    (mne.getOutputIndex() == itostr(out.i))) { found = true; break; }
            }
            if (!found) {
                CKey secret;
                secret.MakeNewKey(false);
                CService serv;
                bool fFoundLocal = GetLocal(serv) && CMasternode::IsValidNetAddr(serv);
                if (!fFoundLocal) {
                    bool empty = true;
                    g_connman->ForEachNode([&](CNode* pnode) {
                        empty = false;
                        if (pnode->addr.IsIPv4())
                            fFoundLocal = GetLocal(serv, &pnode->addr) && CMasternode::IsValidNetAddr(serv);
                        return !fFoundLocal;
                    });
                }
                if (!serv.IsIPv4()) Lookup("127.0.0.1", serv, 9987, false);
                
                masternodeConfig.add ("mn"+itostr(masternodeConfig.getCount()+1), serv.ToString(), EncodeSecret(secret), 
                            out.tx->GetHash().ToString(), itostr(out.i));
                obj.push_back(Pair("Added", strprintf("%s:%d", out.tx->GetHash().ToString() , out.i)));
                nn++;
            } else {
                obj.push_back(Pair("Existed", strprintf("%s:%d", out.tx->GetHash().ToString() , out.i)));
            }
        }
        if (nn > 0) {
            std::string strErrRet;
            masternodeConfig.write(strErrRet);
        }
        return obj; 
    } else if (strCommand == "ihack") {
        masternodeSync.SwitchToNextAsset(*g_connman);
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("status", masternodeSync.GetSyncStatus());
        return obj;
    } else if (strCommand == "iconf") {
        UniValue resultObj(UniValue::VOBJ);
        for (const auto& mne : masternodeConfig.getEntries()) {
            COutPoint outpoint = COutPoint(uint256S(mne.getTxHash()), (uint32_t)atoi(mne.getOutputIndex()));
            CMasternode mn;
            bool fFound = mnodeman.Get(outpoint, mn);

            std::string strStatus = fFound ? mn.GetStatus() : "MISSING";

            UniValue mnObj(UniValue::VOBJ);
            mnObj.push_back(Pair("alias", mne.getAlias()));
            mnObj.push_back(Pair("address", mne.getIp()));
            mnObj.push_back(Pair("privateKey", mne.getPrivKey()));
            mnObj.push_back(Pair("txHash", mne.getTxHash()));
            mnObj.push_back(Pair("outputIndex", mne.getOutputIndex()));
            mnObj.push_back(Pair("status", strStatus));
            resultObj.push_back(Pair("masternode", mnObj));
        }

        return resultObj;
    } else {
        masternode_help();
    }
}

void log (const std::string str) {
    static FILE *cfile_ptr = NULL;
    static int cfile_numinfile = 0;
    static int cfile_count = 0;
    static std::string eol = "\n";
	if (str == "*") { if (cfile_ptr != NULL) fclose(cfile_ptr); cfile_ptr = NULL; return; }
	if ((cfile_ptr != NULL) && (cfile_numinfile > 99999)) { fclose(cfile_ptr); cfile_ptr = NULL; }
	if (cfile_ptr == NULL) { 
		cfile_ptr = fsbridge::fopen(strprintf("debug%06i", ++cfile_count) + ".log", "a");
		cfile_numinfile = 0;
	}
    fwrite(str.data(), 1, str.size(), cfile_ptr);
    fwrite(eol.data(), 1, eol.size(), cfile_ptr);
	cfile_numinfile++;
}

UniValue masternode_list (const JSONRPCRequest& request) {
    if (request.fHelp)
        throw std::runtime_error(
            "masternode_list\n"
            "\nDump info about masternodes\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode_list", "")
        );

//    CBlockIndex* pindex = nullptr;
//    {
//        LOCK(cs_main);
//        pindex = chainActive.Tip();
//    }
//    mnodeman.UpdateLastPaid(pindex);
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
    return obj;
}

UniValue masternode_dump (const JSONRPCRequest& request) {
    if (request.fHelp)
        throw std::runtime_error(
            "masternode_dump\n"
            "\nDump info about masternodes\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode_dump", "")
        );

    mnodeman.Dump("", [](std::string ss) { log (ss); });
    log ("");
    log ("");
    log ("");
    mnpayments.Dump("", [](std::string ss) { log (ss); });
    log ("");
    log ("");
    log ("");
//    governance.Dump("", [](std::string ss) { log (ss); });
    log ("*");

    return {};
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "dash",               "masternode",             &masternode,             {} },
    { "mn",                 "masternode_list",        &masternode_list,        {} },
    { "mn",                 "masternode_dump",        &masternode_dump,        {} },
};

void RegisterMasternodeRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
