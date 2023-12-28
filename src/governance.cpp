// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2023 Uladzimir (t.me/cryptadev)
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <governance.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <masternode.h>
#include <util.h>
#include <instantx.h>
#include <core_io.h>
#include <key_io.h>
#include <tinyformat.h>
#include <utilstrencodings.h>

#include <boost/lexical_cast.hpp>

// governance-vote

std::string CGovernanceVoting::ConvertOutcomeToString(vote_outcome_enum_t nOutcome)
{
    switch(nOutcome)
    {
        case VOTE_OUTCOME_NONE:
            return "NONE"; break;
        case VOTE_OUTCOME_YES:
            return "YES"; break;
        case VOTE_OUTCOME_NO:
            return "NO"; break;
        case VOTE_OUTCOME_ABSTAIN:
            return "ABSTAIN"; break;
    }
    return "error";
}

std::string CGovernanceVoting::ConvertSignalToString(vote_signal_enum_t nSignal)
{
    std::string strReturn = "NONE";
    switch(nSignal)
    {
        case VOTE_SIGNAL_NONE:
            strReturn = "NONE";
            break;
        case VOTE_SIGNAL_FUNDING:
            strReturn = "FUNDING";
            break;
        case VOTE_SIGNAL_VALID:
            strReturn = "VALID";
            break;
        case VOTE_SIGNAL_DELETE:
            strReturn = "DELETE";
            break;
        case VOTE_SIGNAL_ENDORSED:
            strReturn = "ENDORSED";
            break;
    }

    return strReturn;
}


vote_outcome_enum_t CGovernanceVoting::ConvertVoteOutcome(const std::string& strVoteOutcome)
{
    vote_outcome_enum_t eVote = VOTE_OUTCOME_NONE;
    if(strVoteOutcome == "yes") {
        eVote = VOTE_OUTCOME_YES;
    }
    else if(strVoteOutcome == "no") {
        eVote = VOTE_OUTCOME_NO;
    }
    else if(strVoteOutcome == "abstain") {
        eVote = VOTE_OUTCOME_ABSTAIN;
    }
    return eVote;
}

vote_signal_enum_t CGovernanceVoting::ConvertVoteSignal(const std::string& strVoteSignal)
{
    static const std::map <std::string, vote_signal_enum_t> mapStrVoteSignals = {
        {"funding",  VOTE_SIGNAL_FUNDING},
        {"valid",    VOTE_SIGNAL_VALID},
        {"delete",   VOTE_SIGNAL_DELETE},
        {"endorsed", VOTE_SIGNAL_ENDORSED}
    };

    const auto& it = mapStrVoteSignals.find(strVoteSignal);
    if (it == mapStrVoteSignals.end()) {
        LogPrintf("CGovernanceVoting::%s -- ERROR: Unknown signal %s\n", __func__, strVoteSignal);
        return VOTE_SIGNAL_NONE;
    }
    return it->second;
}

CGovernanceVote::CGovernanceVote()
    : fValid(true),
      fSynced(false),
      nVoteSignal(int(VOTE_SIGNAL_NONE)),
      masternodeOutpoint(),
      nParentHash(),
      nVoteOutcome(int(VOTE_OUTCOME_NONE)),
      nTime(0),
      vchSig()
{}

CGovernanceVote::CGovernanceVote(const COutPoint& outpointMasternodeIn, const uint256& nParentHashIn, vote_signal_enum_t eVoteSignalIn, vote_outcome_enum_t eVoteOutcomeIn)
    : fValid(true),
      fSynced(false),
      nVoteSignal(eVoteSignalIn),
      masternodeOutpoint(outpointMasternodeIn),
      nParentHash(nParentHashIn),
      nVoteOutcome(eVoteOutcomeIn),
      nTime(GetAdjustedTime()),
      vchSig()
{
    UpdateHash();
}

std::string CGovernanceVote::ToString() const
{
    std::ostringstream ostr;
    ostr << masternodeOutpoint.ToString() << ":"
         << nTime << ":"
         << CGovernanceVoting::ConvertOutcomeToString(GetOutcome()) << ":"
         << CGovernanceVoting::ConvertSignalToString(GetSignal());
    return ostr.str();
}

void CGovernanceVote::Relay(CConnman& connman) const
{
    // Do not relay until fully synced
    if(!masternodeSync.IsSynced()) {
        LogPrint(BCLog::MN, "CGovernanceVote::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_GOVERNANCE_OBJECT_VOTE, GetHash());
    connman.ForEachNode([&inv](CNode* pnode) {
        pnode->PushInventory(inv);
    });    
}

void CGovernanceVote::UpdateHash() const
{
    // Note: doesn't match serialization

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << masternodeOutpoint << uint8_t{} << 0xffffffff; // adding dummy values here to match old hashing format
    ss << nParentHash;
    ss << nVoteSignal;
    ss << nVoteOutcome;
    ss << nTime;
    *const_cast<uint256*>(&hash) = ss.GetHash();
}

uint256 CGovernanceVote::GetHash() const
{
    return hash;
}

uint256 CGovernanceVote::GetSignatureHash() const
{
    return SerializeHash(*this);
}

bool CGovernanceVote::Sign(const CKey& keyMasternode, const CPubKey& pubKeyMasternode)
{
    std::string strError;

    {
        std::string strMessage = masternodeOutpoint.ToString() + "|" + nParentHash.ToString() + "|" +
            boost::lexical_cast<std::string>(nVoteSignal) + "|" + boost::lexical_cast<std::string>(nVoteOutcome) + "|" + boost::lexical_cast<std::string>(nTime);

        if(!CMessageSigner::SignMessage(strMessage, vchSig, keyMasternode)) {
            LogPrintf("CGovernanceVote::Sign -- SignMessage() failed\n");
            return false;
        }

        if(!CMessageSigner::VerifyMessage(pubKeyMasternode, vchSig, strMessage, strError)) {
            LogPrintf("CGovernanceVote::Sign -- VerifyMessage() failed, error: %s\n", strError);
            return false;
        }
    }

    return true;
}

bool CGovernanceVote::CheckSignature(const CPubKey& pubKeyMasternode) const
{
    std::string strError;
    {
        std::string strMessage = masternodeOutpoint.ToString() + "|" + nParentHash.ToString() + "|" +
            boost::lexical_cast<std::string>(nVoteSignal) + "|" +
            boost::lexical_cast<std::string>(nVoteOutcome) + "|" +
            boost::lexical_cast<std::string>(nTime);

        if(!CMessageSigner::VerifyMessage(pubKeyMasternode, vchSig, strMessage, strError)) {
            LogPrint(BCLog::MN, "CGovernanceVote::IsValid -- VerifyMessage() failed, error: %s\n", strError);
            return false;
        }
    }

    return true;
}

bool CGovernanceVote::IsValid(bool fSignatureCheck) const
{
    if(nTime > GetAdjustedTime() + (60*60)) {
        LogPrint(BCLog::MN, "CGovernanceVote::IsValid -- vote is too far ahead of current time - %s - nTime %lli - Max Time %lli\n", GetHash().ToString(), nTime, GetAdjustedTime() + (60*60));
        return false;
    }

    // support up to MAX_SUPPORTED_VOTE_SIGNAL, can be extended
    if(nVoteSignal > MAX_SUPPORTED_VOTE_SIGNAL)
    {
        LogPrint(BCLog::MN, "CGovernanceVote::IsValid -- Client attempted to vote on invalid signal(%d) - %s\n", nVoteSignal, GetHash().ToString());
        return false;
    }

    // 0=none, 1=yes, 2=no, 3=abstain. Beyond that reject votes
    if(nVoteOutcome > 3)
    {
        LogPrint(BCLog::MN, "CGovernanceVote::IsValid -- Client attempted to vote on invalid outcome(%d) - %s\n", nVoteSignal, GetHash().ToString());
        return false;
    }

    CMasternodeBase infoMn;
    if(!mnodeman.GetMasternodeInfo(masternodeOutpoint, infoMn)) {
        LogPrint(BCLog::MN, "CGovernanceVote::IsValid -- Unknown Masternode - %s\n", masternodeOutpoint.ToString());
        return false;
    }

    if(!fSignatureCheck) return true;

    return CheckSignature(infoMn.pubKeyMasternode);
}

bool operator==(const CGovernanceVote& vote1, const CGovernanceVote& vote2)
{
    bool fResult = ((vote1.masternodeOutpoint == vote2.masternodeOutpoint) &&
                    (vote1.nParentHash == vote2.nParentHash) &&
                    (vote1.nVoteOutcome == vote2.nVoteOutcome) &&
                    (vote1.nVoteSignal == vote2.nVoteSignal) &&
                    (vote1.nTime == vote2.nTime));
    return fResult;
}

bool operator<(const CGovernanceVote& vote1, const CGovernanceVote& vote2)
{
    bool fResult = (vote1.masternodeOutpoint < vote2.masternodeOutpoint);
    if(!fResult) {
        return false;
    }
    fResult = (vote1.masternodeOutpoint == vote2.masternodeOutpoint);

    fResult = fResult && (vote1.nParentHash < vote2.nParentHash);
    if(!fResult) {
        return false;
    }
    fResult = fResult && (vote1.nParentHash == vote2.nParentHash);

    fResult = fResult && (vote1.nVoteOutcome < vote2.nVoteOutcome);
    if(!fResult) {
        return false;
    }
    fResult = fResult && (vote1.nVoteOutcome == vote2.nVoteOutcome);

    fResult = fResult && (vote1.nVoteSignal == vote2.nVoteSignal);
    if(!fResult) {
        return false;
    }
    fResult = fResult && (vote1.nVoteSignal == vote2.nVoteSignal);

    fResult = fResult && (vote1.nTime < vote2.nTime);

    return fResult;
}

// governance-votedb

CGovernanceObjectVoteFile::CGovernanceObjectVoteFile()
    : nMemoryVotes(0),
      listVotes(),
      mapVoteIndex()
{}

CGovernanceObjectVoteFile::CGovernanceObjectVoteFile(const CGovernanceObjectVoteFile& other)
    : nMemoryVotes(other.nMemoryVotes),
      listVotes(other.listVotes),
      mapVoteIndex()
{
    RebuildIndex();
}

void CGovernanceObjectVoteFile::AddVote(const CGovernanceVote& vote)
{
    uint256 nHash = vote.GetHash();
    // make sure to never add/update already known votes
    if (HasVote(nHash))
        return;
    listVotes.push_front(vote);
    mapVoteIndex.emplace(nHash, listVotes.begin());
    ++nMemoryVotes;
}

bool CGovernanceObjectVoteFile::HasVote(const uint256& nHash) const
{
    return mapVoteIndex.find(nHash) != mapVoteIndex.end();
}

bool CGovernanceObjectVoteFile::SerializeVoteToStream(const uint256& nHash, CDataStream& ss) const
{
    vote_m_cit it = mapVoteIndex.find(nHash);
    if(it == mapVoteIndex.end()) {
        return false;
    }
    ss << *(it->second);
    return true;
}

std::vector<CGovernanceVote> CGovernanceObjectVoteFile::GetVotes() const
{
    std::vector<CGovernanceVote> vecResult;
    for(vote_l_cit it = listVotes.begin(); it != listVotes.end(); ++it) {
        vecResult.push_back(*it);
    }
    return vecResult;
}

void CGovernanceObjectVoteFile::RemoveVotesFromMasternode(const COutPoint& outpointMasternode)
{
    vote_l_it it = listVotes.begin();
    while(it != listVotes.end()) {
        if(it->GetMasternodeOutpoint() == outpointMasternode) {
            --nMemoryVotes;
            mapVoteIndex.erase(it->GetHash());
            listVotes.erase(it++);
        }
        else {
            ++it;
        }
    }
}

void CGovernanceObjectVoteFile::RebuildIndex()
{
    mapVoteIndex.clear();
    nMemoryVotes = 0;
    vote_l_it it = listVotes.begin();
    while(it != listVotes.end()) {
        CGovernanceVote& vote = *it;
        uint256 nHash = vote.GetHash();
        if(mapVoteIndex.find(nHash) == mapVoteIndex.end()) {
            mapVoteIndex[nHash] = it;
            ++nMemoryVotes;
            ++it;
        }
        else {
            listVotes.erase(it++);
        }
    }
} 

// governance-object

CGovernanceObject::CGovernanceObject():
    cs(),
    nObjectType(GOVERNANCE_OBJECT_UNKNOWN),
    nHashParent(),
    nRevision(0),
    nTime(0),
    nDeletionTime(0),
    nCollateralHash(),
    vchData(),
    masternodeOutpoint(),
    vchSig(),
    fCachedLocalValidity(false),
    strLocalValidityError(),
    fCachedFunding(false),
    fCachedValid(true),
    fCachedDelete(false),
    fCachedEndorsed(false),
    fDirtyCache(true),
    fExpired(false),
    fUnparsable(false),
    mapCurrentMNVotes(),
    cmmapOrphanVotes(),
    fileVotes()
{
    // PARSE JSON DATA STORAGE (VCHDATA)
    LoadData();
}

CGovernanceObject::CGovernanceObject(const uint256& nHashParentIn, int nRevisionIn, int64_t nTimeIn, const uint256& nCollateralHashIn, const std::string& strDataHexIn):
    cs(),
    nObjectType(GOVERNANCE_OBJECT_UNKNOWN),
    nHashParent(nHashParentIn),
    nRevision(nRevisionIn),
    nTime(nTimeIn),
    nDeletionTime(0),
    nCollateralHash(nCollateralHashIn),
    vchData(ParseHex(strDataHexIn)),
    masternodeOutpoint(),
    vchSig(),
    fCachedLocalValidity(false),
    strLocalValidityError(),
    fCachedFunding(false),
    fCachedValid(true),
    fCachedDelete(false),
    fCachedEndorsed(false),
    fDirtyCache(true),
    fExpired(false),
    fUnparsable(false),
    mapCurrentMNVotes(),
    cmmapOrphanVotes(),
    fileVotes()
{
    // PARSE JSON DATA STORAGE (VCHDATA)
    LoadData();
}

CGovernanceObject::CGovernanceObject(const CGovernanceObject& other):
    cs(),
    nObjectType(other.nObjectType),
    nHashParent(other.nHashParent),
    nRevision(other.nRevision),
    nTime(other.nTime),
    nDeletionTime(other.nDeletionTime),
    nCollateralHash(other.nCollateralHash),
    vchData(other.vchData),
    masternodeOutpoint(other.masternodeOutpoint),
    vchSig(other.vchSig),
    fCachedLocalValidity(other.fCachedLocalValidity),
    strLocalValidityError(other.strLocalValidityError),
    fCachedFunding(other.fCachedFunding),
    fCachedValid(other.fCachedValid),
    fCachedDelete(other.fCachedDelete),
    fCachedEndorsed(other.fCachedEndorsed),
    fDirtyCache(other.fDirtyCache),
    fExpired(other.fExpired),
    fUnparsable(other.fUnparsable),
    mapCurrentMNVotes(other.mapCurrentMNVotes),
    cmmapOrphanVotes(other.cmmapOrphanVotes),
    fileVotes(other.fileVotes)
{}

bool CGovernanceObject::ProcessVote(CNode* pfrom,
                                    const CGovernanceVote& vote,
                                    CGovernanceException& exception,
                                    CConnman& connman)
{
    LOCK(cs);

    // do not process already known valid votes twice
    if (fileVotes.HasVote(vote.GetHash())) {
        // nothing to do here, not an error
        std::ostringstream ostr;
        ostr << "CGovernanceObject::ProcessVote -- Already known valid vote";
        LogPrint(BCLog::MN, "%s\n", ostr.str());
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_NONE);
        return false;
    }

    if(!mnodeman.Has(vote.GetMasternodeOutpoint())) {
        std::ostringstream ostr;
        ostr << "CGovernanceObject::ProcessVote -- Masternode " << vote.GetMasternodeOutpoint().ToString() << " not found";
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_WARNING);
        if(cmmapOrphanVotes.Insert(vote.GetMasternodeOutpoint(), vote_time_pair_t(vote, GetAdjustedTime() + GOVERNANCE_ORPHAN_EXPIRATION_TIME))) {
            if(pfrom) {
                mnodeman.AskForMN(pfrom, vote.GetMasternodeOutpoint(), connman);
            }
            LogPrintf("%s\n", ostr.str());
        }
        else {
            LogPrint(BCLog::MN, "%s\n", ostr.str());
        }
        return false;
    }

    vote_m_it it = mapCurrentMNVotes.emplace(vote_m_t::value_type(vote.GetMasternodeOutpoint(), vote_rec_t())).first;
    vote_rec_t& voteRecordRef = it->second;
    vote_signal_enum_t eSignal = vote.GetSignal();
    if(eSignal == VOTE_SIGNAL_NONE) {
        std::ostringstream ostr;
        ostr << "CGovernanceObject::ProcessVote -- Vote signal: none";
        LogPrint(BCLog::MN, "%s\n", ostr.str());
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_WARNING);
        return false;
    }
    if(eSignal > MAX_SUPPORTED_VOTE_SIGNAL) {
        std::ostringstream ostr;
        ostr << "CGovernanceObject::ProcessVote -- Unsupported vote signal: " << CGovernanceVoting::ConvertSignalToString(vote.GetSignal());
        LogPrintf("%s\n", ostr.str());
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_PERMANENT_ERROR, 20);
        return false;
    }
    vote_instance_m_it it2 = voteRecordRef.mapInstances.emplace(vote_instance_m_t::value_type(int(eSignal), vote_instance_t())).first;
    vote_instance_t& voteInstanceRef = it2->second;

    // Reject obsolete votes
    if(vote.GetTimestamp() < voteInstanceRef.nCreationTime) {
        std::ostringstream ostr;
        ostr << "CGovernanceObject::ProcessVote -- Obsolete vote";
        LogPrint(BCLog::MN, "%s\n", ostr.str());
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_NONE);
        return false;
    }

    int64_t nNow = GetAdjustedTime();
    int64_t nVoteTimeUpdate = voteInstanceRef.nTime;
    if(governance.AreRateChecksEnabled()) {
        int64_t nTimeDelta = nNow - voteInstanceRef.nTime;
        if(nTimeDelta < GOVERNANCE_UPDATE_MIN) {
            std::ostringstream ostr;
            ostr << "CGovernanceObject::ProcessVote -- Masternode voting too often"
                 << ", MN outpoint = " << vote.GetMasternodeOutpoint().ToString()
                 << ", governance object hash = " << GetHash().ToString()
                 << ", time delta = " << nTimeDelta;
            LogPrint(BCLog::MN, "%s\n", ostr.str());
            exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_TEMPORARY_ERROR);
            nVoteTimeUpdate = nNow;
            return false;
        }
    }

    // Finally check that the vote is actually valid (done last because of cost of signature verification)
    if(!vote.IsValid(true)) {
        std::ostringstream ostr;
        ostr << "CGovernanceObject::ProcessVote -- Invalid vote"
                << ", MN outpoint = " << vote.GetMasternodeOutpoint().ToString()
                << ", governance object hash = " << GetHash().ToString()
                << ", vote hash = " << vote.GetHash().ToString();
        LogPrintf("%s\n", ostr.str());
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_PERMANENT_ERROR, 20);
        governance.AddInvalidVote(vote);
        return false;
    }

    if(!mnodeman.AddGovernanceVote(vote.GetMasternodeOutpoint(), vote.GetParentHash())) {
        std::ostringstream ostr;
        ostr << "CGovernanceObject::ProcessVote -- Unable to add governance vote"
             << ", MN outpoint = " << vote.GetMasternodeOutpoint().ToString()
             << ", governance object hash = " << GetHash().ToString();
        LogPrint(BCLog::MN, "%s\n", ostr.str());
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_PERMANENT_ERROR);
        return false;
    }

    voteInstanceRef = vote_instance_t(vote.GetOutcome(), nVoteTimeUpdate, vote.GetTimestamp());
    fileVotes.AddVote(vote);
    fDirtyCache = true;
    return true;
}

void CGovernanceObject::ClearMasternodeVotes()
{
    LOCK(cs);

    vote_m_it it = mapCurrentMNVotes.begin();
    while(it != mapCurrentMNVotes.end()) {
        if(!mnodeman.Has(it->first)) {
            fileVotes.RemoveVotesFromMasternode(it->first);
            mapCurrentMNVotes.erase(it++);
        }
        else {
            ++it;
        }
    }
}

std::string CGovernanceObject::GetSignatureMessage() const
{
    LOCK(cs);
    std::string strMessage = nHashParent.ToString() + "|" +
        boost::lexical_cast<std::string>(nRevision) + "|" +
        boost::lexical_cast<std::string>(nTime) + "|" +
        GetDataAsHexString() + "|" +
        masternodeOutpoint.ToString() + "|" +
        nCollateralHash.ToString();

    return strMessage;
}

uint256 CGovernanceObject::GetHash() const
{
    // Note: doesn't match serialization

    // CREATE HASH OF ALL IMPORTANT PIECES OF DATA

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << nHashParent;
    ss << nRevision;
    ss << nTime;
    ss << GetDataAsHexString();
    ss << masternodeOutpoint << uint8_t{} << 0xffffffff; // adding dummy values here to match old hashing
    ss << vchSig;
    // fee_tx is left out on purpose

    return ss.GetHash();
}

uint256 CGovernanceObject::GetSignatureHash() const
{
    return SerializeHash(*this);
}

void CGovernanceObject::SetMasternodeOutpoint(const COutPoint& outpoint)
{
    masternodeOutpoint = outpoint;
}

bool CGovernanceObject::Sign(const CKey& keyMasternode, const CPubKey& pubKeyMasternode)
{
    std::string strError;

    {
        std::string strMessage = GetSignatureMessage();
        if (!CMessageSigner::SignMessage(strMessage, vchSig, keyMasternode)) {
            LogPrintf("CGovernanceObject::Sign -- SignMessage() failed\n");
            return false;
        }

        if (!CMessageSigner::VerifyMessage(pubKeyMasternode, vchSig, strMessage, strError)) {
            LogPrintf("CGovernanceObject::Sign -- VerifyMessage() failed, error: %s\n", strError);
            return false;
        }
    }

    LogPrint(BCLog::MN, "CGovernanceObject::Sign -- pubkey id = %s, masternode = %s\n",
             pubKeyMasternode.GetID().ToString(), masternodeOutpoint.ToString());

    return true;
}

bool CGovernanceObject::CheckSignature(const CPubKey& pubKeyMasternode) const
{
    std::string strError;

    {
        std::string strMessage = GetSignatureMessage();

        if (!CMessageSigner::VerifyMessage(pubKeyMasternode, vchSig, strMessage, strError)) {
            LogPrintf("CGovernance::CheckSignature -- VerifyMessage() failed, error: %s\n", strError);
            return false;
        }
    }

    return true;
}

/**
   Return the actual object from the vchData JSON structure.

   Returns an empty object on error.
 */
UniValue CGovernanceObject::GetJSONObject()
{
    UniValue obj(UniValue::VOBJ);
    if(vchData.empty()) {
        return obj;
    }

    UniValue objResult(UniValue::VOBJ);
    GetData(objResult);

    if (objResult.isObject()) {
        obj = objResult;
    } else {
        std::vector<UniValue> arr1 = objResult.getValues();
        std::vector<UniValue> arr2 = arr1.at( 0 ).getValues();
        obj = arr2.at( 1 );
    }

    return obj;
}

/**
*   LoadData
*   --------------------------------------------------------
*
*   Attempt to load data from vchData
*
*/

void CGovernanceObject::LoadData()
{
    // todo : 12.1 - resolved
    //return;

    if(vchData.empty()) {
        return;
    }

    try  {
        // ATTEMPT TO LOAD JSON STRING FROM VCHDATA
        UniValue objResult(UniValue::VOBJ);
        GetData(objResult);

        UniValue obj = GetJSONObject();
        nObjectType = obj["type"].get_int();
    }
    catch(std::exception& e) {
        fUnparsable = true;
        std::ostringstream ostr;
        ostr << "CGovernanceObject::LoadData Error parsing JSON"
             << ", e.what() = " << e.what();
        LogPrintf("%s\n", ostr.str());
        return;
    }
    catch(...) {
        fUnparsable = true;
        std::ostringstream ostr;
        ostr << "CGovernanceObject::LoadData Unknown Error parsing JSON";
        LogPrintf("%s\n", ostr.str());
        return;
    }
}

/**
*   GetData - Example usage:
*   --------------------------------------------------------
*
*   Decode governance object data into UniValue(VOBJ)
*
*/

void CGovernanceObject::GetData(UniValue& objResult)
{
    UniValue o(UniValue::VOBJ);
    std::string s = GetDataAsPlainString();
    o.read(s);
    objResult = o;
}

/**
*   GetData - As
*   --------------------------------------------------------
*
*/

std::string CGovernanceObject::GetDataAsHexString() const
{
    return HexStr(vchData);
}

std::string CGovernanceObject::GetDataAsPlainString() const
{
    return std::string(vchData.begin(), vchData.end());
}

void CGovernanceObject::UpdateLocalValidity()
{
    LOCK(cs_main);
    // THIS DOES NOT CHECK COLLATERAL, THIS IS CHECKED UPON ORIGINAL ARRIVAL
    fCachedLocalValidity = IsValidLocally(strLocalValidityError, false);
};


bool CGovernanceObject::IsValidLocally(std::string& strError, bool fCheckCollateral) const
{
    bool fMissingMasternode = false;
    bool fMissingConfirmations = false;

    return IsValidLocally(strError, fMissingMasternode, fMissingConfirmations, fCheckCollateral);
}

bool CGovernanceObject::IsValidLocally(std::string& strError, bool& fMissingMasternode, bool& fMissingConfirmations, bool fCheckCollateral) const
{
    fMissingMasternode = false;
    fMissingConfirmations = false;

    if (fUnparsable) {
        strError = "Object data unparseable";
        return false;
    }

    switch(nObjectType) {
        case GOVERNANCE_OBJECT_WATCHDOG: {
            // watchdogs are deprecated
            return false;
        }
        case GOVERNANCE_OBJECT_PROPOSAL: {
            CProposalValidator validator(GetDataAsHexString());
            // Note: It's ok to have expired proposals
            // they are going to be cleared by CGovernanceManager::UpdateCachesAndClean()
            // TODO: should they be tagged as "expired" to skip vote downloading?
            if (!validator.Validate(false)) {
                strError = strprintf("Invalid proposal data, error messages: %s", validator.GetErrorMessages());
                return false;
            }
            if (fCheckCollateral && !IsCollateralValid(strError, fMissingConfirmations)) {
                strError = "Invalid proposal collateral";
                return false;
            }
            return true;
        }
        case GOVERNANCE_OBJECT_TRIGGER: {
            if (!fCheckCollateral)
                // nothing else we can check here (yet?)
                return true;

            std::string strOutpoint = masternodeOutpoint.ToString();
            CMasternodeBase infoMn;
            if (!mnodeman.GetMasternodeInfo(masternodeOutpoint, infoMn)) {

                CMasternode::CollateralStatus err = CMasternode::CheckCollateral(masternodeOutpoint, CPubKey());
                if (err == CMasternode::COLLATERAL_UTXO_NOT_FOUND) {
                    strError = "Failed to find Masternode UTXO, missing masternode=" + strOutpoint + "\n";
                } else if (err == CMasternode::COLLATERAL_INVALID_AMOUNT) {
                    strError = "Masternode UTXO should have 1000 DASH, missing masternode=" + strOutpoint + "\n";
                } else if (err == CMasternode::COLLATERAL_INVALID_PUBKEY) {
                    fMissingMasternode = true;
                    strError = "Masternode not found: " + strOutpoint;
                } else if (err == CMasternode::COLLATERAL_OK) {
                    // this should never happen with CPubKey() as a param
                    strError = "CheckCollateral critical failure! Masternode: " + strOutpoint;
                }

                return false;
            }

            // Check that we have a valid MN signature
            if (!CheckSignature(infoMn.pubKeyMasternode)) {
                strError = "Invalid masternode signature for: " + strOutpoint + ", pubkey id = " + infoMn.pubKeyMasternode.GetID().ToString();
                return false;
            }

            return true;
        }
        default: {
            strError = strprintf("Invalid object type %d", nObjectType);
            return false;
        }
    }

}

CAmount CGovernanceObject::GetMinCollateralFee() const
{
    // Only 1 type has a fee for the moment but switch statement allows for future object types
    switch(nObjectType) {
        case GOVERNANCE_OBJECT_PROPOSAL:    return GOVERNANCE_PROPOSAL_FEE_TX;
        case GOVERNANCE_OBJECT_TRIGGER:     return 0;
        case GOVERNANCE_OBJECT_WATCHDOG:    return 0;
        default:                            return MAX_MONEY;
    }
}

bool CGovernanceObject::IsCollateralValid(std::string& strError, bool& fMissingConfirmations) const
{
    strError = "";
    fMissingConfirmations = false;
    CAmount nMinFee = GetMinCollateralFee();
    uint256 nExpectedHash = GetHash();

    CTransactionRef txCollateral;
    uint256 nBlockHash;

    // RETRIEVE TRANSACTION IN QUESTION

    if(!GetTransaction(nCollateralHash, txCollateral, Params().GetConsensus(), nBlockHash, true)){
        strError = strprintf("Can't find collateral tx %s", nCollateralHash.ToString());
        LogPrintf("CGovernanceObject::IsCollateralValid -- %s\n", strError);
        return false;
    }

    if(nBlockHash == uint256()) {
        strError = strprintf("Collateral tx %s is not mined yet", txCollateral->ToString());
        LogPrintf("CGovernanceObject::IsCollateralValid -- %s\n", strError);
        return false;
    }

    if(txCollateral->vout.size() < 1) {
        strError = strprintf("tx vout size less than 1 | %d", txCollateral->vout.size());
        LogPrintf("CGovernanceObject::IsCollateralValid -- %s\n", strError);
        return false;
    }

    // LOOK FOR SPECIALIZED GOVERNANCE SCRIPT (PROOF OF BURN)

    CScript findScript;
    findScript << OP_RETURN << ToByteVector(nExpectedHash);

    bool foundOpReturn = false;
    for (const auto& output : txCollateral->vout) {
        auto& scr = output.scriptPubKey;
        if (!((scr.size() == 25) && (scr[0] == OP_DUP) && (scr[1] == OP_HASH160) && 
             (scr[2] == 0x14) && (scr[23] == OP_EQUALVERIFY) && (scr[24] == OP_CHECKSIG))) {
            strError = strprintf("Invalid Script %s", txCollateral->ToString());
            LogPrintf ("CGovernanceObject::IsCollateralValid -- %s\n", strError);
            return false;
        }
        if(output.scriptPubKey == findScript && output.nValue >= nMinFee) {
            foundOpReturn = true;
        }
    }

    if(!foundOpReturn){
        strError = strprintf("Couldn't find opReturn %s in %s", nExpectedHash.ToString(), txCollateral->ToString());
        LogPrintf ("CGovernanceObject::IsCollateralValid -- %s\n", strError);
        return false;
    }

    // GET CONFIRMATIONS FOR TRANSACTION

    AssertLockHeld(cs_main);
    int nConfirmationsIn = instantsend.GetConfirmations(nCollateralHash);
    if (nBlockHash != uint256()) {
        BlockMap::iterator mi = mapBlockIndex.find(nBlockHash);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex* pindex = (*mi).second;
            if (chainActive.Contains(pindex)) {
                nConfirmationsIn += chainActive.Height() - pindex->nHeight + 1;
            }
        }
    }

    if(nConfirmationsIn < GOVERNANCE_FEE_CONFIRMATIONS) {
        strError = strprintf("Collateral requires at least %d confirmations to be relayed throughout the network (it has only %d)", GOVERNANCE_FEE_CONFIRMATIONS, nConfirmationsIn);
        if (nConfirmationsIn >= GOVERNANCE_MIN_RELAY_FEE_CONFIRMATIONS) {
            fMissingConfirmations = true;
            strError += ", pre-accepted -- waiting for required confirmations";
        } else {
            strError += ", rejected -- try again later";
        }
        LogPrintf ("CGovernanceObject::IsCollateralValid -- %s\n", strError);

        return false;
    }

    strError = "valid";
    return true;
}

int CGovernanceObject::CountMatchingVotes(vote_signal_enum_t eVoteSignalIn, vote_outcome_enum_t eVoteOutcomeIn) const
{
    LOCK(cs);

    int nCount = 0;
    for (const auto& votepair : mapCurrentMNVotes) {
        const vote_rec_t& recVote = votepair.second;
        vote_instance_m_cit it2 = recVote.mapInstances.find(eVoteSignalIn);
        if(it2 != recVote.mapInstances.end() && it2->second.eOutcome == eVoteOutcomeIn) {
            ++nCount;
        }
    }
    return nCount;
}

/**
*   Get specific vote counts for each outcome (funding, validity, etc)
*/

int CGovernanceObject::GetAbsoluteYesCount(vote_signal_enum_t eVoteSignalIn) const
{
    return GetYesCount(eVoteSignalIn) - GetNoCount(eVoteSignalIn);
}

int CGovernanceObject::GetAbsoluteNoCount(vote_signal_enum_t eVoteSignalIn) const
{
    return GetNoCount(eVoteSignalIn) - GetYesCount(eVoteSignalIn);
}

int CGovernanceObject::GetYesCount(vote_signal_enum_t eVoteSignalIn) const
{
    return CountMatchingVotes(eVoteSignalIn, VOTE_OUTCOME_YES);
}

int CGovernanceObject::GetNoCount(vote_signal_enum_t eVoteSignalIn) const
{
    return CountMatchingVotes(eVoteSignalIn, VOTE_OUTCOME_NO);
}

int CGovernanceObject::GetAbstainCount(vote_signal_enum_t eVoteSignalIn) const
{
    return CountMatchingVotes(eVoteSignalIn, VOTE_OUTCOME_ABSTAIN);
}

bool CGovernanceObject::GetCurrentMNVotes(const COutPoint& mnCollateralOutpoint, vote_rec_t& voteRecord) const
{
    LOCK(cs);

    vote_m_cit it = mapCurrentMNVotes.find(mnCollateralOutpoint);
    if (it == mapCurrentMNVotes.end()) {
        return false;
    }
    voteRecord = it->second;
    return  true;
}

void CGovernanceObject::Relay(CConnman& connman)
{
    // Do not relay until fully synced
    if(!masternodeSync.IsSynced()) {
        LogPrint(BCLog::MN, "CGovernanceObject::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_GOVERNANCE_OBJECT, GetHash());
    connman.ForEachNode([&inv](CNode* pnode) {
        pnode->PushInventory(inv);
    });
}

void CGovernanceObject::UpdateSentinelVariables()
{
    // CALCULATE MINIMUM SUPPORT LEVELS REQUIRED

    int nMnCount = mnodeman.CountEnabled();
    if(nMnCount == 0) return;

    // CALCULATE THE MINUMUM VOTE COUNT REQUIRED FOR FULL SIGNAL

    int nAbsVoteReq = std::max(10/*Params().GetConsensus().nGovernanceMinQuorum*/, nMnCount / 10);
    int nAbsDeleteReq = std::max(10/*Params().GetConsensus().nGovernanceMinQuorum*/, (2 * nMnCount) / 3);

    // SET SENTINEL FLAGS TO FALSE

    fCachedFunding = false;
    fCachedValid = true; //default to valid
    fCachedEndorsed = false;
    fDirtyCache = false;

    // SET SENTINEL FLAGS TO TRUE IF MIMIMUM SUPPORT LEVELS ARE REACHED
    // ARE ANY OF THESE FLAGS CURRENTLY ACTIVATED?

    if(GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING) >= nAbsVoteReq) fCachedFunding = true;
    if((GetAbsoluteYesCount(VOTE_SIGNAL_DELETE) >= nAbsDeleteReq) && !fCachedDelete) {
        fCachedDelete = true;
        if(nDeletionTime == 0) {
            nDeletionTime = GetAdjustedTime();
        }
    }
    if(GetAbsoluteYesCount(VOTE_SIGNAL_ENDORSED) >= nAbsVoteReq) fCachedEndorsed = true;

    if(GetAbsoluteNoCount(VOTE_SIGNAL_VALID) >= nAbsVoteReq) fCachedValid = false;
}

void CGovernanceObject::swap(CGovernanceObject& first, CGovernanceObject& second) // nothrow
{
    // enable ADL (not necessary in our case, but good practice)
    using std::swap;

    // by swapping the members of two classes,
    // the two classes are effectively swapped
    swap(first.nHashParent, second.nHashParent);
    swap(first.nRevision, second.nRevision);
    swap(first.nTime, second.nTime);
    swap(first.nDeletionTime, second.nDeletionTime);
    swap(first.nCollateralHash, second.nCollateralHash);
    swap(first.vchData, second.vchData);
    swap(first.nObjectType, second.nObjectType);

    // swap all cached valid flags
    swap(first.fCachedFunding, second.fCachedFunding);
    swap(first.fCachedValid, second.fCachedValid);
    swap(first.fCachedDelete, second.fCachedDelete);
    swap(first.fCachedEndorsed, second.fCachedEndorsed);
    swap(first.fDirtyCache, second.fDirtyCache);
    swap(first.fExpired, second.fExpired);
}

void CGovernanceObject::CheckOrphanVotes(CConnman& connman)
{
    int64_t nNow = GetAdjustedTime();
    const vote_cmm_t::list_t& listVotes = cmmapOrphanVotes.GetItemList();
    vote_cmm_t::list_cit it = listVotes.begin();
    while(it != listVotes.end()) {
        bool fRemove = false;
        const COutPoint& key = it->key;
        const vote_time_pair_t& pairVote = it->value;
        const CGovernanceVote& vote = pairVote.first;
        if(pairVote.second < nNow) {
            fRemove = true;
        }
        else if(!mnodeman.Has(vote.GetMasternodeOutpoint())) {
            ++it;
            continue;
        }
        CGovernanceException exception;
        if(!ProcessVote(nullptr, vote, exception, connman)) {
            LogPrintf("CGovernanceObject::CheckOrphanVotes -- Failed to add orphan vote: %s\n", exception.what());
        }
        else {
            vote.Relay(connman);
            fRemove = true;
        }
        ++it;
        if(fRemove) {
            cmmapOrphanVotes.Erase(key, pairVote);
        }
    }
}

// governance

CGovernanceManager governance;

int nSubmittedFinalBudget;

const std::string CGovernanceManager::SERIALIZATION_VERSION_STRING = "CGovernanceManager-Version-13";
const int CGovernanceManager::MAX_TIME_FUTURE_DEVIATION = 60*60;
const int CGovernanceManager::RELIABLE_PROPAGATION_TIME = 60;

CGovernanceManager::CGovernanceManager()
    : nTimeLastDiff(0),
      nCachedBlockHeight(0),
      mapObjects(),
      mapErasedGovernanceObjects(),
      mapMasternodeOrphanObjects(),
      cmapVoteToObject(MAX_CACHE_SIZE),
      cmapInvalidVotes(MAX_CACHE_SIZE),
      cmmapOrphanVotes(MAX_CACHE_SIZE),
      mapLastMasternodeObject(),
      setRequestedObjects(),
      fRateChecksEnabled(true),
      cs()
{}

// Accessors for thread-safe access to maps
bool CGovernanceManager::HaveObjectForHash(const uint256& nHash) const {
    LOCK(cs);
    return (mapObjects.count(nHash) == 1 || mapPostponedObjects.count(nHash) == 1);
}

bool CGovernanceManager::SerializeObjectForHash(const uint256& nHash, CDataStream& ss) const {
    LOCK(cs);
    object_m_cit it = mapObjects.find(nHash);
    if (it == mapObjects.end()) {
        it = mapPostponedObjects.find(nHash);
        if (it == mapPostponedObjects.end())
            return false;
    }
    ss << it->second;
    return true;
}

bool CGovernanceManager::HaveVoteForHash(const uint256& nHash) const {
    LOCK(cs);
    CGovernanceObject* pGovobj = nullptr;
    return cmapVoteToObject.Get(nHash, pGovobj) && pGovobj->GetVoteFile().HasVote(nHash);
}

int CGovernanceManager::GetVoteCount() const {
    LOCK(cs);
    return (int)cmapVoteToObject.GetSize();
}

bool CGovernanceManager::SerializeVoteForHash(const uint256& nHash, CDataStream& ss) const {
    LOCK(cs);
    CGovernanceObject* pGovobj = nullptr;
    return cmapVoteToObject.Get(nHash,pGovobj) && pGovobj->GetVoteFile().SerializeVoteToStream(nHash, ss);
}

bool CGovernanceManager::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman) {
    // ANOTHER USER IS ASKING US TO HELP THEM SYNC GOVERNANCE OBJECT DATA
    if (strCommand == NetMsgType::MNGOVERNANCESYNC) {
        // Ignore such requests until we are fully synced.
        // We could start processing this after masternode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!masternodeSync.IsSynced()) return true;

        uint256 nProp;
        CBloomFilter filter;

        vRecv >> nProp;
        vRecv >> filter;
        filter.UpdateEmptyFull();

        if (nProp == uint256()) {
            SyncAll(pfrom, connman);
        } else {
            SyncSingleObjAndItsVotes(pfrom, nProp, filter, connman);
        }
        LogPrint(BCLog::MN, "MNGOVERNANCESYNC -- syncing governance objects to our peer at %s\n", pfrom->addr.ToString());
        return true;
    }
    // A NEW GOVERNANCE OBJECT HAS ARRIVED
    else if (strCommand == NetMsgType::MNGOVERNANCEOBJECT) {
        // MAKE SURE WE HAVE A VALID REFERENCE TO THE TIP BEFORE CONTINUING
        CGovernanceObject govobj;
        vRecv >> govobj;

        uint256 nHash = govobj.GetHash();

        pfrom->setAskFor.erase(nHash);

        if (!masternodeSync.IsMasternodeListSynced()) {
            LogPrint(BCLog::MN, "MNGOVERNANCEOBJECT -- masternode list not synced\n");
            return true;
        }

        std::string strHash = nHash.ToString();

        LogPrint(BCLog::MN, "MNGOVERNANCEOBJECT -- Received object: %s\n", strHash);

        if (!AcceptObjectMessage(nHash)) {
            LogPrintf("MNGOVERNANCEOBJECT -- Received unrequested object: %s\n", strHash);
            return true;
        }

        LOCK2(cs_main, cs);

        if (mapObjects.count(nHash) || mapPostponedObjects.count(nHash) ||
                    mapErasedGovernanceObjects.count(nHash) || mapMasternodeOrphanObjects.count(nHash)) {
            // TODO - print error code? what if it's GOVOBJ_ERROR_IMMATURE?
            LogPrint(BCLog::MN, "MNGOVERNANCEOBJECT -- Received already seen object: %s\n", strHash);
            return true;
        }

        bool fRateCheckBypassed = false;
        if(!MasternodeRateCheck(govobj, true, false, fRateCheckBypassed)) {
            LogPrintf("MNGOVERNANCEOBJECT -- masternode rate check failed - %s - (current block height %d) \n", strHash, nCachedBlockHeight);
            return true;
        }

        std::string strError = "";
        // CHECK OBJECT AGAINST LOCAL BLOCKCHAIN

        bool fMasternodeMissing = false;
        bool fMissingConfirmations = false;
        bool fIsValid = govobj.IsValidLocally(strError, fMasternodeMissing, fMissingConfirmations, true);

        if (fRateCheckBypassed && (fIsValid || fMasternodeMissing)) {
            if(!MasternodeRateCheck(govobj, true)) {
                LogPrintf("MNGOVERNANCEOBJECT -- masternode rate check failed (after signature verification) - %s - (current block height %d) \n", strHash, nCachedBlockHeight);
                return true;
            }
        }

        if (!fIsValid) {
            if (fMasternodeMissing) {
                int& count = mapMasternodeOrphanCounter[govobj.GetMasternodeOutpoint()];
                if (count >= 10) {
                    LogPrint(BCLog::MN, "MNGOVERNANCEOBJECT -- Too many orphan objects, missing masternode=%s\n", govobj.GetMasternodeOutpoint().ToString());
                    // ask for this object again in 2 minutes
                    CInv inv(MSG_GOVERNANCE_OBJECT, govobj.GetHash());
                    pfrom->AskFor(inv);
                    return true;
                }
                count++;
                ExpirationInfo info(pfrom->GetId(), GetAdjustedTime() + GOVERNANCE_ORPHAN_EXPIRATION_TIME);
                mapMasternodeOrphanObjects.insert(std::make_pair(nHash, object_info_pair_t(govobj, info)));
                LogPrintf("MNGOVERNANCEOBJECT -- Missing masternode for: %s, strError = %s\n", strHash, strError);
            } else if(fMissingConfirmations) {
                AddPostponedObject(govobj);
                LogPrintf("MNGOVERNANCEOBJECT -- Not enough fee confirmations for: %s, strError = %s\n", strHash, strError);
            } else {
                LogPrintf("MNGOVERNANCEOBJECT -- Governance object is invalid - %s\n", strError);
                // apply node's ban score
                Misbehaving(pfrom->GetId(), 20, "");
            }
            return true;
        }
        AddGovernanceObject(govobj, connman, pfrom);
        return true;
    }
    // A NEW GOVERNANCE OBJECT VOTE HAS ARRIVED
    else if (strCommand == NetMsgType::MNGOVERNANCEOBJECTVOTE) {
        CGovernanceVote vote;
        vRecv >> vote;

        uint256 nHash = vote.GetHash();

        pfrom->setAskFor.erase(nHash);

        // Ignore such messages until masternode list is synced
        if (!masternodeSync.IsMasternodeListSynced()) {
            LogPrint(BCLog::MN, "MNGOVERNANCEOBJECTVOTE -- masternode list not synced\n");
            return true;
        }

        LogPrint(BCLog::MN, "MNGOVERNANCEOBJECTVOTE -- Received vote: %s\n", vote.ToString());

        std::string strHash = nHash.ToString();

        if (!AcceptVoteMessage(nHash)) {
            LogPrint(BCLog::MN, "MNGOVERNANCEOBJECTVOTE -- Received unrequested vote object: %s, hash: %s, peer = %d\n",
                      vote.ToString(), strHash, pfrom->GetId());
            return true;
        }

        CGovernanceException exception;
        if (ProcessVote(pfrom, vote, exception, connman)) {
            LogPrint(BCLog::MN, "MNGOVERNANCEOBJECTVOTE -- %s new\n", strHash);
            masternodeSync.BumpAssetLastTime("MNGOVERNANCEOBJECTVOTE");
            vote.Relay(connman);
        } else {
            LogPrint(BCLog::MN, "MNGOVERNANCEOBJECTVOTE -- Rejected vote, error = %s\n", exception.what());
            if ((exception.GetNodePenalty() != 0) && masternodeSync.IsSynced()) {
                LOCK(cs_main);
                Misbehaving(pfrom->GetId(), exception.GetNodePenalty(), "");
            }
        }
        return true;
    }
    return false;
}

void CGovernanceManager::CheckOrphanVotes(CGovernanceObject& govobj, CGovernanceException& exception, CConnman& connman) {
    uint256 nHash = govobj.GetHash();
    std::vector<vote_time_pair_t> vecVotePairs;
    cmmapOrphanVotes.GetAll(nHash, vecVotePairs);

    ScopedLockBool guard(cs, fRateChecksEnabled, false);

    int64_t nNow = GetAdjustedTime();
    for(size_t i = 0; i < vecVotePairs.size(); ++i) {
        bool fRemove = false;
        vote_time_pair_t& pairVote = vecVotePairs[i];
        CGovernanceVote& vote = pairVote.first;
        CGovernanceException exception;
        if (pairVote.second < nNow) {
            fRemove = true;
        } else if(govobj.ProcessVote(nullptr, vote, exception, connman)) {
            vote.Relay(connman);
            fRemove = true;
        }
        if (fRemove) {
            cmmapOrphanVotes.Erase(nHash, pairVote);
        }
    }
}

void CGovernanceManager::AddGovernanceObject(CGovernanceObject& govobj, CConnman& connman, CNode* pfrom) {
    uint256 nHash = govobj.GetHash();
    std::string strHash = nHash.ToString();

    // UPDATE CACHED VARIABLES FOR THIS OBJECT AND ADD IT TO OUR MANANGED DATA

    govobj.UpdateSentinelVariables(); //this sets local vars in object

    LOCK2(cs_main, cs);
    std::string strError = "";

    // MAKE SURE THIS OBJECT IS OK

    if (!govobj.IsValidLocally(strError, true)) {
        LogPrintf("CGovernanceManager::AddGovernanceObject -- invalid governance object - %s - (nCachedBlockHeight %d) \n", strError, nCachedBlockHeight);
        return;
    }

    LogPrint(BCLog::MN, "CGovernanceManager::AddGovernanceObject -- Adding object: hash = %s, type = %d\n", nHash.ToString(), govobj.GetObjectType());

    // INSERT INTO OUR GOVERNANCE OBJECT MEMORY
    // IF WE HAVE THIS OBJECT ALREADY, WE DON'T WANT ANOTHER COPY
    auto objpair = mapObjects.emplace(nHash, govobj);

    if (!objpair.second) {
        LogPrintf("CGovernanceManager::AddGovernanceObject -- already have governance object %s\n", nHash.ToString());
        return;
    }

    // SHOULD WE ADD THIS OBJECT TO ANY OTHER MANANGERS?

    LogPrintf("CGovernanceManager::AddGovernanceObject -- %s new, received from %s\n", strHash, pfrom? pfrom->GetAddrName() : "NULL");
    govobj.Relay(connman);

    // Update the rate buffer
    MasternodeRateUpdate(govobj);

    masternodeSync.BumpAssetLastTime("CGovernanceManager::AddGovernanceObject");

    // WE MIGHT HAVE PENDING/ORPHAN VOTES FOR THIS OBJECT

    CGovernanceException exception;
    CheckOrphanVotes(govobj, exception, connman);
}

void CGovernanceManager::UpdateCachesAndClean() {
    LogPrint(BCLog::MN, "CGovernanceManager::UpdateCachesAndClean\n");

    std::vector<uint256> vecDirtyHashes = mnodeman.GetAndClearDirtyGovernanceObjectHashes();

    LOCK2(cs_main, cs);

    for(size_t i = 0; i < vecDirtyHashes.size(); ++i) {
        object_m_it it = mapObjects.find(vecDirtyHashes[i]);
        if (it == mapObjects.end()) {
            continue;
        }
        it->second.ClearMasternodeVotes();
        it->second.fDirtyCache = true;
    }

    ScopedLockBool guard(cs, fRateChecksEnabled, false);

    object_m_it it = mapObjects.begin();
    int64_t nNow = GetAdjustedTime();

    while(it != mapObjects.end()) {
        CGovernanceObject* pObj = &((*it).second);

        if (!pObj) {
            ++it;
            continue;
        }

        uint256 nHash = it->first;
        std::string strHash = nHash.ToString();

        // IF CACHE IS NOT DIRTY, WHY DO THIS?
        if (pObj->IsSetDirtyCache()) {
            // UPDATE LOCAL VALIDITY AGAINST CRYPTO DATA
            pObj->UpdateLocalValidity();

            // UPDATE SENTINEL SIGNALING VARIABLES
            pObj->UpdateSentinelVariables();
        }

        // IF DELETE=TRUE, THEN CLEAN THE MESS UP!

        int64_t nTimeSinceDeletion = nNow - pObj->GetDeletionTime();

        LogPrint(BCLog::MN, "CGovernanceManager::UpdateCachesAndClean -- Checking object for deletion: %s, deletion time = %d, time since deletion = %d, delete flag = %d, expired flag = %d\n",
                 strHash, pObj->GetDeletionTime(), nTimeSinceDeletion, pObj->IsSetCachedDelete(), pObj->IsSetExpired());

        if ((pObj->IsSetCachedDelete() || pObj->IsSetExpired()) && (nTimeSinceDeletion >= GOVERNANCE_DELETION_DELAY)) {
            LogPrint(BCLog::MN, "CGovernanceManager::UpdateCachesAndClean -- erase obj %s\n", (*it).first.ToString());
            mnodeman.RemoveGovernanceObject(pObj->GetHash());

            // Remove vote references
            const object_ref_cm_t::list_t& listItems = cmapVoteToObject.GetItemList();
            object_ref_cm_t::list_cit lit = listItems.begin();
            while (lit != listItems.end()) {
                if (lit->value == pObj) {
                    uint256 nKey = lit->key;
                    cmapVoteToObject.Erase(nKey);
                }
                ++lit;
            }

            int64_t nTimeExpired{0};

            if (pObj->GetObjectType() == GOVERNANCE_OBJECT_PROPOSAL) {
                // keep hashes of deleted proposals forever
                nTimeExpired = std::numeric_limits<int64_t>::max();
            } else {                                            //         1 Month
                int64_t nSuperblockCycleSeconds = 16616/*Params().GetConsensus().nSuperblockCycle*/ * Params().GetConsensus().nPowTargetSpacing;
                nTimeExpired = pObj->GetCreationTime() + 2 * nSuperblockCycleSeconds + GOVERNANCE_DELETION_DELAY;
            }

            mapErasedGovernanceObjects.insert(std::make_pair(nHash, nTimeExpired));
            mapObjects.erase(it++);
        } else {
            // NOTE: triggers are handled via triggerman
            if (pObj->GetObjectType() == GOVERNANCE_OBJECT_PROPOSAL) {
                CProposalValidator validator(pObj->GetDataAsHexString());
                if (!validator.Validate()) {
                    LogPrint(BCLog::MN, "CGovernanceManager::UpdateCachesAndClean -- set for deletion expired obj %s\n", (*it).first.ToString());
                    pObj->fCachedDelete = true;
                    if (pObj->nDeletionTime == 0) {
                        pObj->nDeletionTime = nNow;
                    }
                }
            }
            ++it;
        }
    }

    // forget about expired deleted objects
    hash_time_m_it s_it = mapErasedGovernanceObjects.begin();
    while(s_it != mapErasedGovernanceObjects.end()) {
        if (s_it->second < nNow)
            mapErasedGovernanceObjects.erase(s_it++);
        else
            ++s_it;
    }

    LogPrint(BCLog::MN, "CGovernanceManager::UpdateCachesAndClean -- %s\n", ToString());
}

CGovernanceObject* CGovernanceManager::FindGovernanceObject(const uint256& nHash) {
    LOCK(cs);
    if (mapObjects.count(nHash)) return &mapObjects[nHash];
    return nullptr;
}

std::vector<CGovernanceVote> CGovernanceManager::GetMatchingVotes(const uint256& nParentHash) const {
    LOCK(cs);
    std::vector<CGovernanceVote> vecResult;

    object_m_cit it = mapObjects.find(nParentHash);
    if (it == mapObjects.end()) return vecResult;

    return it->second.GetVoteFile().GetVotes();
}

std::vector<CGovernanceVote> CGovernanceManager::GetCurrentVotes(const uint256& nParentHash, const COutPoint& mnCollateralOutpointFilter) const {
    LOCK(cs);
    std::vector<CGovernanceVote> vecResult;

    // Find the governance object or short-circuit.
    object_m_cit it = mapObjects.find(nParentHash);
    if (it == mapObjects.end()) return vecResult;
    const CGovernanceObject& govobj = it->second;

    CMasternode mn;
    std::map<COutPoint, CMasternode> mapMasternodes;
    if (mnCollateralOutpointFilter.IsNull()) {
        mapMasternodes = mnodeman.GetFullMasternodeMap();
    } else if (mnodeman.Get(mnCollateralOutpointFilter, mn)) {
        mapMasternodes[mnCollateralOutpointFilter] = mn;
    }

    // Loop thru each MN collateral outpoint and get the votes for the `nParentHash` governance object
    for (const auto& mnpair : mapMasternodes) {
        // get a vote_rec_t from the govobj
        vote_rec_t voteRecord;
        if (!govobj.GetCurrentMNVotes(mnpair.first, voteRecord)) continue;

        for (vote_instance_m_it it3 = voteRecord.mapInstances.begin(); it3 != voteRecord.mapInstances.end(); ++it3) {
            int signal = (it3->first);
            int outcome = ((it3->second).eOutcome);
            int64_t nCreationTime = ((it3->second).nCreationTime);

            CGovernanceVote vote = CGovernanceVote(mnpair.first, nParentHash, (vote_signal_enum_t)signal, (vote_outcome_enum_t)outcome);
            vote.SetTime(nCreationTime);

            vecResult.push_back(vote);
        }
    }

    return vecResult;
}

std::vector<const CGovernanceObject*> CGovernanceManager::GetAllNewerThan(int64_t nMoreThanTime) const {
    LOCK(cs);

    std::vector<const CGovernanceObject*> vGovObjs;

    object_m_cit it = mapObjects.begin();
    while(it != mapObjects.end()) {
        // IF THIS OBJECT IS OLDER THAN TIME, CONTINUE

        if ((*it).second.GetCreationTime() < nMoreThanTime) {
            ++it;
            continue;
        }

        // ADD GOVERNANCE OBJECT TO LIST

        const CGovernanceObject* pGovObj = &((*it).second);
        vGovObjs.push_back(pGovObj);

        // NEXT

        ++it;
    }

    return vGovObjs;
}

//
// Sort by votes, if there's a tie sort by their feeHash TX
//
struct sortProposalsByVotes {
    bool operator()(const std::pair<CGovernanceObject*, int> &left, const std::pair<CGovernanceObject*, int> &right) {
        if (left.second != right.second) return (left.second > right.second);
        return (UintToArith256(left.first->GetCollateralHash()) > UintToArith256(right.first->GetCollateralHash()));
    }
};

void CGovernanceManager::DoMaintenance(CConnman& connman) {
    if (!masternodeSync.IsSynced()) return;

    // CHECK OBJECTS WE'VE ASKED FOR, REMOVE OLD ENTRIES

    CleanOrphanObjects();

    RequestOrphanObjects(connman);

    // CHECK AND REMOVE - REPROCESS GOVERNANCE OBJECTS

    UpdateCachesAndClean();
}

bool CGovernanceManager::ConfirmInventoryRequest(const CInv& inv) {
    // do not request objects until it's time to sync
    if (!masternodeSync.IsWinnersListSynced()) return false;

    LOCK(cs);

    LogPrint(BCLog::MN, "CGovernanceManager::ConfirmInventoryRequest inv = %s\n", inv.ToString());

    // First check if we've already recorded this object
    switch(inv.type) {
        case MSG_GOVERNANCE_OBJECT:
            if (mapObjects.count(inv.hash) == 1 || mapPostponedObjects.count(inv.hash) == 1) {
                LogPrint(BCLog::MN, "CGovernanceManager::ConfirmInventoryRequest already have governance object, returning false\n");
                return false;
            }
            break;
        case MSG_GOVERNANCE_OBJECT_VOTE:
            if (cmapVoteToObject.HasKey(inv.hash)) {
                LogPrint(BCLog::MN, "CGovernanceManager::ConfirmInventoryRequest already have governance vote, returning false\n");
                return false;
            }
            break;
        default:
            LogPrint(BCLog::MN, "CGovernanceManager::ConfirmInventoryRequest unknown type, returning false\n");
            return false;
    }
    hash_s_t* setHash = nullptr;
    switch(inv.type) {
        case MSG_GOVERNANCE_OBJECT:
            setHash = &setRequestedObjects;
            break;
        case MSG_GOVERNANCE_OBJECT_VOTE:
            setHash = &setRequestedVotes;
            break;
        default:
            return false;
    }

    hash_s_cit it = setHash->find(inv.hash);
    if (it == setHash->end()) {
        setHash->insert(inv.hash);
        LogPrint(BCLog::MN, "CGovernanceManager::ConfirmInventoryRequest added inv to requested set\n");
    }

    LogPrint(BCLog::MN, "CGovernanceManager::ConfirmInventoryRequest reached end, returning true\n");
    return true;
}

void CGovernanceManager::SyncSingleObjAndItsVotes(CNode* pnode, const uint256& nProp, const CBloomFilter& filter, CConnman& connman) {
    // do not provide any data until our node is synced
    if (!masternodeSync.IsSynced()) return;

    int nVoteCount = 0;

    // SYNC GOVERNANCE OBJECTS WITH OTHER CLIENT

    LogPrint(BCLog::MN, "CGovernanceManager::%s -- syncing single object to peer=%d, nProp = %s\n", __func__, pnode->GetId(), nProp.ToString());

    LOCK2(cs_main, cs);

    // single valid object and its valid votes
    object_m_it it = mapObjects.find(nProp);
    if (it == mapObjects.end()) {
        LogPrint(BCLog::MN, "CGovernanceManager::%s -- no matching object for hash %s, peer=%d\n", __func__, nProp.ToString(), pnode->GetId());
        return;
    }
    CGovernanceObject& govobj = it->second;
    std::string strHash = it->first.ToString();

    LogPrint(BCLog::MN, "CGovernanceManager::%s -- attempting to sync govobj: %s, peer=%d\n", __func__, strHash, pnode->GetId());

    if(govobj.IsSetCachedDelete() || govobj.IsSetExpired()) {
        LogPrintf("CGovernanceManager::%s -- not syncing deleted/expired govobj: %s, peer=%d\n", __func__, strHash, pnode->GetId());
        return;
    }

    // Push the govobj inventory message over to the other client
    LogPrint(BCLog::MN, "CGovernanceManager::%s -- syncing govobj: %s, peer=%d\n", __func__, strHash, pnode->GetId());
    pnode->PushInventory(CInv(MSG_GOVERNANCE_OBJECT, it->first));

    auto fileVotes = govobj.GetVoteFile();

    for (const auto& vote : fileVotes.GetVotes()) {
        uint256 nVoteHash = vote.GetHash();
        if (filter.contains(nVoteHash) || !vote.IsValid(true)) continue;
        pnode->PushInventory(CInv(MSG_GOVERNANCE_OBJECT_VOTE, nVoteHash));
        ++nVoteCount;
    }

    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::SYNCSTATUSCOUNT, MASTERNODE_SYNC_GOVOBJ, 1));
    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::SYNCSTATUSCOUNT, MASTERNODE_SYNC_GOVOBJ_VOTE, nVoteCount));
    LogPrintf("CGovernanceManager::%s -- sent 1 object and %d votes to peer=%d\n", __func__, nVoteCount, pnode->GetId());
}

void CGovernanceManager::SyncAll(CNode* pnode, CConnman& connman) const {
    // do not provide any data until our node is synced
    if (!masternodeSync.IsSynced()) return;

    if (netfulfilledman.HasFulfilledRequest(pnode->addr, NetMsgType::MNGOVERNANCESYNC)) {
        LOCK(cs_main);
        // Asking for the whole list multiple times in a short period of time is no good
        LogPrint(BCLog::MN, "CGovernanceManager::%s -- peer already asked me for the list\n", __func__);
        Misbehaving(pnode->GetId(), 20, "");
        return;
    }
    netfulfilledman.AddFulfilledRequest(pnode->addr, NetMsgType::MNGOVERNANCESYNC);

    int nObjCount = 0;
    int nVoteCount = 0;

    // SYNC GOVERNANCE OBJECTS WITH OTHER CLIENT

    LogPrint(BCLog::MN, "CGovernanceManager::%s -- syncing all objects to peer=%d\n", __func__, pnode->GetId());

    LOCK2(cs_main, cs);

    // all valid objects, no votes
    for(object_m_cit it = mapObjects.begin(); it != mapObjects.end(); ++it) {
        const CGovernanceObject& govobj = it->second;
        std::string strHash = it->first.ToString();

        LogPrint(BCLog::MN, "CGovernanceManager::%s -- attempting to sync govobj: %s, peer=%d\n", __func__, strHash, pnode->GetId());

        if(govobj.IsSetCachedDelete() || govobj.IsSetExpired()) {
            LogPrintf("CGovernanceManager::%s -- not syncing deleted/expired govobj: %s, peer=%d\n", __func__,
                      strHash, pnode->GetId());
            continue;
        }

        // Push the inventory budget proposal message over to the other client
        LogPrint(BCLog::MN, "CGovernanceManager::%s -- syncing govobj: %s, peer=%d\n", __func__, strHash, pnode->GetId());
        pnode->PushInventory(CInv(MSG_GOVERNANCE_OBJECT, it->first));
        ++nObjCount;
    }

    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::SYNCSTATUSCOUNT, MASTERNODE_SYNC_GOVOBJ, nObjCount));
    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::SYNCSTATUSCOUNT, MASTERNODE_SYNC_GOVOBJ_VOTE, nVoteCount));
    LogPrintf("CGovernanceManager::%s -- sent %d objects and %d votes to peer=%d\n", __func__, nObjCount, nVoteCount, pnode->GetId());
}

void CGovernanceManager::MasternodeRateUpdate(const CGovernanceObject& govobj) {
    if (govobj.GetObjectType() != GOVERNANCE_OBJECT_TRIGGER) return;

    const COutPoint& masternodeOutpoint = govobj.GetMasternodeOutpoint();
    txout_m_it it  = mapLastMasternodeObject.find(masternodeOutpoint);

    if (it == mapLastMasternodeObject.end())
        it = mapLastMasternodeObject.insert(txout_m_t::value_type(masternodeOutpoint, last_object_rec(true))).first;

    int64_t nTimestamp = govobj.GetCreationTime();
    it->second.triggerBuffer.AddTimestamp(nTimestamp);

    if (nTimestamp > GetTime() + MAX_TIME_FUTURE_DEVIATION - RELIABLE_PROPAGATION_TIME) {
        // schedule additional relay for the object
        setAdditionalRelayObjects.insert(govobj.GetHash());
    }

    it->second.fStatusOK = true;
}

bool CGovernanceManager::MasternodeRateCheck(const CGovernanceObject& govobj, bool fUpdateFailStatus) {
    bool fRateCheckBypassed;
    return MasternodeRateCheck(govobj, fUpdateFailStatus, true, fRateCheckBypassed);
}

bool CGovernanceManager::MasternodeRateCheck(const CGovernanceObject& govobj, bool fUpdateFailStatus, bool fForce, bool& fRateCheckBypassed) {
    LOCK(cs);

    fRateCheckBypassed = false;

    if (!masternodeSync.IsSynced()) {
        return true;
    }

    if (!fRateChecksEnabled) {
        return true;
    }

    if (govobj.GetObjectType() != GOVERNANCE_OBJECT_TRIGGER) {
        return true;
    }

    const COutPoint& masternodeOutpoint = govobj.GetMasternodeOutpoint();
    int64_t nTimestamp = govobj.GetCreationTime();
    int64_t nNow = GetAdjustedTime();               // 1 Month
    int64_t nSuperblockCycleSeconds = 16616/*Params().GetConsensus().nSuperblockCycle*/ * Params().GetConsensus().nPowTargetSpacing;

    std::string strHash = govobj.GetHash().ToString();

    if (nTimestamp < nNow - 2 * nSuperblockCycleSeconds) {
        LogPrintf("CGovernanceManager::MasternodeRateCheck -- object %s rejected due to too old timestamp, masternode = %s, timestamp = %d, current time = %d\n",
                 strHash, masternodeOutpoint.ToString(), nTimestamp, nNow);
        return false;
    }

    if (nTimestamp > nNow + MAX_TIME_FUTURE_DEVIATION) {
        LogPrintf("CGovernanceManager::MasternodeRateCheck -- object %s rejected due to too new (future) timestamp, masternode = %s, timestamp = %d, current time = %d\n",
                 strHash, masternodeOutpoint.ToString(), nTimestamp, nNow);
        return false;
    }

    txout_m_it it  = mapLastMasternodeObject.find(masternodeOutpoint);
    if (it == mapLastMasternodeObject.end())
        return true;

    if (it->second.fStatusOK && !fForce) {
        fRateCheckBypassed = true;
        return true;
    }

    // Allow 1 trigger per mn per cycle, with a small fudge factor
    double dMaxRate = 2 * 1.1 / double(nSuperblockCycleSeconds);

    // Temporary copy to check rate after new timestamp is added
    CRateCheckBuffer buffer = it->second.triggerBuffer;

    buffer.AddTimestamp(nTimestamp);
    double dRate = buffer.GetRate();

    if (dRate < dMaxRate) {
        return true;
    }

    LogPrintf("CGovernanceManager::MasternodeRateCheck -- Rate too high: object hash = %s, masternode = %s, object timestamp = %d, rate = %f, max rate = %f\n",
              strHash, masternodeOutpoint.ToString(), nTimestamp, dRate, dMaxRate);

    if (fUpdateFailStatus)
        it->second.fStatusOK = false;

    return false;
}

bool CGovernanceManager::ProcessVote(CNode* pfrom, const CGovernanceVote& vote, CGovernanceException& exception, CConnman& connman) {
    ENTER_CRITICAL_SECTION(cs);
    uint256 nHashVote = vote.GetHash();
    uint256 nHashGovobj = vote.GetParentHash();

    if (cmapVoteToObject.HasKey(nHashVote)) {
        LogPrint(BCLog::MN, "CGovernanceObject::ProcessVote -- skipping known valid vote %s for object %s\n", nHashVote.ToString(), nHashGovobj.ToString());
        LEAVE_CRITICAL_SECTION(cs);
        return false;
    }

    if (cmapInvalidVotes.HasKey(nHashVote)) {
        std::ostringstream ostr;
        ostr << "CGovernanceManager::ProcessVote -- Old invalid vote "
                << ", MN outpoint = " << vote.GetMasternodeOutpoint().ToString()
                << ", governance object hash = " << nHashGovobj.ToString();
        LogPrintf("%s\n", ostr.str());
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_PERMANENT_ERROR, 20);
        LEAVE_CRITICAL_SECTION(cs);
        return false;
    }

    object_m_it it = mapObjects.find(nHashGovobj);
    if (it == mapObjects.end()) {
        std::ostringstream ostr;
        ostr << "CGovernanceManager::ProcessVote -- Unknown parent object " << nHashGovobj.ToString()
             << ", MN outpoint = " << vote.GetMasternodeOutpoint().ToString();
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_WARNING);
        if(cmmapOrphanVotes.Insert(nHashGovobj, vote_time_pair_t(vote, GetAdjustedTime() + GOVERNANCE_ORPHAN_EXPIRATION_TIME))) {
            LEAVE_CRITICAL_SECTION(cs);
            RequestGovernanceObject(pfrom, nHashGovobj, connman);
            LogPrintf("%s\n", ostr.str());
            return false;
        }

        LogPrint(BCLog::MN, "%s\n", ostr.str());
        LEAVE_CRITICAL_SECTION(cs);
        return false;
    }

    CGovernanceObject& govobj = it->second;

    if (govobj.IsSetCachedDelete() || govobj.IsSetExpired()) {
        LogPrint(BCLog::MN, "CGovernanceObject::ProcessVote -- ignoring vote for expired or deleted object, hash = %s\n", nHashGovobj.ToString());
        LEAVE_CRITICAL_SECTION(cs);
        return false;
    }

    bool fOk = govobj.ProcessVote(pfrom, vote, exception, connman) && cmapVoteToObject.Insert(nHashVote, &govobj);
    LEAVE_CRITICAL_SECTION(cs);
    return fOk;
}

void CGovernanceManager::CheckMasternodeOrphanVotes(CConnman& connman) {
    LOCK2(cs_main, cs);

    ScopedLockBool guard(cs, fRateChecksEnabled, false);

    for(object_m_it it = mapObjects.begin(); it != mapObjects.end(); ++it) {
        it->second.CheckOrphanVotes(connman);
    }
}

void CGovernanceManager::CheckMasternodeOrphanObjects(CConnman& connman) {
    LOCK2(cs_main, cs);
    int64_t nNow = GetAdjustedTime();
    ScopedLockBool guard(cs, fRateChecksEnabled, false);
    object_info_m_it it = mapMasternodeOrphanObjects.begin();
    while(it != mapMasternodeOrphanObjects.end()) {
        object_info_pair_t& pair = it->second;
        CGovernanceObject& govobj = pair.first;

        if(pair.second.nExpirationTime >= nNow) {
            std::string strError;
            bool fMasternodeMissing = false;
            bool fConfirmationsMissing = false;
            bool fIsValid = govobj.IsValidLocally(strError, fMasternodeMissing, fConfirmationsMissing, true);

            if (fIsValid) {
                AddGovernanceObject(govobj, connman);
            } else if(fMasternodeMissing) {
                ++it;
                continue;
            }
        } else {
            // apply node's ban score
            Misbehaving(pair.second.idFrom, 20, "");
        }

        auto it_count = mapMasternodeOrphanCounter.find(govobj.GetMasternodeOutpoint());
        if(--it_count->second == 0)
            mapMasternodeOrphanCounter.erase(it_count);

        mapMasternodeOrphanObjects.erase(it++);
    }
}

void CGovernanceManager::CheckPostponedObjects(CConnman& connman) {
    if(!masternodeSync.IsSynced()) return;

    LOCK2(cs_main, cs);

    // Check postponed proposals
    for(object_m_it it = mapPostponedObjects.begin(); it != mapPostponedObjects.end();) {

        const uint256& nHash = it->first;
        CGovernanceObject& govobj = it->second;

        assert(govobj.GetObjectType() != GOVERNANCE_OBJECT_TRIGGER);

        std::string strError;
        bool fMissingConfirmations;
        if (govobj.IsCollateralValid(strError, fMissingConfirmations)) {
            if(govobj.IsValidLocally(strError, false))
                AddGovernanceObject(govobj, connman);
            else
                LogPrintf("CGovernanceManager::CheckPostponedObjects -- %s invalid\n", nHash.ToString());

        } else if(fMissingConfirmations) {
            // wait for more confirmations
            ++it;
            continue;
        }

        // remove processed or invalid object from the queue
        mapPostponedObjects.erase(it++);
    }

    // Perform additional relays for triggers
    int64_t nNow = GetAdjustedTime();               // 1 Month
    int64_t nSuperblockCycleSeconds = 16616/*Params().GetConsensus().nSuperblockCycle*/ * Params().GetConsensus().nPowTargetSpacing;

    for(hash_s_it it = setAdditionalRelayObjects.begin(); it != setAdditionalRelayObjects.end();) {
        object_m_it itObject = mapObjects.find(*it);
        if(itObject != mapObjects.end()) {
            CGovernanceObject& govobj = itObject->second;

            int64_t nTimestamp = govobj.GetCreationTime();

            bool fValid = (nTimestamp <= nNow + MAX_TIME_FUTURE_DEVIATION) && (nTimestamp >= nNow - 2 * nSuperblockCycleSeconds);
            bool fReady = (nTimestamp <= nNow + MAX_TIME_FUTURE_DEVIATION - RELIABLE_PROPAGATION_TIME);

            if (fValid) {
                if(fReady) {
                    LogPrintf("CGovernanceManager::CheckPostponedObjects -- additional relay: hash = %s\n", govobj.GetHash().ToString());
                    govobj.Relay(connman);
                } else {
                    it++;
                    continue;
                }
            }
        } else {
            LogPrintf("CGovernanceManager::CheckPostponedObjects -- additional relay of unknown object: %s\n", it->ToString());
        }
        setAdditionalRelayObjects.erase(it++);
    }
}

void CGovernanceManager::RequestGovernanceObject(CNode* pfrom, const uint256& nHash, CConnman& connman, bool fUseFilter) {
    if (!pfrom) return;

    LogPrint(BCLog::MN, "CGovernanceObject::RequestGovernanceObject -- hash = %s (peer=%d)\n", nHash.ToString(), pfrom->GetId());

    CNetMsgMaker msgMaker(pfrom->GetSendVersion());

    CBloomFilter filter;
    filter.clear();

    int nVoteCount = 0;
    if(fUseFilter) {
        LOCK(cs);
        CGovernanceObject* pObj = FindGovernanceObject(nHash);

        if(pObj) {
            filter = CBloomFilter(20000, GOVERNANCE_FILTER_FP_RATE, GetRandInt(999999), BLOOM_UPDATE_ALL);
            std::vector<CGovernanceVote> vecVotes = pObj->GetVoteFile().GetVotes();
            nVoteCount = vecVotes.size();
            for(size_t i = 0; i < vecVotes.size(); ++i) {
                filter.insert(vecVotes[i].GetHash());
            }
        }
    }

    LogPrint(BCLog::MN, "CGovernanceManager::RequestGovernanceObject -- nHash %s nVoteCount %d peer=%d\n", nHash.ToString(), nVoteCount, pfrom->GetId());
    connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::MNGOVERNANCESYNC, nHash, filter));
}

int CGovernanceManager::RequestGovernanceObjectVotes(CNode* pnode, CConnman& connman) {
    std::vector<CNode*> vNodesCopy;
    vNodesCopy.push_back(pnode);
    return RequestGovernanceObjectVotes(vNodesCopy, connman);
}

int CGovernanceManager::RequestGovernanceObjectVotes(const std::vector<CNode*>& vNodesCopy, CConnman& connman) {
    static std::map<uint256, std::map<CService, int64_t> > mapAskedRecently;

    if(vNodesCopy.empty()) return -1;

    int64_t nNow = GetTime();
    int nTimeout = 60 * 60;
    size_t nPeersPerHashMax = 3;

    std::vector<CGovernanceObject*> vpGovObjsTmp;
    std::vector<CGovernanceObject*> vpGovObjsTriggersTmp;

    // This should help us to get some idea about an impact this can bring once deployed on mainnet.
    // Testnet is ~40 times smaller in masternode count, but only ~1000 masternodes usually vote,
    // so 1 obj on mainnet == ~10 objs or ~1000 votes on testnet. However we want to test a higher
    // number of votes to make sure it's robust enough, so aim at 2000 votes per masternode per request.
    // On mainnet nMaxObjRequestsPerNode is always set to 1.
    int nMaxObjRequestsPerNode = 1;
    size_t nProjectedVotes = 2000;

    {
        LOCK2(cs_main, cs);

        if(mapObjects.empty()) return -2;

        for(object_m_it it = mapObjects.begin(); it != mapObjects.end(); ++it) {
            if(mapAskedRecently.count(it->first)) {
                std::map<CService, int64_t>::iterator it1 = mapAskedRecently[it->first].begin();
                while(it1 != mapAskedRecently[it->first].end()) {
                    if(it1->second < nNow) {
                        mapAskedRecently[it->first].erase(it1++);
                    } else {
                        ++it1;
                    }
                }
                if(mapAskedRecently[it->first].size() >= nPeersPerHashMax) continue;
            }
            if(it->second.nObjectType == GOVERNANCE_OBJECT_TRIGGER) {
                vpGovObjsTriggersTmp.push_back(&(it->second));
            } else {
                vpGovObjsTmp.push_back(&(it->second));
            }
        }
    }

    LogPrint(BCLog::MN, "CGovernanceManager::RequestGovernanceObjectVotes -- start: vpGovObjsTriggersTmp %d vpGovObjsTmp %d mapAskedRecently %d\n",
                vpGovObjsTriggersTmp.size(), vpGovObjsTmp.size(), mapAskedRecently.size());

    FastRandomContext insecure_rand;
    // shuffle pointers
    std::random_shuffle(vpGovObjsTriggersTmp.begin(), vpGovObjsTriggersTmp.end(), insecure_rand);
    std::random_shuffle(vpGovObjsTmp.begin(), vpGovObjsTmp.end(), insecure_rand);

    for (int i = 0; i < nMaxObjRequestsPerNode; ++i) {
        uint256 nHashGovobj;

        // ask for triggers first
        if(vpGovObjsTriggersTmp.size()) {
            nHashGovobj = vpGovObjsTriggersTmp.back()->GetHash();
        } else {
            if(vpGovObjsTmp.empty()) break;
            nHashGovobj = vpGovObjsTmp.back()->GetHash();
        }
        bool fAsked = false;
        for (const auto& pnode : vNodesCopy) {
            // Only use regular peers, don't try to ask from outbound "masternode" connections -
            // they stay connected for a short period of time and it's possible that we won't get everything we should.
            // Only use outbound connections - inbound connection could be a "masternode" connection
            // initiated from another node, so skip it too.
            if (pnode->fMasternode || (fMasternodeMode && pnode->fInbound)) continue;
            // stop early to prevent setAskFor overflow
            size_t nProjectedSize = pnode->setAskFor.size() + nProjectedVotes;
            if (nProjectedSize > SETASKFOR_MAX_SZ/2) continue;
            // to early to ask the same node
            if(mapAskedRecently[nHashGovobj].count(pnode->addr)) continue;

            RequestGovernanceObject(pnode, nHashGovobj, connman, true);
            mapAskedRecently[nHashGovobj][pnode->addr] = nNow + nTimeout;
            fAsked = true;
            // stop loop if max number of peers per obj was asked
            if(mapAskedRecently[nHashGovobj].size() >= nPeersPerHashMax) break;
        }
        // NOTE: this should match `if` above (the one before `while`)
        if(vpGovObjsTriggersTmp.size()) {
            vpGovObjsTriggersTmp.pop_back();
        } else {
            vpGovObjsTmp.pop_back();
        }
        if(!fAsked) i--;
    }
    LogPrint(BCLog::MN, "CGovernanceManager::RequestGovernanceObjectVotes -- end: vpGovObjsTriggersTmp %d vpGovObjsTmp %d mapAskedRecently %d\n",
                vpGovObjsTriggersTmp.size(), vpGovObjsTmp.size(), mapAskedRecently.size());

    return int(vpGovObjsTriggersTmp.size() + vpGovObjsTmp.size());
}

bool CGovernanceManager::AcceptObjectMessage(const uint256& nHash) {
    LOCK(cs);
    return AcceptMessage(nHash, setRequestedObjects);
}

bool CGovernanceManager::AcceptVoteMessage(const uint256& nHash) {
    LOCK(cs);
    return AcceptMessage(nHash, setRequestedVotes);
}

bool CGovernanceManager::AcceptMessage(const uint256& nHash, hash_s_t& setHash) {
    hash_s_it it = setHash.find(nHash);
    if (it == setHash.end()) {
        // We never requested this
        return false;
    }
    // Only accept one response
    setHash.erase(it);
    return true;
}

void CGovernanceManager::RebuildIndexes() {
    LOCK(cs);

    cmapVoteToObject.Clear();
    for (object_m_it it = mapObjects.begin(); it != mapObjects.end(); ++it) {
        CGovernanceObject& govobj = it->second;
        std::vector<CGovernanceVote> vecVotes = govobj.GetVoteFile().GetVotes();
        for(size_t i = 0; i < vecVotes.size(); ++i) {
            cmapVoteToObject.Insert(vecVotes[i].GetHash(), &govobj);
        }
    }
}

void CGovernanceManager::InitOnLoad() {
    LOCK(cs);
    int64_t nStart = GetTimeMillis();
    LogPrintf("Preparing masternode indexes and governance triggers...\n");
    RebuildIndexes();
    LogPrintf("Masternode indexes and governance triggers prepared  %dms\n", GetTimeMillis() - nStart);
    LogPrintf("     %s\n", ToString());
}

std::string CGovernanceManager::ToString() const {
    LOCK(cs);

    int nProposalCount = 0;
    int nTriggerCount = 0;
    int nOtherCount = 0;

    object_m_cit it = mapObjects.begin();

    while(it != mapObjects.end()) {
        switch(it->second.GetObjectType()) {
            case GOVERNANCE_OBJECT_PROPOSAL:
                nProposalCount++;
                break;
            case GOVERNANCE_OBJECT_TRIGGER:
                nTriggerCount++;
                break;
            default:
                nOtherCount++;
                break;
        }
        ++it;
    }

    return strprintf("Governance Objects: %d (Proposals: %d, Triggers: %d, Other: %d; Erased: %d), Votes: %d",
                    (int)mapObjects.size(),
                    nProposalCount, nTriggerCount, nOtherCount, (int)mapErasedGovernanceObjects.size(),
                    (int)cmapVoteToObject.GetSize());
}

UniValue CGovernanceManager::ToJson() const {
    LOCK(cs);

    int nProposalCount = 0;
    int nTriggerCount = 0;
    int nOtherCount = 0;

    for (const auto& objpair : mapObjects) {
        switch(objpair.second.GetObjectType()) {
            case GOVERNANCE_OBJECT_PROPOSAL:
                nProposalCount++;
                break;
            case GOVERNANCE_OBJECT_TRIGGER:
                nTriggerCount++;
                break;
            default:
                nOtherCount++;
                break;
        }
    }

    UniValue jsonObj(UniValue::VOBJ);
    jsonObj.push_back(Pair("objects_total", (int)mapObjects.size()));
    jsonObj.push_back(Pair("proposals", nProposalCount));
    jsonObj.push_back(Pair("triggers", nTriggerCount));
    jsonObj.push_back(Pair("other", nOtherCount));
    jsonObj.push_back(Pair("erased", (int)mapErasedGovernanceObjects.size()));
    jsonObj.push_back(Pair("votes", (int)cmapVoteToObject.GetSize()));
    return jsonObj;
}

void CGovernanceManager::UpdatedBlockTip(const CBlockIndex *pindex, CConnman& connman) {
    // Note this gets called from ActivateBestChain without cs_main being held
    // so it should be safe to lock our mutex here without risking a deadlock
    // On the other hand it should be safe for us to access pindex without holding a lock
    // on cs_main because the CBlockIndex objects are dynamically allocated and
    // presumably never deleted.
    if (!pindex) {
        return;
    }

    nCachedBlockHeight = pindex->nHeight;
    LogPrint(BCLog::MN, "CGovernanceManager::UpdatedBlockTip -- nCachedBlockHeight: %d\n", nCachedBlockHeight);

    CheckPostponedObjects(connman);
}

void CGovernanceManager::RequestOrphanObjects(CConnman& connman) {
    std::vector<uint256> vecHashesFiltered;
    {
        std::vector<uint256> vecHashes;
        LOCK(cs);
        cmmapOrphanVotes.GetKeys(vecHashes);
        for(size_t i = 0; i < vecHashes.size(); ++i) {
            const uint256& nHash = vecHashes[i];
            if(mapObjects.find(nHash) == mapObjects.end()) {
                vecHashesFiltered.push_back(nHash);
            }
        }
    }
    LogPrint(BCLog::MN, "CGovernanceObject::RequestOrphanObjects -- number objects = %d\n", vecHashesFiltered.size());

    connman.ForEachNode([this, &connman, &vecHashesFiltered](CNode* pnode) {
        if (!(pnode && pnode->fSuccessfullyConnected && !pnode->fDisconnect)) return;
        for (size_t i = 0; i < vecHashesFiltered.size(); ++i) {
            const uint256& nHash = vecHashesFiltered[i];
            if (!pnode->fMasternode) RequestGovernanceObject(pnode, nHash, connman);
        }
    }); 
}

void CGovernanceManager::CleanOrphanObjects() {
    LOCK(cs);
    const vote_cmm_t::list_t& items = cmmapOrphanVotes.GetItemList();

    int64_t nNow = GetAdjustedTime();

    vote_cmm_t::list_cit it = items.begin();
    while (it != items.end()) {
        vote_cmm_t::list_cit prevIt = it;
        ++it;
        const vote_time_pair_t& pairVote = prevIt->value;
        if(pairVote.second < nNow) {
            cmmapOrphanVotes.Erase(prevIt->key, prevIt->value);
        }
    }
}

// governance-validators

const size_t MAX_DATA_SIZE  = 512;
const size_t MAX_NAME_SIZE  = 40;

CProposalValidator::CProposalValidator(const std::string& strHexData) :
    objJSON(UniValue::VOBJ),
    fJSONValid(false),
    strErrorMessages()
{
    if(!strHexData.empty()) {
        ParseStrHexData(strHexData);
    }
}

void CProposalValidator::ParseStrHexData(const std::string& strHexData)
{
    std::vector<unsigned char> v = ParseHex(strHexData);
    if (v.size() > MAX_DATA_SIZE) {
        strErrorMessages = strprintf("data exceeds %lu characters;", MAX_DATA_SIZE);
        return;
    }
    ParseJSONData(std::string(v.begin(), v.end()));
}

bool CProposalValidator::Validate(bool fCheckExpiration)
{
    if(!fJSONValid) {
        strErrorMessages += "JSON parsing error;";
        return false;
    }
    if(!ValidateName()) {
        strErrorMessages += "Invalid name;";
        return false;
    }
    if(!ValidateStartEndEpoch(fCheckExpiration)) {
        strErrorMessages += "Invalid start:end range;";
        return false;
    }
    if(!ValidatePaymentAmount()) {
        strErrorMessages += "Invalid payment amount;";
        return false;
    }
    if(!ValidatePaymentAddress()) {
        strErrorMessages += "Invalid payment address;";
        return false;
    }
    if(!ValidateURL()) {
        strErrorMessages += "Invalid URL;";
        return false;
    }
    return true;
}

bool CProposalValidator::ValidateName()
{
    std::string strName;
    if(!GetDataValue("name", strName)) {
        strErrorMessages += "name field not found;";
        return false;
    }

    if(strName.size() > MAX_NAME_SIZE) {
        strErrorMessages += strprintf("name exceeds %lu characters;", MAX_NAME_SIZE);
        return false;
    }

    static const std::string strAllowedChars = "-_abcdefghijklmnopqrstuvwxyz0123456789";

    std::transform(strName.begin(), strName.end(), strName.begin(), ::tolower);

    if(strName.find_first_not_of(strAllowedChars) != std::string::npos) {
        strErrorMessages += "name contains invalid characters;";
        return false;
    }

    return true;
}

bool CProposalValidator::ValidateStartEndEpoch(bool fCheckExpiration)
{
    int64_t nStartEpoch = 0;
    int64_t nEndEpoch = 0;

    if(!GetDataValue("start_epoch", nStartEpoch)) {
        strErrorMessages += "start_epoch field not found;";
        return false;
    }

    if(!GetDataValue("end_epoch", nEndEpoch)) {
        strErrorMessages += "end_epoch field not found;";
        return false;
    }

    if(nEndEpoch <= nStartEpoch) {
        strErrorMessages += "end_epoch <= start_epoch;";
        return false;
    }

    if(fCheckExpiration && nEndEpoch <= GetAdjustedTime()) {
        strErrorMessages += "expired;";
        return false;
    }

    return true;
}

bool CProposalValidator::ValidatePaymentAmount()
{
    double dValue = 0.0;

    if(!GetDataValue("payment_amount", dValue)) {
        strErrorMessages += "payment_amount field not found;";
        return false;
    }

    if(dValue <= 0.0) {
        strErrorMessages += "payment_amount is negative;";
        return false;
    }

    // TODO: Should check for an amount which exceeds the budget but this is
    // currently difficult because start and end epochs are defined in terms of
    // clock time instead of block height.

    return true;
}

bool CProposalValidator::ValidatePaymentAddress()
{
    std::string strPaymentAddress;

    if(!GetDataValue("payment_address", strPaymentAddress)) {
        strErrorMessages += "payment_address field not found;";
        return false;
    }

    if(std::find_if(strPaymentAddress.begin(), strPaymentAddress.end(), ::isspace) != strPaymentAddress.end()) {
        strErrorMessages += "payment_address can't have whitespaces;";
        return false;
    }

    CTxDestination dest = DecodeDestination(strPaymentAddress);
    if(!IsValidDestination(dest)) {
        strErrorMessages += "payment_address is invalid;";
        return false;
    }

    if (GetScriptForDestination(dest).IsPayToScriptHash()) {
        strErrorMessages += "script addresses are not supported;";
        return false;
    }

    return true;
}

bool CProposalValidator::ValidateURL()
{
    std::string strURL;
    if(!GetDataValue("url", strURL)) {
        strErrorMessages += "url field not found;";
        return false;
    }

    if(std::find_if(strURL.begin(), strURL.end(), ::isspace) != strURL.end()) {
        strErrorMessages += "url can't have whitespaces;";
        return false;
    }

    if(strURL.size() < 4U) {
        strErrorMessages += "url too short;";
        return false;
    }

    if(!CheckURL(strURL)) {
        strErrorMessages += "url invalid;";
        return false;
    }

    return true;
}

void CProposalValidator::ParseJSONData(const std::string& strJSONData)
{
    fJSONValid = false;

    if(strJSONData.empty()) {
        return;
    }

    try {
        UniValue obj(UniValue::VOBJ);

        obj.read(strJSONData);

        if (obj.isObject()) {
            objJSON = obj;
        } else {
            std::vector<UniValue> arr1 = obj.getValues();
            std::vector<UniValue> arr2 = arr1.at(0).getValues();
            objJSON = arr2.at(1);
        }

        fJSONValid = true;
    }
    catch(std::exception& e) {
        strErrorMessages += std::string(e.what()) + std::string(";");
    }
    catch(...) {
        strErrorMessages += "Unknown exception;";
    }
}

bool CProposalValidator::GetDataValue(const std::string& strKey, std::string& strValueRet)
{
    bool fOK = false;
    try  {
        strValueRet = objJSON[strKey].get_str();
        fOK = true;
    }
    catch(std::exception& e) {
        strErrorMessages += std::string(e.what()) + std::string(";");
    }
    catch(...) {
        strErrorMessages += "Unknown exception;";
    }
    return fOK;
}

bool CProposalValidator::GetDataValue(const std::string& strKey, int64_t& nValueRet)
{
    bool fOK = false;
    try  {
        const UniValue uValue = objJSON[strKey];
        switch(uValue.getType()) {
        case UniValue::VNUM:
            nValueRet = uValue.get_int64();
            fOK = true;
            break;
        default:
            break;
        }
    }
    catch(std::exception& e) {
        strErrorMessages += std::string(e.what()) + std::string(";");
    }
    catch(...) {
        strErrorMessages += "Unknown exception;";
    }
    return fOK;
}

bool CProposalValidator::GetDataValue(const std::string& strKey, double& dValueRet)
{
    bool fOK = false;
    try  {
        const UniValue uValue = objJSON[strKey];
        switch(uValue.getType()) {
        case UniValue::VNUM:
            dValueRet = uValue.get_real();
            fOK = true;
            break;
        default:
            break;
        }
    }
    catch(std::exception& e) {
        strErrorMessages += std::string(e.what()) + std::string(";");
    }
    catch(...) {
        strErrorMessages += "Unknown exception;";
    }
    return fOK;
}

/*
  The purpose of this function is to replicate the behavior of the
  Python urlparse function used by sentinel (urlparse.py).  This function
  should return false whenever urlparse raises an exception and true
  otherwise.
 */
bool CProposalValidator::CheckURL(const std::string& strURLIn)
{
    std::string strRest(strURLIn);
    std::string::size_type nPos = strRest.find(':');

    if(nPos != std::string::npos) {
        //std::string strSchema = strRest.substr(0,nPos);

        if(nPos < strRest.size()) {
            strRest = strRest.substr(nPos + 1);
        }
        else {
            strRest = "";
        }
    }

    // Process netloc
    if((strRest.size() > 2) && (strRest.substr(0,2) == "//")) {
        static const std::string strNetlocDelimiters = "/?#";

        strRest = strRest.substr(2);

        std::string::size_type nPos2 = strRest.find_first_of(strNetlocDelimiters);

        std::string strNetloc = strRest.substr(0,nPos2);

        if((strNetloc.find('[') != std::string::npos) && (strNetloc.find(']') == std::string::npos)) {
            return false;
        }

        if((strNetloc.find(']') != std::string::npos) && (strNetloc.find('[') == std::string::npos)) {
            return false;
        }
    }

    return true;
}