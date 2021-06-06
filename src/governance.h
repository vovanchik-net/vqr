// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GOVERNANCE_H
#define GOVERNANCE_H

#include <bloom.h>
#include <cachemap.h>
#include <cachemultimap.h>
#include <chain.h>
#include <net.h>
#include <sync.h>
#include <timedata.h>
#include <util.h>
#include <key.h>

#include <univalue.h>

// governance-exceptions

enum CGovernanceExceptionType {
    /// Default value, normally indicates no exception condition occurred
    GOVERNANCE_EXCEPTION_NONE = 0,
    /// Unusual condition requiring no caller action
    GOVERNANCE_EXCEPTION_WARNING = 1,
    /// Requested operation cannot be performed
    GOVERNANCE_EXCEPTION_PERMANENT_ERROR = 2,
    /// Requested operation not currently possible, may resubmit later
    GOVERNANCE_EXCEPTION_TEMPORARY_ERROR = 3,
    /// Unexpected error (ie. should not happen unless there is a bug in the code)
    GOVERNANCE_EXCEPTION_INTERNAL_ERROR = 4
};

inline std::ostream& operator<<(std::ostream& os, CGovernanceExceptionType eType)
{
    switch(eType) {
    case GOVERNANCE_EXCEPTION_NONE:
        os << "GOVERNANCE_EXCEPTION_NONE";
        break;
    case GOVERNANCE_EXCEPTION_WARNING:
        os << "GOVERNANCE_EXCEPTION_WARNING";
        break;
    case GOVERNANCE_EXCEPTION_PERMANENT_ERROR:
        os << "GOVERNANCE_EXCEPTION_PERMANENT_ERROR";
        break;
    case GOVERNANCE_EXCEPTION_TEMPORARY_ERROR:
        os << "GOVERNANCE_EXCEPTION_TEMPORARY_ERROR";
        break;
    case GOVERNANCE_EXCEPTION_INTERNAL_ERROR:
        os << "GOVERNANCE_EXCEPTION_INTERNAL_ERROR";
        break;
    }
    return os;
}

/**
 * A class which encapsulates information about a governance exception condition
 *
 * Derives from std::exception so is suitable for throwing
 * (ie. will be caught by a std::exception handler) but may also be used as a
 * normal object.
 */
class CGovernanceException : public std::exception {
private:
    std::string strMessage;

    CGovernanceExceptionType eType;

    int nNodePenalty;

public:
    CGovernanceException(const std::string& strMessageIn = "", CGovernanceExceptionType eTypeIn = GOVERNANCE_EXCEPTION_NONE,
                int nNodePenaltyIn = 0) : strMessage(), eType(eTypeIn), nNodePenalty(nNodePenaltyIn) {
        std::ostringstream ostr;
        ostr << eType << ":" << strMessageIn;
        strMessage = ostr.str();
    }

    virtual ~CGovernanceException() throw() {}

    virtual const char* what() const throw() override {
        return strMessage.c_str();
    }

    const std::string& GetMessage() const {
        return strMessage;
    }

    CGovernanceExceptionType GetType() const {
        return eType;
    }

    int GetNodePenalty() const {
        return nNodePenalty;
    }
}; 

// governance-vote

// INTENTION OF MASTERNODES REGARDING ITEM
enum vote_outcome_enum_t  {
    VOTE_OUTCOME_NONE      = 0,
    VOTE_OUTCOME_YES       = 1,
    VOTE_OUTCOME_NO        = 2,
    VOTE_OUTCOME_ABSTAIN   = 3
};

// SIGNAL VARIOUS THINGS TO HAPPEN:
enum vote_signal_enum_t  {
    VOTE_SIGNAL_NONE       = 0,
    VOTE_SIGNAL_FUNDING    = 1, //   -- fund this object for it's stated amount
    VOTE_SIGNAL_VALID      = 2, //   -- this object checks out in sentinel engine
    VOTE_SIGNAL_DELETE     = 3, //   -- this object should be deleted from memory entirely
    VOTE_SIGNAL_ENDORSED   = 4, //   -- officially endorsed by the network somehow (delegation)
};

static const int MAX_SUPPORTED_VOTE_SIGNAL = VOTE_SIGNAL_ENDORSED;

/**
* Governance Voting
*
*   Static class for accessing governance data
*/

class CGovernanceVoting {
public:
    static vote_outcome_enum_t ConvertVoteOutcome(const std::string& strVoteOutcome);
    static vote_signal_enum_t ConvertVoteSignal(const std::string& strVoteSignal);
    static std::string ConvertOutcomeToString(vote_outcome_enum_t nOutcome);
    static std::string ConvertSignalToString(vote_signal_enum_t nSignal);
};

//
// CGovernanceVote - Allow a masternode node to vote and broadcast throughout the network
//

class CGovernanceVote {
    friend bool operator==(const CGovernanceVote& vote1, const CGovernanceVote& vote2);
    friend bool operator<(const CGovernanceVote& vote1, const CGovernanceVote& vote2);

private:
    bool fValid; //if the vote is currently valid / counted
    bool fSynced; //if we've sent this to our peers
    int nVoteSignal; // see VOTE_ACTIONS above
    COutPoint masternodeOutpoint;
    uint256 nParentHash;
    int nVoteOutcome; // see VOTE_OUTCOMES above
    int64_t nTime;
    std::vector<unsigned char> vchSig;

    /** Memory only. */
    const uint256 hash;
    void UpdateHash() const;

public:
    CGovernanceVote();
    CGovernanceVote(const COutPoint& outpointMasternodeIn, const uint256& nParentHashIn, vote_signal_enum_t eVoteSignalIn, vote_outcome_enum_t eVoteOutcomeIn);

    bool IsValid() const { return fValid; }

    bool IsSynced() const { return fSynced; }

    int64_t GetTimestamp() const { return nTime; }

    vote_signal_enum_t GetSignal() const  { return vote_signal_enum_t(nVoteSignal); }

    vote_outcome_enum_t GetOutcome() const  { return vote_outcome_enum_t(nVoteOutcome); }

    const uint256& GetParentHash() const { return nParentHash; }

    void SetTime(int64_t nTimeIn) { nTime = nTimeIn; UpdateHash(); }

    void SetSignature(const std::vector<unsigned char>& vchSigIn) { vchSig = vchSigIn; }

    bool Sign(const CKey& keyMasternode, const CPubKey& pubKeyMasternode);
    bool CheckSignature(const CPubKey& pubKeyMasternode) const;
    bool IsValid(bool fSignatureCheck) const;
    void Relay(CConnman& connman) const;

    std::string GetVoteString() const {
        return CGovernanceVoting::ConvertOutcomeToString(GetOutcome());
    }

    const COutPoint& GetMasternodeOutpoint() const { return masternodeOutpoint; }

    /**
    *   GetHash()
    *
    *   GET UNIQUE HASH WITH DETERMINISTIC VALUE OF THIS SPECIFIC VOTE
    */

    uint256 GetHash() const;
    uint256 GetSignatureHash() const;

    std::string ToString() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        READWRITE(masternodeOutpoint);
        READWRITE(nParentHash);
        READWRITE(nVoteOutcome);
        READWRITE(nVoteSignal);
        READWRITE(nTime);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
        if (ser_action.ForRead())
            UpdateHash();
    }
};

// governance-votedb

class CGovernanceObjectVoteFile {
public: // Types
    typedef std::list<CGovernanceVote> vote_l_t;

    typedef vote_l_t::iterator vote_l_it;

    typedef vote_l_t::const_iterator vote_l_cit;

    typedef std::map<uint256,vote_l_it> vote_m_t;

    typedef vote_m_t::iterator vote_m_it;

    typedef vote_m_t::const_iterator vote_m_cit;

private:
    static const int MAX_MEMORY_VOTES = -1;

    int nMemoryVotes;

    vote_l_t listVotes;

    vote_m_t mapVoteIndex;

public:
    CGovernanceObjectVoteFile();

    CGovernanceObjectVoteFile(const CGovernanceObjectVoteFile& other);

    /**
     * Add a vote to the file
     */
    void AddVote(const CGovernanceVote& vote);

    /**
     * Return true if the vote with this hash is currently cached in memory
     */
    bool HasVote(const uint256& nHash) const;

    /**
     * Retrieve a vote cached in memory
     */
    bool SerializeVoteToStream(const uint256& nHash, CDataStream& ss) const;

    int GetVoteCount() {
        return nMemoryVotes;
    }

    std::vector<CGovernanceVote> GetVotes() const;

    void RemoveVotesFromMasternode(const COutPoint& outpointMasternode);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nMemoryVotes);
        READWRITE(listVotes);
        if(ser_action.ForRead()) {
            RebuildIndex();
        }
    }
private:
    void RebuildIndex();

};

// governance-object

class CGovernanceManager;

static const int MAX_GOVERNANCE_OBJECT_DATA_SIZE = 16 * 1024;

static const double GOVERNANCE_FILTER_FP_RATE = 0.001;

static const int GOVERNANCE_OBJECT_UNKNOWN = 0;
static const int GOVERNANCE_OBJECT_PROPOSAL = 1;
static const int GOVERNANCE_OBJECT_TRIGGER = 2;
static const int GOVERNANCE_OBJECT_WATCHDOG = 3;

static const CAmount GOVERNANCE_PROPOSAL_FEE_TX = (5.0*COIN);

static const int64_t GOVERNANCE_FEE_CONFIRMATIONS = 6;
static const int64_t GOVERNANCE_MIN_RELAY_FEE_CONFIRMATIONS = 1;
static const int64_t GOVERNANCE_UPDATE_MIN = 60*60;
static const int64_t GOVERNANCE_DELETION_DELAY = 10*60;
static const int64_t GOVERNANCE_ORPHAN_EXPIRATION_TIME = 10*60;

// FOR SEEN MAP ARRAYS - GOVERNANCE OBJECTS AND VOTES
static const int SEEN_OBJECT_IS_VALID = 0;
static const int SEEN_OBJECT_ERROR_INVALID = 1;
static const int SEEN_OBJECT_ERROR_IMMATURE = 2;
static const int SEEN_OBJECT_EXECUTED = 3; //used for triggers
static const int SEEN_OBJECT_UNKNOWN = 4; // the default

typedef std::pair<CGovernanceVote, int64_t> vote_time_pair_t;

inline bool operator<(const vote_time_pair_t& p1, const vote_time_pair_t& p2) {
    return (p1.first < p2.first);
}

struct vote_instance_t {
    vote_outcome_enum_t eOutcome;
    int64_t nTime;
    int64_t nCreationTime;

    vote_instance_t(vote_outcome_enum_t eOutcomeIn = VOTE_OUTCOME_NONE, int64_t nTimeIn = 0, int64_t nCreationTimeIn = 0)
                : eOutcome(eOutcomeIn), nTime(nTimeIn), nCreationTime(nCreationTimeIn) {
        //    
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nOutcome = int(eOutcome);
        READWRITE(nOutcome);
        READWRITE(nTime);
        READWRITE(nCreationTime);
        if (ser_action.ForRead()) {
            eOutcome = vote_outcome_enum_t(nOutcome);
        }
    }
};

typedef std::map<int,vote_instance_t> vote_instance_m_t;

typedef vote_instance_m_t::iterator vote_instance_m_it;

typedef vote_instance_m_t::const_iterator vote_instance_m_cit;

struct vote_rec_t {
    vote_instance_m_t mapInstances;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(mapInstances);
    }
};

/**
* Governance Object
*
*/

class CGovernanceObject {
    friend class CGovernanceManager;

public: // Types
    typedef std::map<COutPoint, vote_rec_t> vote_m_t;

    typedef vote_m_t::iterator vote_m_it;

    typedef vote_m_t::const_iterator vote_m_cit;

    typedef CacheMultiMap<COutPoint, vote_time_pair_t> vote_cmm_t;

private:
    /// critical section to protect the inner data structures
    mutable CCriticalSection cs;

    /// Object typecode
    int nObjectType;

    /// parent object, 0 is root
    uint256 nHashParent;

    /// object revision in the system
    int nRevision;

    /// time this object was created
    int64_t nTime;

    /// time this object was marked for deletion
    int64_t nDeletionTime;

    /// fee-tx
    uint256 nCollateralHash;

    /// Data field - can be used for anything
    std::vector<unsigned char> vchData;

    /// Masternode info for signed objects
    COutPoint masternodeOutpoint;
    std::vector<unsigned char> vchSig;

    /// is valid by blockchain
    bool fCachedLocalValidity;
    std::string strLocalValidityError;

    // VARIOUS FLAGS FOR OBJECT / SET VIA MASTERNODE VOTING

    /// true == minimum network support has been reached for this object to be funded (doesn't mean it will for sure though)
    bool fCachedFunding;

    /// true == minimum network has been reached flagging this object as a valid and understood governance object (e.g, the serialized data is correct format, etc)
    bool fCachedValid;

    /// true == minimum network support has been reached saying this object should be deleted from the system entirely
    bool fCachedDelete;

    /** true == minimum network support has been reached flagging this object as endorsed by an elected representative body
     * (e.g. business review board / technecial review board /etc)
     */
    bool fCachedEndorsed;

    /// object was updated and cached values should be updated soon
    bool fDirtyCache;

    /// Object is no longer of interest
    bool fExpired;

    /// Failed to parse object data
    bool fUnparsable;

    vote_m_t mapCurrentMNVotes;

    /// Limited map of votes orphaned by MN
    vote_cmm_t cmmapOrphanVotes;

    CGovernanceObjectVoteFile fileVotes;

public:
    CGovernanceObject();

    CGovernanceObject(const uint256& nHashParentIn, int nRevisionIn, int64_t nTime, const uint256& nCollateralHashIn, const std::string& strDataHexIn);

    CGovernanceObject(const CGovernanceObject& other);

    void swap(CGovernanceObject& first, CGovernanceObject& second); // nothrow

    // Public Getter methods

    int64_t GetCreationTime() const {
        return nTime;
    }

    int64_t GetDeletionTime() const {
        return nDeletionTime;
    }

    int GetObjectType() const {
        return nObjectType;
    }

    const uint256& GetCollateralHash() const {
        return nCollateralHash;
    }

    const COutPoint& GetMasternodeOutpoint() const {
        return masternodeOutpoint;
    }

    bool IsSetCachedFunding() const {
        return fCachedFunding;
    }

    bool IsSetCachedValid() const {
        return fCachedValid;
    }

    bool IsSetCachedDelete() const {
        return fCachedDelete;
    }

    bool IsSetCachedEndorsed() const {
        return fCachedEndorsed;
    }

    bool IsSetDirtyCache() const {
        return fDirtyCache;
    }

    bool IsSetExpired() const {
        return fExpired;
    }

    void InvalidateVoteCache() {
        fDirtyCache = true;
    }

    const CGovernanceObjectVoteFile& GetVoteFile() const {
        return fileVotes;
    }

    // Signature related functions

    void SetMasternodeOutpoint(const COutPoint& outpoint);
    bool Sign(const CKey& keyMasternode, const CPubKey& pubKeyMasternode);
    bool CheckSignature(const CPubKey& pubKeyMasternode) const;

    std::string GetSignatureMessage() const;
    uint256 GetSignatureHash() const;

    // CORE OBJECT FUNCTIONS

    bool IsValidLocally(std::string& strError, bool fCheckCollateral) const;

    bool IsValidLocally(std::string& strError, bool& fMissingMasternode, bool& fMissingConfirmations, bool fCheckCollateral) const;

    /// Check the collateral transaction for the budget proposal/finalized budget
    bool IsCollateralValid(std::string& strError, bool& fMissingConfirmations) const;

    void UpdateLocalValidity();

    void UpdateSentinelVariables();

    CAmount GetMinCollateralFee() const;

    UniValue GetJSONObject();

    void Relay(CConnman& connman);

    uint256 GetHash() const;

    // GET VOTE COUNT FOR SIGNAL

    int CountMatchingVotes(vote_signal_enum_t eVoteSignalIn, vote_outcome_enum_t eVoteOutcomeIn) const;

    int GetAbsoluteYesCount(vote_signal_enum_t eVoteSignalIn) const;
    int GetAbsoluteNoCount(vote_signal_enum_t eVoteSignalIn) const;
    int GetYesCount(vote_signal_enum_t eVoteSignalIn) const;
    int GetNoCount(vote_signal_enum_t eVoteSignalIn) const;
    int GetAbstainCount(vote_signal_enum_t eVoteSignalIn) const;

    bool GetCurrentMNVotes(const COutPoint& mnCollateralOutpoint, vote_rec_t& voteRecord) const;

    // FUNCTIONS FOR DEALING WITH DATA STRING

    std::string GetDataAsHexString() const;
    std::string GetDataAsPlainString() const;

    // SERIALIZER

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        // SERIALIZE DATA FOR SAVING/LOADING OR NETWORK FUNCTIONS
        int nVersion = s.GetVersion();
        READWRITE(nHashParent);
        READWRITE(nRevision);
        READWRITE(nTime);
        READWRITE(nCollateralHash);
        READWRITE(vchData);
        READWRITE(nObjectType);
        READWRITE(masternodeOutpoint);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
        if (s.GetType() & SER_DISK) {
            // Only include these for the disk file format
            LogPrint(BCLog::MN, "CGovernanceObject::SerializationOp Reading/writing votes from/to disk\n");
            READWRITE(nDeletionTime);
            READWRITE(fExpired);
            READWRITE(mapCurrentMNVotes);
            READWRITE(fileVotes);
            LogPrint(BCLog::MN, "CGovernanceObject::SerializationOp hash = %s, vote count = %d\n", GetHash().ToString(), fileVotes.GetVoteCount());
        }
        // AFTER DESERIALIZATION OCCURS, CACHED VARIABLES MUST BE CALCULATED MANUALLY
    }

    CGovernanceObject& operator=(CGovernanceObject from) {
        swap(*this, from);
        return *this;
    }

private:
    // FUNCTIONS FOR DEALING WITH DATA STRING
    void LoadData();
    void GetData(UniValue& objResult);

    bool ProcessVote (CNode* pfrom, const CGovernanceVote& vote, CGovernanceException& exception, CConnman& connman);

    /// Called when MN's which have voted on this object have been removed
    void ClearMasternodeVotes();

    void CheckOrphanVotes(CConnman& connman);
}; 

// governance

struct ExpirationInfo {
    ExpirationInfo(int64_t _nExpirationTime, int _idFrom) : nExpirationTime(_nExpirationTime), idFrom(_idFrom) {}

    int64_t nExpirationTime;
    NodeId idFrom;
};

typedef std::pair<CGovernanceObject, ExpirationInfo> object_info_pair_t;

static const int RATE_BUFFER_SIZE = 5;

class CRateCheckBuffer {
private:
    std::vector<int64_t> vecTimestamps;

    int nDataStart;

    int nDataEnd;

    bool fBufferEmpty;

public:
    CRateCheckBuffer() : vecTimestamps(RATE_BUFFER_SIZE), nDataStart(0), nDataEnd(0), fBufferEmpty(true)
        {}

    void AddTimestamp(int64_t nTimestamp) {
        if ((nDataEnd == nDataStart) && !fBufferEmpty) {
            // Buffer full, discard 1st element
            nDataStart = (nDataStart + 1) % RATE_BUFFER_SIZE;
        }
        vecTimestamps[nDataEnd] = nTimestamp;
        nDataEnd = (nDataEnd + 1) % RATE_BUFFER_SIZE;
        fBufferEmpty = false;
    }

    int64_t GetMinTimestamp() {
        int nIndex = nDataStart;
        int64_t nMin = std::numeric_limits<int64_t>::max();
        if (fBufferEmpty) {
            return nMin;
        }
        do {
            if (vecTimestamps[nIndex] < nMin) {
                nMin = vecTimestamps[nIndex];
            }
            nIndex = (nIndex + 1) % RATE_BUFFER_SIZE;
        } while(nIndex != nDataEnd);
        return nMin;
    }

    int64_t GetMaxTimestamp() {
        int nIndex = nDataStart;
        int64_t nMax = 0;
        if (fBufferEmpty) {
            return nMax;
        }
        do {
            if(vecTimestamps[nIndex] > nMax) {
                nMax = vecTimestamps[nIndex];
            }
            nIndex = (nIndex + 1) % RATE_BUFFER_SIZE;
        } while(nIndex != nDataEnd);
        return nMax;
    }

    int GetCount() {
        int nCount = 0;
        if (fBufferEmpty) {
            return 0;
        }
        if (nDataEnd > nDataStart) {
            nCount = nDataEnd - nDataStart;
        } else {
            nCount = RATE_BUFFER_SIZE - nDataStart + nDataEnd;
        }
        return nCount;
    }

    double GetRate() {
        int nCount = GetCount();
        if (nCount < RATE_BUFFER_SIZE) {
            return 0.0;
        }
        int64_t nMin = GetMinTimestamp();
        int64_t nMax = GetMaxTimestamp();
        if (nMin == nMax) {
            // multiple objects with the same timestamp => infinite rate
            return 1.0e10;
        }
        return double(nCount) / double(nMax - nMin);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vecTimestamps);
        READWRITE(nDataStart);
        READWRITE(nDataEnd);
        READWRITE(fBufferEmpty);
    }
};

//
// Governance Manager : Contains all proposals for the budget
//
class CGovernanceManager {
    friend class CGovernanceObject;

public: // Types
    struct last_object_rec {
        last_object_rec(bool fStatusOKIn = true) : triggerBuffer(), fStatusOK(fStatusOKIn)
            {}

        ADD_SERIALIZE_METHODS;

        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            READWRITE(triggerBuffer);
            READWRITE(fStatusOK);
        }

        CRateCheckBuffer triggerBuffer;
        bool fStatusOK;
    };

    typedef std::map<uint256, CGovernanceObject> object_m_t;

    typedef object_m_t::iterator object_m_it;

    typedef object_m_t::const_iterator object_m_cit;

    typedef CacheMap<uint256, CGovernanceObject*> object_ref_cm_t;

    typedef std::map<uint256, CGovernanceVote> vote_m_t;

    typedef vote_m_t::iterator vote_m_it;

    typedef vote_m_t::const_iterator vote_m_cit;

    typedef CacheMap<uint256, CGovernanceVote> vote_cm_t;

    typedef CacheMultiMap<uint256, vote_time_pair_t> vote_cmm_t;

    typedef object_m_t::size_type size_type;

    typedef std::map<COutPoint, last_object_rec > txout_m_t;

    typedef txout_m_t::iterator txout_m_it;

    typedef txout_m_t::const_iterator txout_m_cit;

    typedef std::map<COutPoint, int> txout_int_m_t;

    typedef std::set<uint256> hash_s_t;

    typedef hash_s_t::iterator hash_s_it;

    typedef hash_s_t::const_iterator hash_s_cit;

    typedef std::map<uint256, object_info_pair_t> object_info_m_t;

    typedef object_info_m_t::iterator object_info_m_it;

    typedef object_info_m_t::const_iterator object_info_m_cit;

    typedef std::map<uint256, int64_t> hash_time_m_t;

    typedef hash_time_m_t::iterator hash_time_m_it;

    typedef hash_time_m_t::const_iterator hash_time_m_cit;

private:
    static const int MAX_CACHE_SIZE = 1000000;

    static const std::string SERIALIZATION_VERSION_STRING;

    static const int MAX_TIME_FUTURE_DEVIATION;
    static const int RELIABLE_PROPAGATION_TIME;

    int64_t nTimeLastDiff;

    // keep track of current block height
    int nCachedBlockHeight;

    // keep track of the scanning errors
    object_m_t mapObjects;

    // mapErasedGovernanceObjects contains key-value pairs, where
    //   key   - governance object's hash
    //   value - expiration time for deleted objects
    hash_time_m_t mapErasedGovernanceObjects;

    object_info_m_t mapMasternodeOrphanObjects;
    txout_int_m_t mapMasternodeOrphanCounter;

    object_m_t mapPostponedObjects;
    hash_s_t setAdditionalRelayObjects;

    object_ref_cm_t cmapVoteToObject;

    vote_cm_t cmapInvalidVotes;

    vote_cmm_t cmmapOrphanVotes;

    txout_m_t mapLastMasternodeObject;

    hash_s_t setRequestedObjects;

    hash_s_t setRequestedVotes;

    bool fRateChecksEnabled;

    class ScopedLockBool {
        bool& ref;
        bool fPrevValue;
    public:
        ScopedLockBool(CCriticalSection& _cs, bool& _ref, bool _value) : ref(_ref) {
            AssertLockHeld(_cs);
            fPrevValue = ref;
            ref = _value;
        }
        ~ScopedLockBool() {
            ref = fPrevValue;
        }
    };

public:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    CGovernanceManager();

    virtual ~CGovernanceManager() {}

    /**
     * This is called by AlreadyHave in net_processing.cpp as part of the inventory
     * retrieval process.  Returns true if we want to retrieve the object, otherwise
     * false. (Note logic is inverted in AlreadyHave).
     */
    bool ConfirmInventoryRequest(const CInv& inv);

    void SyncSingleObjAndItsVotes(CNode* pnode, const uint256& nProp, const CBloomFilter& filter, CConnman& connman);
    void SyncAll(CNode* pnode, CConnman& connman) const;

    void ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman);

    void DoMaintenance(CConnman& connman);

    CGovernanceObject* FindGovernanceObject(const uint256& nHash);

    // These commands are only used in RPC
    std::vector<CGovernanceVote> GetMatchingVotes(const uint256& nParentHash) const;
    std::vector<CGovernanceVote> GetCurrentVotes(const uint256& nParentHash, const COutPoint& mnCollateralOutpointFilter) const;
    std::vector<const CGovernanceObject*> GetAllNewerThan(int64_t nMoreThanTime) const;

    void AddGovernanceObject(CGovernanceObject& govobj, CConnman& connman, CNode* pfrom = nullptr);

    void UpdateCachesAndClean();

    void CheckAndRemove() {UpdateCachesAndClean();}

    void Clear() {
        LOCK(cs);

        LogPrint(BCLog::MN, "Governance object manager was cleared\n");
        mapObjects.clear();
        mapErasedGovernanceObjects.clear();
        cmapVoteToObject.Clear();
        cmapInvalidVotes.Clear();
        cmmapOrphanVotes.Clear();
        mapLastMasternodeObject.clear();
    }

    std::string ToString() const;
    UniValue ToJson() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        LOCK(cs);
        std::string strVersion;
        if (ser_action.ForRead()) {
            READWRITE(strVersion);
        } else {
            strVersion = SERIALIZATION_VERSION_STRING;
            READWRITE(strVersion);
        }

        READWRITE(mapErasedGovernanceObjects);
        READWRITE(cmapInvalidVotes);
        READWRITE(cmmapOrphanVotes);
        READWRITE(mapObjects);
        READWRITE(mapLastMasternodeObject);
        if (ser_action.ForRead() && (strVersion != SERIALIZATION_VERSION_STRING)) {
            Clear();
            return;
        }
    }

    void UpdatedBlockTip(const CBlockIndex *pindex, CConnman& connman);
    int64_t GetLastDiffTime() const { return nTimeLastDiff; }
    void UpdateLastDiffTime(int64_t nTimeIn) { nTimeLastDiff = nTimeIn; }

    int GetCachedBlockHeight() const { return nCachedBlockHeight; }

    // Accessors for thread-safe access to maps
    bool HaveObjectForHash(const uint256& nHash) const;

    bool HaveVoteForHash(const uint256& nHash) const;

    int GetVoteCount() const;

    bool SerializeObjectForHash(const uint256& nHash, CDataStream& ss) const;

    bool SerializeVoteForHash(const uint256& nHash, CDataStream& ss) const;

    void AddPostponedObject(const CGovernanceObject& govobj) {
        LOCK(cs);
        mapPostponedObjects.insert(std::make_pair(govobj.GetHash(), govobj));
    }

    void AddSeenGovernanceObject(const uint256& nHash, int status);

    void AddSeenVote(const uint256& nHash, int status);

    void MasternodeRateUpdate(const CGovernanceObject& govobj);

    bool MasternodeRateCheck(const CGovernanceObject& govobj, bool fUpdateFailStatus = false);

    bool MasternodeRateCheck(const CGovernanceObject& govobj, bool fUpdateFailStatus, bool fForce, bool& fRateCheckBypassed);

    bool ProcessVoteAndRelay(const CGovernanceVote& vote, CGovernanceException& exception, CConnman& connman) {
        bool fOK = ProcessVote(nullptr, vote, exception, connman);
        if (fOK) {
            vote.Relay(connman);
        }
        return fOK;
    }

    void CheckMasternodeOrphanVotes(CConnman& connman);

    void CheckMasternodeOrphanObjects(CConnman& connman);

    void CheckPostponedObjects(CConnman& connman);

    bool AreRateChecksEnabled() const {
        LOCK(cs);
        return fRateChecksEnabled;
    }

    void InitOnLoad();

    int RequestGovernanceObjectVotes(CNode* pnode, CConnman& connman);
    int RequestGovernanceObjectVotes(const std::vector<CNode*>& vNodesCopy, CConnman& connman);

private:
    void RequestGovernanceObject(CNode* pfrom, const uint256& nHash, CConnman& connman, bool fUseFilter = false);

    void AddInvalidVote(const CGovernanceVote& vote) {        
        cmapInvalidVotes.Insert(vote.GetHash(), vote);
    }

    void AddOrphanVote(const CGovernanceVote& vote) {
        cmmapOrphanVotes.Insert(vote.GetHash(), vote_time_pair_t(vote, GetAdjustedTime() + GOVERNANCE_ORPHAN_EXPIRATION_TIME));
    }

    bool ProcessVote(CNode* pfrom, const CGovernanceVote& vote, CGovernanceException& exception, CConnman& connman);

    /// Called to indicate a requested object has been received
    bool AcceptObjectMessage(const uint256& nHash);

    /// Called to indicate a requested vote has been received
    bool AcceptVoteMessage(const uint256& nHash);

    static bool AcceptMessage(const uint256& nHash, hash_s_t& setHash);

    void CheckOrphanVotes(CGovernanceObject& govobj, CGovernanceException& exception, CConnman& connman);

    void RebuildIndexes();

    void RequestOrphanObjects(CConnman& connman);

    void CleanOrphanObjects();
    void Dump (const std::string& border, std::function<void(std::string)> dumpfunc);    
};

extern CGovernanceManager governance;

// governance-validators

class CProposalValidator {
private:
    UniValue               objJSON;
    bool                   fJSONValid;
    std::string            strErrorMessages;

public:
    CProposalValidator(const std::string& strDataHexIn = std::string());

    bool Validate(bool fCheckExpiration = true);

    const std::string& GetErrorMessages() {
        return strErrorMessages;
    }

private:
    void ParseStrHexData(const std::string& strHexData);
    void ParseJSONData(const std::string& strJSONData);

    bool GetDataValue(const std::string& strKey, std::string& strValueRet);
    bool GetDataValue(const std::string& strKey, int64_t& nValueRet);
    bool GetDataValue(const std::string& strKey, double& dValueRet);

    bool ValidateName();
    bool ValidateStartEndEpoch(bool fCheckExpiration = true);
    bool ValidatePaymentAmount();
    bool ValidatePaymentAddress();
    bool ValidateURL();

    bool CheckURL(const std::string& strURLIn);
};

#endif