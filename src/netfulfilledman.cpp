// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <netfulfilledman.h>
#include <util.h>

CNetFulfilledRequestManager netfulfilledman;

void CNetFulfilledRequestManager::AddFulfilledRequest(const CService& addr, const std::string& strRequest) {
    LOCK(cs_mapFulfilledRequests);
    mapFulfilledRequests[addr.ToString() + strRequest] = GetTime() + 15 * 60;
}

bool CNetFulfilledRequestManager::HasFulfilledRequest(const CService& addr, const std::string& strRequest) {
    LOCK(cs_mapFulfilledRequests);
    auto it = mapFulfilledRequests.find (addr.ToString() + strRequest);
    return (it != mapFulfilledRequests.end()) && (it->second > GetTime());
}

void CNetFulfilledRequestManager::RemoveFulfilledRequest(const CService& addr, const std::string& strRequest) {
    LOCK(cs_mapFulfilledRequests);
    mapFulfilledRequests.erase (addr.ToString() + strRequest);
}

void CNetFulfilledRequestManager::CheckAndRemove() {
    LOCK(cs_mapFulfilledRequests);

    int64_t now = GetTime();
    auto it = mapFulfilledRequests.begin();
    while (it != mapFulfilledRequests.end()) {
        if (now > it->second) {
            mapFulfilledRequests.erase(it++);
        } else {
            ++it;
        }
    }
}

void CNetFulfilledRequestManager::Clear() {
    LOCK(cs_mapFulfilledRequests);
    mapFulfilledRequests.clear();
}

std::string CNetFulfilledRequestManager::ToString() const {
    std::ostringstream info;
    info << "Nodes with fulfilled requests: " << (int)mapFulfilledRequests.size();
    return info.str();
}
