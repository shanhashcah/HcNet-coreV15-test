#pragma once

// Copyright 2018 Hcnet Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/ShortHash.h"
#include "ledger/GeneralizedLedgerEntry.h"
#include "xdr/Hcnet-ledger.h"
#include <functional>

// implements a default hasher for "LedgerKey"
namespace std
{
template <> class hash<hcnet::Asset>
{
  public:
    size_t
    operator()(hcnet::Asset const& asset) const
    {
        size_t res = asset.type();
        switch (asset.type())
        {
        case hcnet::ASSET_TYPE_NATIVE:
            break;
        case hcnet::ASSET_TYPE_CREDIT_ALPHANUM4:
        {
            auto& a4 = asset.alphaNum4();
            res ^= hcnet::shortHash::computeHash(
                hcnet::ByteSlice(a4.issuer.ed25519().data(), 8));
            res ^= a4.assetCode[0];
            break;
        }
        case hcnet::ASSET_TYPE_CREDIT_ALPHANUM12:
        {
            auto& a12 = asset.alphaNum12();
            res ^= hcnet::shortHash::computeHash(
                hcnet::ByteSlice(a12.issuer.ed25519().data(), 8));
            res ^= a12.assetCode[0];
            break;
        }
        }
        return res;
    }
};

template <> class hash<hcnet::LedgerKey>
{
  public:
    size_t
    operator()(hcnet::LedgerKey const& lk) const
    {
        size_t res;
        switch (lk.type())
        {
        case hcnet::ACCOUNT:
            res = hcnet::shortHash::computeHash(
                hcnet::ByteSlice(lk.account().accountID.ed25519().data(), 8));
            break;
        case hcnet::TRUSTLINE:
        {
            auto& tl = lk.trustLine();
            res = hcnet::shortHash::computeHash(
                hcnet::ByteSlice(tl.accountID.ed25519().data(), 8));
            res ^= hash<hcnet::Asset>()(tl.asset);
            break;
        }
        case hcnet::DATA:
            res = hcnet::shortHash::computeHash(
                hcnet::ByteSlice(lk.data().accountID.ed25519().data(), 8));
            res ^= hcnet::shortHash::computeHash(hcnet::ByteSlice(
                lk.data().dataName.data(), lk.data().dataName.size()));
            break;
        case hcnet::OFFER:
            res = hcnet::shortHash::computeHash(hcnet::ByteSlice(
                &lk.offer().offerID, sizeof(lk.offer().offerID)));
            break;
        case hcnet::CLAIMABLE_BALANCE:
            res = hcnet::shortHash::computeHash(hcnet::ByteSlice(
                lk.claimableBalance().balanceID.v0().data(), 8));
            break;
        default:
            abort();
        }
        return res;
    }
};

template <> class hash<hcnet::GeneralizedLedgerKey>
{
  public:
    size_t
    operator()(hcnet::GeneralizedLedgerKey const& glk) const
    {
        switch (glk.type())
        {
        case hcnet::GeneralizedLedgerEntryType::LEDGER_ENTRY:
            return hash<hcnet::LedgerKey>()(glk.ledgerKey());
        case hcnet::GeneralizedLedgerEntryType::SPONSORSHIP:
            return hcnet::shortHash::computeHash(hcnet::ByteSlice(
                glk.sponsorshipKey().sponsoredID.ed25519().data(), 8));
        case hcnet::GeneralizedLedgerEntryType::SPONSORSHIP_COUNTER:
            return hcnet::shortHash::computeHash(hcnet::ByteSlice(
                glk.sponsorshipCounterKey().sponsoringID.ed25519().data(), 8));
        default:
            abort();
        }
    }
};
}
