#ifdef reference
static const int64_t COIN_YEAR_REWARD = 5 * CENT; // 5% per year
int nCoinbaseMaturity = 100;
static const int STAKE_TIMESTAMP_MASK = 15;

// MODIFIER_INTERVAL_RATIO:
// ratio of group interval length between the last group and the first group
static const int MODIFIER_INTERVAL_RATIO = 3;

CBigNum bnProofOfStakeLimit(~uint256(0) >> 20);
CBigNum bnProofOfStakeLimitV2(~uint256(0) >> 48);

unsigned int nTargetSpacing = 1 * 60; // BitcoinDark - 1 minute
static const int64_t nTargetTimespan = 60 * 60;  // BitcoinDark - every 1 hour
unsigned int nStakeMinAge = 8 * 60 * 60; // BitcoinDark - 8 hours
unsigned int nStakeMaxAge = -1;
unsigned int nModifierInterval = 10 * 60; // BitcoinDark - time to elapse before new modifier is

unsigned int nStakeSplitAge = 1 * 24 * 60 * 60;
int64_t nStakeCombineThreshold = 1000 * COIN;

enum
{
    BLOCK_PROOF_OF_STAKE = (1 << 0), // is proof-of-stake block
    BLOCK_STAKE_ENTROPY  = (1 << 1), // entropy bit for stake modifier
    BLOCK_STAKE_MODIFIER = (1 << 2), // regenerated stake modifier
};

uint64_t nStakeModifier; // hash modifier for proof-of-stake
unsigned int nStakeModifierChecksum; // checksum of index; in-memeory only


uint256 CBlockIndex::GetBlockTrust() const
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    
    if (bnTarget <= 0)
        return 0;
    
    return ((CBigNum(1)<<256) / (bnTarget+1)).getuint256();
}

unsigned int GetStakeEntropyBit() const
{
    return ((nFlags & BLOCK_STAKE_ENTROPY) >> 1);
}

bool SetStakeEntropyBit(unsigned int nEntropyBit)
{
    if (nEntropyBit > 1)
        return false;
    nFlags |= (nEntropyBit? BLOCK_STAKE_ENTROPY : 0);
    return true;
}

bool GeneratedStakeModifier() const
{
    return (nFlags & BLOCK_STAKE_MODIFIER);
}

void SetStakeModifier(uint64_t nModifier, bool fGeneratedStakeModifier)
{
    nStakeModifier = nModifier;
    if (fGeneratedStakeModifier)
        nFlags |= BLOCK_STAKE_MODIFIER;
}

// miner's coin stake reward based on coin age spent (coin-days)
int64_t GetProofOfStakeReward(int64_t nCoinAge, int64_t nFees)
{
    int64_t nSubsidy = nCoinAge * COIN_YEAR_REWARD * 33 / (365 * 33 + 8);
    return(nSubsidy + nFees);
}

//
// maximum nBits value could possible be required nTime after
//
unsigned int ComputeMaxBits(CBigNum bnTargetLimit, unsigned int nBase, int64_t nTime)
{
    CBigNum bnResult;
    bnResult.SetCompact(nBase);
    bnResult *= 2;
    while (nTime > 0 && bnResult < bnTargetLimit)
    {
        // Maximum 200% adjustment per day...
        bnResult *= 2;
        nTime -= 24 * 60 * 60;
    }
    if (bnResult > bnTargetLimit)
        bnResult = bnTargetLimit;
    return bnResult.GetCompact();
}

//
// minimum amount of stake that could possibly be required nTime after
// minimum proof-of-stake required was nBase
//
unsigned int ComputeMinStake(unsigned int nBase, int64_t nTime, unsigned int nBlockTime)
{
    return ComputeMaxBits(bnProofOfStakeLimit, nBase, nTime);
}

static CBigNum GetProofOfStakeLimit(int nHeight)
{
    if(IsPoSV2(nHeight))
		return bnProofOfStakeLimitV2;
	else
        return bnProofOfStakeLimit;
}

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake)
{
	CBigNum bnTargetLimit = fProofOfStake ? GetProofOfStakeLimit(pindexLast->nHeight) : bnProofOfWorkLimit;
    
    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block
    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // first block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // second block
    
    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();
    if (nActualSpacing < 0)
        nActualSpacing = nTargetSpacing;
    
    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    CBigNum bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    int64_t nInterval = nTargetTimespan / nTargetSpacing;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);
    
    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;
    
    return bnNew.GetCompact();
}

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
bool CTransaction::GetCoinAge(CTxDB& txdb, uint64_t& nCoinAge) const
{
    CBigNum bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;
    if (IsCoinBase())
        return true;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // First try finding the previous transaction in database
        CTransaction txPrev;
        CTxIndex txindex;
        if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
            continue;  // previous transaction not in main chain
        if (nTime < txPrev.nTime)
            return false;  // Transaction timestamp violation
        // Read block header
        CBlock block;
        if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
            return false; // unable to read block of previous transaction
        if (block.GetBlockTime() + nStakeMinAge > nTime)
            continue; // only count coins meeting min age requirement
        
        int64_t nValueIn = txPrev.vout[txin.prevout.n].nValue;
        bnCentSecond += CBigNum(nValueIn) * (nTime-txPrev.nTime) / CENT;
        
        if (fDebug && GetBoolArg("-printcoinage"))
            printf("coin age nValueIn=%"PRId64" nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString().c_str());
    }
    CBigNum bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
        nCoinAge = bnCoinDay.getuint64();
        return true;
}

// ppcoin: total coin age spent in block, in the unit of coin-days.
bool CBlock::GetCoinAge(uint64_t& nCoinAge) const
{
    nCoinAge = 0;
    
    CTxDB txdb("r");
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        uint64_t nTxCoinAge;
        if (tx.GetCoinAge(txdb, nTxCoinAge))
            nCoinAge += nTxCoinAge;
        else
            return false;
    }
    if (nCoinAge == 0) // block coin age minimum 1 coin-day
        nCoinAge = 1;
        if (fDebug && GetBoolArg("-printcoinage"))
            printf("block coin age total nCoinDays=%"PRId64"\n", nCoinAge);
            return true;
}

// Get time weight
int64_t GetWeight(int64_t nIntervalBeginning, int64_t nIntervalEnd)
{
    // Kernel hash weight starts from 0 at the min age
    // this change increases active coins participating the hash and helps
    // to secure the network when proof-of-stake difficulty is low
    
    return min(nIntervalEnd - nIntervalBeginning - nStakeMinAge, (int64_t)nStakeMaxAge);
}

// Get the last stake modifier and its generation time from a given block
static bool GetLastStakeModifier(const CBlockIndex* pindex, uint64_t& nStakeModifier, int64_t& nModifierTime)
{
    if (!pindex)
        return error("GetLastStakeModifier: null pindex");
    while (pindex && pindex->pprev && !pindex->GeneratedStakeModifier())
        pindex = pindex->pprev;
    if (!pindex->GeneratedStakeModifier())
        return error("GetLastStakeModifier: no generation at genesis block");
    nStakeModifier = pindex->nStakeModifier;
    nModifierTime = pindex->GetBlockTime();
    return true;
}

// Get selection interval section (in seconds)
static int64_t GetStakeModifierSelectionIntervalSection(int nSection)
{
    assert (nSection >= 0 && nSection < 64);
    return (nModifierInterval * 63 / (63 + ((63 - nSection) * (MODIFIER_INTERVAL_RATIO - 1))));
}

// Get stake modifier selection interval (in seconds)
static int64_t GetStakeModifierSelectionInterval()
{
    int64_t nSelectionInterval = 0;
    for (int nSection=0; nSection<64; nSection++)
        nSelectionInterval += GetStakeModifierSelectionIntervalSection(nSection);
    return nSelectionInterval;
}

// select a block from the candidate blocks in vSortedByTimestamp, excluding
// already selected blocks in vSelectedBlocks, and with timestamp up to
// nSelectionIntervalStop.
static bool SelectBlockFromCandidates(vector<pair<int64_t, uint256> >& vSortedByTimestamp, map<uint256, const CBlockIndex*>& mapSelectedBlocks,
                                      int64_t nSelectionIntervalStop, uint64_t nStakeModifierPrev, const CBlockIndex** pindexSelected)
{
    bool fSelected = false;
    uint256 hashBest = 0;
    *pindexSelected = (const CBlockIndex*) 0;
    BOOST_FOREACH(const PAIRTYPE(int64_t, uint256)& item, vSortedByTimestamp)
    {
        if (!mapBlockIndex.count(item.second))
            return error("SelectBlockFromCandidates: failed to find block index for candidate block %s", item.second.ToString().c_str());
        const CBlockIndex* pindex = mapBlockIndex[item.second];
        if (fSelected && pindex->GetBlockTime() > nSelectionIntervalStop)
            break;
        if (mapSelectedBlocks.count(pindex->GetBlockHash()) > 0)
            continue;
        // compute the selection hash by hashing its proof-hash and the
        // previous proof-of-stake modifier
        CDataStream ss(SER_GETHASH, 0);
        ss << pindex->hashProof << nStakeModifierPrev;
        uint256 hashSelection = Hash(ss.begin(), ss.end());
        // the selection hash is divided by 2**32 so that proof-of-stake block
        // is always favored over proof-of-work block. this is to preserve
        // the energy efficiency property
        if (pindex->IsProofOfStake())
            hashSelection >>= 32;
        if (fSelected && hashSelection < hashBest)
        {
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*) pindex;
        }
        else if (!fSelected)
        {
            fSelected = true;
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*) pindex;
        }
    }
    if (fDebug && GetBoolArg("-printstakemodifier"))
        printf("SelectBlockFromCandidates: selection hash=%s\n", hashBest.ToString().c_str());
    return fSelected;
}

// Stake Modifier (hash modifier of proof-of-stake):
// The purpose of stake modifier is to prevent a txout (coin) owner from
// computing future proof-of-stake generated by this txout at the time
// of transaction confirmation. To meet kernel protocol, the txout
// must hash with a future stake modifier to generate the proof.
// Stake modifier consists of bits each of which is contributed from a
// selected block of a given block group in the past.
// The selection of a block is based on a hash of the block's proof-hash and
// the previous stake modifier.
// Stake modifier is recomputed at a fixed time interval instead of every
// block. This is to make it difficult for an attacker to gain control of
// additional bits in the stake modifier, even after generating a chain of
// blocks.
bool ComputeNextStakeModifier(const CBlockIndex* pindexPrev, uint64_t& nStakeModifier, bool& fGeneratedStakeModifier)
{
    nStakeModifier = 0;
    fGeneratedStakeModifier = false;
    if (!pindexPrev)
    {
        fGeneratedStakeModifier = true;
        return true;  // genesis block's modifier is 0
    }
    // First find current stake modifier and its generation block time
    // if it's not old enough, return the same stake modifier
    int64_t nModifierTime = 0;
    if (!GetLastStakeModifier(pindexPrev, nStakeModifier, nModifierTime))
        return error("ComputeNextStakeModifier: unable to get last modifier");
    if (fDebug)
    {
        printf("ComputeNextStakeModifier: prev modifier=0x%016"PRIx64" time=%s\n", nStakeModifier, DateTimeStrFormat(nModifierTime).c_str());
    }
    if (nModifierTime / nModifierInterval >= pindexPrev->GetBlockTime() / nModifierInterval)
        return true;
    
    // Sort candidate blocks by timestamp
    vector<pair<int64_t, uint256> > vSortedByTimestamp;
    vSortedByTimestamp.reserve(64 * nModifierInterval / nTargetSpacing);
    int64_t nSelectionInterval = GetStakeModifierSelectionInterval();
    int64_t nSelectionIntervalStart = (pindexPrev->GetBlockTime() / nModifierInterval) * nModifierInterval - nSelectionInterval;
    const CBlockIndex* pindex = pindexPrev;
    while (pindex && pindex->GetBlockTime() >= nSelectionIntervalStart)
    {
        vSortedByTimestamp.push_back(make_pair(pindex->GetBlockTime(), pindex->GetBlockHash()));
        pindex = pindex->pprev;
    }
    int nHeightFirstCandidate = pindex ? (pindex->nHeight + 1) : 0;
    reverse(vSortedByTimestamp.begin(), vSortedByTimestamp.end());
    sort(vSortedByTimestamp.begin(), vSortedByTimestamp.end());
    
    // Select 64 blocks from candidate blocks to generate stake modifier
    uint64_t nStakeModifierNew = 0;
    int64_t nSelectionIntervalStop = nSelectionIntervalStart;
    map<uint256, const CBlockIndex*> mapSelectedBlocks;
    for (int nRound=0; nRound<min(64, (int)vSortedByTimestamp.size()); nRound++)
    {
        // add an interval section to the current selection round
        nSelectionIntervalStop += GetStakeModifierSelectionIntervalSection(nRound);
        // select a block from the candidates of current round
        if (!SelectBlockFromCandidates(vSortedByTimestamp, mapSelectedBlocks, nSelectionIntervalStop, nStakeModifier, &pindex))
            return error("ComputeNextStakeModifier: unable to select block at round %d", nRound);
        // write the entropy bit of the selected block
        nStakeModifierNew |= (((uint64_t)pindex->GetStakeEntropyBit()) << nRound);
        // add the selected block from candidates to selected list
        mapSelectedBlocks.insert(make_pair(pindex->GetBlockHash(), pindex));
        if (fDebug && GetBoolArg("-printstakemodifier"))
            printf("ComputeNextStakeModifier: selected round %d stop=%s height=%d bit=%d\n", nRound, DateTimeStrFormat(nSelectionIntervalStop).c_str(), pindex->nHeight, pindex->GetStakeEntropyBit());
    }
    
    // Print selection map for visualization of the selected blocks
    if (fDebug && GetBoolArg("-printstakemodifier"))
    {
        string strSelectionMap = "";
        // '-' indicates proof-of-work blocks not selected
        strSelectionMap.insert(0, pindexPrev->nHeight - nHeightFirstCandidate + 1, '-');
        pindex = pindexPrev;
        while (pindex && pindex->nHeight >= nHeightFirstCandidate)
        {
            // '=' indicates proof-of-stake blocks not selected
            if (pindex->IsProofOfStake())
                strSelectionMap.replace(pindex->nHeight - nHeightFirstCandidate, 1, "=");
            pindex = pindex->pprev;
        }
        BOOST_FOREACH(const PAIRTYPE(uint256, const CBlockIndex*)& item, mapSelectedBlocks)
        {
            // 'S' indicates selected proof-of-stake blocks
            // 'W' indicates selected proof-of-work blocks
            strSelectionMap.replace(item.second->nHeight - nHeightFirstCandidate, 1, item.second->IsProofOfStake()? "S" : "W");
        }
        printf("ComputeNextStakeModifier: selection height [%d, %d] map %s\n", nHeightFirstCandidate, pindexPrev->nHeight, strSelectionMap.c_str());
    }
    if (fDebug)
    {
        printf("ComputeNextStakeModifier: new modifier=0x%016"PRIx64" time=%s\n", nStakeModifierNew, DateTimeStrFormat(pindexPrev->GetBlockTime()).c_str());
    }
    
    nStakeModifier = nStakeModifierNew;
    fGeneratedStakeModifier = true;
    return true;
}

// The stake modifier used to hash for a stake kernel is chosen as the stake
// modifier about a selection interval later than the coin generating the kernel
static bool GetKernelStakeModifier(uint256 hashBlockFrom, uint64_t& nStakeModifier, int& nStakeModifierHeight, int64_t& nStakeModifierTime, bool fPrintProofOfStake)
{
    nStakeModifier = 0;
    if (!mapBlockIndex.count(hashBlockFrom))
        return error("GetKernelStakeModifier() : block not indexed");
    const CBlockIndex* pindexFrom = mapBlockIndex[hashBlockFrom];
    nStakeModifierHeight = pindexFrom->nHeight;
    nStakeModifierTime = pindexFrom->GetBlockTime();
    int64_t nStakeModifierSelectionInterval = GetStakeModifierSelectionInterval();
    const CBlockIndex* pindex = pindexFrom;
    // loop to find the stake modifier later by a selection interval
    while (nStakeModifierTime < pindexFrom->GetBlockTime() + nStakeModifierSelectionInterval)
    {
        if (!pindex->pnext)
        {   // reached best block; may happen if node is behind on block chain
            if (fPrintProofOfStake || (pindex->GetBlockTime() + nStakeMinAge - nStakeModifierSelectionInterval > GetAdjustedTime()))
                return error("GetKernelStakeModifier() : reached best block %s at height %d from block %s",
                             pindex->GetBlockHash().ToString().c_str(), pindex->nHeight, hashBlockFrom.ToString().c_str());
            else
                return false;
        }
        pindex = pindex->pnext;
        if (pindex->GeneratedStakeModifier())
        {
            nStakeModifierHeight = pindex->nHeight;
            nStakeModifierTime = pindex->GetBlockTime();
        }
    }
    nStakeModifier = pindex->nStakeModifier;
    return true;
}

// ppcoin kernel protocol
// coinstake must meet hash target according to the protocol:
// kernel (input 0) must meet the formula
//     hash(nStakeModifier + txPrev.block.nTime + txPrev.offset + txPrev.nTime + txPrev.vout.n + nTime) < bnTarget * nCoinDayWeight
// this ensures that the chance of getting a coinstake is proportional to the
// amount of coin age one owns.
// The reason this hash is chosen is the following:
//   nStakeModifier: scrambles computation to make it very difficult to precompute
//                  future proof-of-stake at the time of the coin's confirmation
//   txPrev.block.nTime: prevent nodes from guessing a good timestamp to
//                       generate transaction for future advantage
//   txPrev.offset: offset of txPrev inside block, to reduce the chance of
//                  nodes generating coinstake at the same time
//   txPrev.nTime: reduce the chance of nodes generating coinstake at the same
//                 time
//   txPrev.vout.n: output number of txPrev, to reduce the chance of nodes
//                  generating coinstake at the same time
//   block/tx hash should not be used here as they can be generated in vast
//   quantities so as to generate blocks faster, degrading the system back into
//   a proof-of-work situation.
//
bool CheckStakeKernelHashV1(unsigned int nBits, const CBlock& blockFrom, unsigned int nTxPrevOffset, const CTransaction& txPrev, const COutPoint& prevout, unsigned int nTimeTx, uint256& hashProofOfStake, uint256& targetProofOfStake, bool fPrintProofOfStake)
{
    if (nTimeTx < txPrev.nTime)  // Transaction timestamp violation
        return error("CheckStakeKernelHash() : nTime violation");
    
    unsigned int nTimeBlockFrom = blockFrom.GetBlockTime();
    if (nTimeBlockFrom + nStakeMinAge > nTimeTx) // Min age requirement
        return error("CheckStakeKernelHash() : min age violation");
    
    CBigNum bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
    int64_t nValueIn = txPrev.vout[prevout.n].nValue;
    
    uint256 hashBlockFrom = blockFrom.GetHash();
    
    CBigNum bnCoinDayWeight = CBigNum(nValueIn) * GetWeight((int64_t)txPrev.nTime, (int64_t)nTimeTx) / COIN / (24 * 60 * 60);
    targetProofOfStake = (bnCoinDayWeight * bnTargetPerCoinDay).getuint256();
    
    // Calculate hash
    CDataStream ss(SER_GETHASH, 0);
    uint64_t nStakeModifier = 0;
    int nStakeModifierHeight = 0;
    int64_t nStakeModifierTime = 0;
    
    if ( !GetKernelStakeModifier(hashBlockFrom, nStakeModifier, nStakeModifierHeight, nStakeModifierTime, fPrintProofOfStake) )
        return false;
    ss << nStakeModifier << nTimeBlockFrom << nTxPrevOffset << txPrev.nTime << prevout.n << nTimeTx;
    hashProofOfStake = Hash(ss.begin(), ss.end());
    if (fPrintProofOfStake)
    {
        printf("CheckStakeKernelHash() : using modifier 0x%016"PRIx64" at height=%d timestamp=%s for block from height=%d timestamp=%s\n",
               nStakeModifier, nStakeModifierHeight,
               DateTimeStrFormat(nStakeModifierTime).c_str(),
               mapBlockIndex[hashBlockFrom]->nHeight,
               DateTimeStrFormat(blockFrom.GetBlockTime()).c_str());
        printf("CheckStakeKernelHash() : check modifier=0x%016"PRIx64" nTimeBlockFrom=%u nTxPrevOffset=%u nTimeTxPrev=%u nPrevout=%u nTimeTx=%u hashProof=%s\n",
               nStakeModifier,
               nTimeBlockFrom, nTxPrevOffset, txPrev.nTime, prevout.n, nTimeTx,
               hashProofOfStake.ToString().c_str());
    }
    
    // Now check if proof-of-stake hash meets target protocol
    if (CBigNum(hashProofOfStake) > bnCoinDayWeight * bnTargetPerCoinDay)
        return false;
    if (fDebug && !fPrintProofOfStake)
    {
        printf("CheckStakeKernelHash() : using modifier 0x%016"PRIx64" at height=%d timestamp=%s for block from height=%d timestamp=%s\n",
               nStakeModifier, nStakeModifierHeight,
               DateTimeStrFormat(nStakeModifierTime).c_str(),
               mapBlockIndex[hashBlockFrom]->nHeight,
               DateTimeStrFormat(blockFrom.GetBlockTime()).c_str());
        printf("CheckStakeKernelHash() : pass modifier=0x%016"PRIx64" nTimeBlockFrom=%u nTxPrevOffset=%u nTimeTxPrev=%u nPrevout=%u nTimeTx=%u hashProof=%s\n",
               nStakeModifier,
               nTimeBlockFrom, nTxPrevOffset, txPrev.nTime, prevout.n, nTimeTx,
               hashProofOfStake.ToString().c_str());
    }
    return true;
}

bool CheckStakeKernelHash(CBlockIndex* pindexPrev, unsigned int nBits, const CBlock& blockFrom, unsigned int nTxPrevOffset, const CTransaction& txPrev, const COutPoint& prevout, unsigned int nTimeTx, uint256& hashProofOfStake, uint256& targetProofOfStake, bool fPrintProofOfStake)
{
    if (IsPoSV2(pindexPrev->nHeight+1))
        return CheckStakeKernelHashV2(pindexPrev, nBits, blockFrom.GetBlockTime(), txPrev, prevout, nTimeTx, hashProofOfStake, targetProofOfStake, fPrintProofOfStake);
    else
        return CheckStakeKernelHashV1(nBits, blockFrom, nTxPrevOffset, txPrev, prevout, nTimeTx, hashProofOfStake, targetProofOfStake, fPrintProofOfStake);
}

bool CWallet::CreateCoinStake(const CKeyStore& keystore, unsigned int nBits, int64_t nSearchInterval, int64_t nFees, CTransaction& txNew, CKey& key)
{
    CBlockIndex* pindexPrev = pindexBest;
    CBigNum bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
    
    txNew.vin.clear();
    txNew.vout.clear();
    
    // Mark coin stake transaction
    CScript scriptEmpty;
    scriptEmpty.clear();
    txNew.vout.push_back(CTxOut(0, scriptEmpty));
    
    // Choose coins to use
    int64_t nBalance = GetBalance();
    
    if (nBalance <= nReserveBalance)
        return false;
    
    vector<const CWalletTx*> vwtxPrev;
    
    set<pair<const CWalletTx*,unsigned int> > setCoins;
    int64_t nValueIn = 0;
    
    // Select coins with suitable depth
    if (!SelectCoinsSimple(nBalance - nReserveBalance, txNew.nTime, nCoinbaseMaturity + 10, setCoins, nValueIn))
        return false;
    
    if (setCoins.empty())
        return false;
    
    int64_t nCredit = 0;
    CScript scriptPubKeyKernel;
    CTxDB txdb("r");
    BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
    {
        CTxIndex txindex;
        {
            LOCK2(cs_main, cs_wallet);
            if (!txdb.ReadTxIndex(pcoin.first->GetHash(), txindex))
                continue;
        }
        
        // Read block header
        CBlock block;
        {
            LOCK2(cs_main, cs_wallet);
            if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
                continue;
        }
        
        static int nMaxStakeSearchInterval = 60;
        if (block.GetBlockTime() + nStakeMinAge > txNew.nTime - nMaxStakeSearchInterval)
            continue; // only count coins meeting min age requirement
        
        bool fKernelFound = false;
        for (unsigned int n=0; n<min(nSearchInterval,(int64_t)nMaxStakeSearchInterval) && !fKernelFound && !fShutdown && pindexPrev == pindexBest; n++)
        {
            // Search backward in time from the given txNew timestamp
            // Search nSearchInterval seconds back up to nMaxStakeSearchInterval
            uint256 hashProofOfStake = 0, targetProofOfStake = 0;
            COutPoint prevoutStake = COutPoint(pcoin.first->GetHash(), pcoin.second);
            if (CheckStakeKernelHash(pindexPrev, nBits, block, txindex.pos.nTxPos - txindex.pos.nBlockPos, *pcoin.first, prevoutStake, txNew.nTime - n, hashProofOfStake, targetProofOfStake))
            {
                // Found a kernel
                if (fDebug && GetBoolArg("-printcoinstake"))
                    printf("CreateCoinStake : kernel found\n");
                vector<valtype> vSolutions;
                txnouttype whichType;
                CScript scriptPubKeyOut;
                scriptPubKeyKernel = pcoin.first->vout[pcoin.second].scriptPubKey;
                if (!Solver(scriptPubKeyKernel, whichType, vSolutions))
                {
                    if (fDebug && GetBoolArg("-printcoinstake"))
                        printf("CreateCoinStake : failed to parse kernel\n");
                    break;
                }
                if (fDebug && GetBoolArg("-printcoinstake"))
                    printf("CreateCoinStake : parsed kernel type=%d\n", whichType);
                if (whichType != TX_PUBKEY && whichType != TX_PUBKEYHASH)
                {
                    if (fDebug && GetBoolArg("-printcoinstake"))
                        printf("CreateCoinStake : no support for kernel type=%d\n", whichType);
                    break;  // only support pay to public key and pay to address
                }
                if (whichType == TX_PUBKEYHASH) // pay to address type
                {
                    // convert to pay to public key type
                    if (!keystore.GetKey(uint160(vSolutions[0]), key))
                    {
                        if (fDebug && GetBoolArg("-printcoinstake"))
                            printf("CreateCoinStake : failed to get key for kernel type=%d\n", whichType);
                        break;  // unable to find corresponding public key
                    }
                    scriptPubKeyOut << key.GetPubKey() << OP_CHECKSIG;
                }
                if (whichType == TX_PUBKEY)
                {
                    valtype& vchPubKey = vSolutions[0];
                    if (!keystore.GetKey(Hash160(vchPubKey), key))
                    {
                        if (fDebug && GetBoolArg("-printcoinstake"))
                            printf("CreateCoinStake : failed to get key for kernel type=%d\n", whichType);
                        break;  // unable to find corresponding public key
                    }
                    
                    if (key.GetPubKey() != vchPubKey)
                    {
                        if (fDebug && GetBoolArg("-printcoinstake"))
                            printf("CreateCoinStake : invalid key for kernel type=%d\n", whichType);
                        break; // keys mismatch
                    }
                    
                    scriptPubKeyOut = scriptPubKeyKernel;
                }
                
                txNew.nTime -= n;
                txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
                nCredit += pcoin.first->vout[pcoin.second].nValue;
                vwtxPrev.push_back(pcoin.first);
                txNew.vout.push_back(CTxOut(0, scriptPubKeyOut));
                
                if (GetWeight(block.GetBlockTime(), (int64_t)txNew.nTime) < nStakeSplitAge)
                    txNew.vout.push_back(CTxOut(0, scriptPubKeyOut)); //split stake
                if (fDebug && GetBoolArg("-printcoinstake"))
                    printf("CreateCoinStake : added kernel type=%d\n", whichType);
                fKernelFound = true;
                break;
            }
        }
        
        if (fKernelFound || fShutdown)
            break; // if kernel is found stop searching
    }
    
    if (nCredit == 0 || nCredit > nBalance - nReserveBalance)
        return false;
    
    BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
    {
        // Attempt to add more inputs
        // Only add coins of the same key/address as kernel
        if (txNew.vout.size() == 2 && ((pcoin.first->vout[pcoin.second].scriptPubKey == scriptPubKeyKernel || pcoin.first->vout[pcoin.second].scriptPubKey == txNew.vout[1].scriptPubKey))
            && pcoin.first->GetHash() != txNew.vin[0].prevout.hash)
        {
            int64_t nTimeWeight = GetWeight((int64_t)pcoin.first->nTime, (int64_t)txNew.nTime);
            
            // Stop adding more inputs if already too many inputs
            if (txNew.vin.size() >= 100)
                break;
            // Stop adding more inputs if value is already pretty significant
            if (nCredit >= nStakeCombineThreshold)
                break;
            // Stop adding inputs if reached reserve limit
            if (nCredit + pcoin.first->vout[pcoin.second].nValue > nBalance - nReserveBalance)
                break;
            // Do not add additional significant input
            if (pcoin.first->vout[pcoin.second].nValue >= nStakeCombineThreshold)
                continue;
            // Do not add input that is still too young
            if (nTimeWeight < nStakeMinAge)
                continue;
            
            txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
            nCredit += pcoin.first->vout[pcoin.second].nValue;
            vwtxPrev.push_back(pcoin.first);
        }
    }
    
    // Calculate coin age reward
    {
        uint64_t nCoinAge;
        CTxDB txdb("r");
        if (!txNew.GetCoinAge(txdb, nCoinAge))
            return error("CreateCoinStake : failed to calculate coin age");
        
        int64_t nReward = GetProofOfStakeReward(nCoinAge, nFees);
        if (nReward <= 0)
            return false;
        
        nCredit += nReward;
    }
    
    // Set output amount
    if (txNew.vout.size() == 3)
    {
        txNew.vout[1].nValue = (nCredit / 2 / CENT) * CENT;
        txNew.vout[2].nValue = nCredit - txNew.vout[1].nValue;
    }
    else
        txNew.vout[1].nValue = nCredit;
    
    // Sign
    int nIn = 0;
    BOOST_FOREACH(const CWalletTx* pcoin, vwtxPrev)
    {
        if (!SignSignature(*this, *pcoin, txNew, nIn++))
            return error("CreateCoinStake : failed to sign coinstake");
    }
    
    // Limit size
    unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);
    if (nBytes >= MAX_BLOCK_SIZE_GEN/5)
        return error("CreateCoinStake : exceeded coinstake size limit");
    
    // Successfully generated coinstake
    return true;
}

// Check kernel hash target and coinstake signature
bool CheckProofOfStake(CBlockIndex* pindexPrev, const CTransaction& tx, unsigned int nBits, uint256& hashProofOfStake, uint256& targetProofOfStake)
{
    if (!tx.IsCoinStake())
        return error("CheckProofOfStake() : called on non-coinstake %s", tx.GetHash().ToString().c_str());
    
    // Kernel (input 0) must match the stake hash target per coin age (nBits)
    const CTxIn& txin = tx.vin[0];
    
    // First try finding the previous transaction in database
    CTxDB txdb("r");
    CTransaction txPrev;
    CTxIndex txindex;
    if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
        return tx.DoS(1, error("CheckProofOfStake() : INFO: read txPrev failed"));  // previous transaction not in main chain, may occur during initial download
    
    // Verify signature
    if (!VerifySignature(txPrev, tx, 0, 0))
        return tx.DoS(100, error("CheckProofOfStake() : VerifySignature failed on coinstake %s", tx.GetHash().ToString().c_str()));
    
    // Read block header
    CBlock block;
    if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
        return fDebug? error("CheckProofOfStake() : read block failed") : false; // unable to read block of previous transaction
    
    if (!CheckStakeKernelHash(pindexPrev, nBits, block, txindex.pos.nTxPos - txindex.pos.nBlockPos, txPrev, txin.prevout, tx.nTime, hashProofOfStake, targetProofOfStake, fDebug))
        return tx.DoS(1, error("CheckProofOfStake() : INFO: check kernel failed on coinstake %s, hashProof=%s", tx.GetHash().ToString().c_str(), hashProofOfStake.ToString().c_str())); // may occur during initial download or if behind on block chain sync
    
    return true;
}

// Check whether the coinstake timestamp meets protocol
bool CheckCoinStakeTimestamp(int64_t nTimeBlock, int64_t nTimeTx)
{
    // v0.3 protocol
    return (nTimeBlock == nTimeTx);
}

// Get stake modifier checksum
unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex)
{
    //assert (pindex->pprev || pindex->GetBlockHash() == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet));
    // Hash previous checksum with flags, hashProofOfStake and nStakeModifier
    CDataStream ss(SER_GETHASH, 0);
    if (pindex->pprev)
        ss << pindex->pprev->nStakeModifierChecksum;
    ss << pindex->nFlags << (pindex->IsProofOfStake() ? pindex->hashProof : 0) << pindex->nStakeModifier;
    uint256 hashChecksum = Hash(ss.begin(), ss.end());
    hashChecksum >>= (256 - 32);
    return hashChecksum.Get64();
}

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, unsigned int nStakeModifierChecksum)
{
    MapModifierCheckpoints& checkpoints = (fTestNet ? mapStakeModifierCheckpointsTestNet : mapStakeModifierCheckpoints);
    
    if (checkpoints.count(nHeight))
        return nStakeModifierChecksum == checkpoints[nHeight];
    return true;
}
// novacoin: attempt to generate suitable proof-of-stake
bool CBlock::SignBlock(CWallet& wallet, int64_t nFees)
{
    // if we are trying to sign
    //    something except proof-of-stake block template
    if (!vtx[0].vout[0].IsEmpty())
        return false;
    
    // if we are trying to sign
    //    a complete proof-of-stake block
    if (IsProofOfStake())
        return true;
    
    static int64_t nLastCoinStakeSearchTime = GetAdjustedTime(); // startup timestamp
    
    CKey key;
    CTransaction txCoinStake;
    int64_t nSearchTime = txCoinStake.nTime; // search to current time
    
    if (nSearchTime > nLastCoinStakeSearchTime)
    {
        if (wallet.CreateCoinStake(wallet, nBits, nSearchTime-nLastCoinStakeSearchTime, nFees, txCoinStake, key))
        {
                if (txCoinStake.nTime >= max(pindexBest->GetPastTimeLimit()+1, PastDrift(pindexBest->GetBlockTime())))
                {
                    // make sure coinstake would meet timestamp protocol
                    //    as it would be the same as the block timestamp
                    vtx[0].nTime = nTime = txCoinStake.nTime;
                    nTime = max(pindexBest->GetPastTimeLimit()+1, GetMaxTransactionTime());
                    nTime = max(GetBlockTime(), PastDrift(pindexBest->GetBlockTime()));
                    // we have to make sure that we have no future timestamps in
                    //    our transactions set
                    for (vector<CTransaction>::iterator it = vtx.begin(); it != vtx.end();)
                        if (it->nTime > nTime) { it = vtx.erase(it); } else { ++it; }
                    
                    vtx.insert(vtx.begin() + 1, txCoinStake);
                    hashMerkleRoot = BuildMerkleTree();
                    
                    // append a signature to our block
                    return key.Sign(GetHash(), vchBlockSig);
                }
        }
        nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
        nLastCoinStakeSearchTime = nSearchTime;
    }
    
    return false;
}

bool CBlock::CheckBlockSignature() const
{
    if (IsProofOfWork())
        return vchBlockSig.empty();
        
        vector<valtype> vSolutions;
    txnouttype whichType;
    
    const CTxOut& txout = vtx[1].vout[1];
    
    if (!Solver(txout.scriptPubKey, whichType, vSolutions))
        return false;
    
    if (whichType == TX_PUBKEY)
    {
        valtype& vchPubKey = vSolutions[0];
        CKey key;
        if (!key.SetPubKey(vchPubKey))
            return false;
        if (vchBlockSig.empty())
            return false;
        return key.Verify(GetHash(), vchBlockSig);
    }
    
    return false;
}

#endif
