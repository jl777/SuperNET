/******************************************************************************
 * Copyright © 2014-2016 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include "peggy.h"

int32_t peggy_create_micropay(uint8_t *txbuf,int32_t len,struct accts777_info *accts,uint32_t blocknum,uint32_t blocktimestamp,uint64_t nxt64bits,struct peggy_txmicropay *micropay,struct peggy_input *in,struct peggy_output *out)
{
    //struct peggy_txmicropay { bits256 claimhash,refundhash; uint32_t expiration,chainlen; uint8_t vin,vout; };
    return(len);
}

int32_t peggy_create_micropair(uint8_t *txbuf,int32_t len,struct accts777_info *accts,uint32_t blocknum,uint32_t blocktimestamp,uint64_t nxt64bitsA,struct peggy_txmicropay *micropayA,struct peggy_input *inA,struct peggy_output *outA,uint64_t nxt64bitsB,struct peggy_txmicropay *micropayB,struct peggy_input *inB,struct peggy_output *outB)
{
    return(len);
}

int32_t peggy_create_prices(uint8_t *txbuf,int32_t len,struct accts777_info *accts,uint32_t blocknum,uint32_t blocktimestamp,uint64_t nxt64bits,struct peggy_txprices *price,uint32_t stakedblock)
{
    uint32_t key[2]; int32_t i,size = price->num * sizeof(price->feed[0]);
    if ( stakedblock != 0 || nxt64bits != 0 )
    {
        for (i=0; i<price->num; i++)
            len = txind777_txbuf(txbuf,len,price->feed[i],sizeof(price->feed[i]));//, fprintf(stderr,"%d ",price->feed[i]);
        key[0] = blocknum, key[1] = 0;
        ramkv777_write(accts->pricefeeds,key,price->feed,size);
        return(len);
    } else printf("unsigned pricefeed not staked blocknum.%d t%u\n",blocknum,blocktimestamp);
    // add to daily list for eval in daily settlement
    return(-1);
}

int32_t peggy_create_bet(uint8_t *txbuf,struct accts777_info *accts,uint32_t blocknum,uint32_t blocktimestamp,uint64_t nxt64bits,uint64_t value,char *coinaddr,struct peggy_txbet *bet)
{
    uint64_t key[2];
    key[0] = blocktimestamp, key[1] = nxt64bits;
    // add to daily list for eval in daily settlement
    return(0);
}

int32_t peggy_enable(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
{
    PEG->name.enabled = (int32_t)val;
    return(0);
}

int32_t peggy_dailyrate(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
{
    PEG->maxdailyrate = (int32_t)val;
    return(0);
}

int32_t peggy_quorum(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
{
    PEG->pool.quorum = val;
    return(0);
}

int32_t peggy_decisionthreshold(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
{
    PEG->pool.decisionthreshold = val;
    return(0);
}

int32_t peggy_maxnetbalance(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
{
    PEG->maxnetbalance = val;
    return(0);
}

int32_t peggy_maxsupply(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
{
    PEG->maxsupply = val;
    return(0);
}

/*int32_t peggy_numtimeframes(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
 {
 PEG->limits.numtimeframes = (int32_t)val;
 return(0);
 }
 
 int32_t peggy_timeframe(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
 {
 if ( val < PEG->limits.numtimeframes )
 PEG->limits.timeframes[val] = (int32_t)valB;
 return(0);
 }
 
 int32_t peggy_timescale(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
 {
 if ( val < PEG->limits.numtimeframes )
 PEG->limits.scales[val] = valB;
 return(0);
 }*/

int32_t peggy_lockdays(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
{
    PEG->lockparms.minlockdays = val, PEG->lockparms.maxlockdays = valB;
    return(0);
}

int32_t peggy_clonesmear(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
{
    PEG->lockparms.clonesmear = val;
    return(0);
}

int32_t peggy_mixrange(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
{
    PEG->lockparms.mixrange = val;
    return(0);
}

int32_t peggy_redemptiongap(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
{
    PEG->lockparms.redemptiongapdays = val;
    return(0);
}

int32_t peggy_extralockdays(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
{
    PEG->lockparms.extralockdays = val;
    return(0);
}

int32_t peggy_maxmargin(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
{
    PEG->lockparms.margin = val;
    return(0);
}

int32_t peggy_mindenomination(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
{
    PEG->mindenomination.Pval = val;
    return(0);
}

int32_t peggy_spread(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB)
{
    PEG->spread.Pval = val;
    return(0);
}

int32_t peggy_fees(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint8_t interesttenths,uint8_t posboost,uint8_t negpenalty,uint8_t feediv,uint8_t feemult)
{
    PEGS->interesttenths = interesttenths, PEGS->posboost = posboost, PEGS->negpenalty = negpenalty, PEGS->feediv = feediv, PEGS->feemult = feemult;
    return(0);
}

int32_t (*tunefuncs[])(struct peggy_info *PEGS,struct peggy *PEG,uint32_t blocktimestamp,int32_t actionflag,uint64_t val,uint64_t valB) =
{
    peggy_enable, peggy_dailyrate, peggy_quorum, peggy_decisionthreshold, peggy_maxnetbalance, peggy_maxsupply, peggy_lockdays, peggy_clonesmear, peggy_mixrange, peggy_redemptiongap, peggy_extralockdays, peggy_maxmargin, peggy_mindenomination, peggy_spread
};

uint64_t peggy_onesigner(struct peggy_tx *Ptx)
{
    if ( Ptx->sigs[0].signer64bits != 0 && Ptx->sigs[1].signer64bits == 0 )
        return(Ptx->sigs[0].signer64bits);
    else return(0);
}

int32_t peggy_twosigners(uint64_t signers[2],struct peggy_tx *Ptx)
{
    if ( Ptx->sigs[0].signer64bits != 0 && Ptx->sigs[1].signer64bits != 0 && Ptx->sigs[2].signer64bits == 0 )
    {
        signers[0] = Ptx->sigs[0].signer64bits;
        signers[1] = Ptx->sigs[1].signer64bits;
        return(2);
    }
    else return(-1);
}

int64_t peggy_txind_tune(struct peggy_info *PEGS,uint32_t blocknum,uint32_t blocktimestamp,int32_t actionflag,struct peggy_tx *Ptx,struct peggy_txtune *tune,int32_t numtunes)
{
    static char *accts[] = { "NXT-SQ9J-JCAN-8XVY-5XN7K", "NXT-J698-WN8Q-XR8A-92TLD", "NXT-JNES-HJ86-KNXQ-AQ33Z", "NXT-RQYG-UPJP-HMMH-7WHFZ" };
    char name[16]; int32_t i,peg,flag = 0; uint64_t nxt64bits; struct peggy *PEG; int64_t txind=0,txinds[256];
    if ( Ptx->numoutputs != 0 || Ptx->numinputs != 0 || (nxt64bits= peggy_onesigner(Ptx)) == 0 )
        return(-1);
    for (i=0; i<sizeof(accts)/sizeof(*accts); i++)
        if ( nxt64bits == conv_acctstr(accts[i]) )
            flag = 1;
    if ( flag == 0 )
        return(-1);
    if ( numtunes > 0 )
    {
        for (i=0; i<numtunes; i++)
        {
            peg = peggy_pegstr(name,PEGS,tune[i].peg);
            if ( peg < 0 || peg >= PEGS->numpegs )
                return(-1);
            if ( actionflag <= 0 )
                continue;
            PEG = PEGS->contracts[peg];
            if ( tune[i].type == 77 && peggy_fees(PEGS,PEG,blocktimestamp,actionflag,tune[i].B.bytes[0],tune[i].B.bytes[1],tune[i].B.bytes[2],tune[i].B.bytes[3],tune[i].B.bytes[4]) < 0 )
                return(-1);
            else if ( tune[i].type >= sizeof(tunefuncs)/sizeof(*tunefuncs) )
                return(-1);
            else if ( (*tunefuncs[i])(PEGS,PEG,blocktimestamp,actionflag,tune->val,tune->B.val) < 0 )
                return(-1);
            txinds[i] = txind777_create(PEGS->accts->txinds,blocknum,blocktimestamp,&tune[i],sizeof(tune[i]));
        }
        txind = txind777_bundle(PEGS->accts->txinds,blocknum,blocktimestamp,txinds,numtunes);
    }
    return(txind);
}

int64_t peggy_txind_micropay(uint8_t *txbuf,int32_t len,struct accts777_info *accts,uint32_t blocknum,uint32_t blocktimestamp,int32_t actionflag,struct peggy_tx *Ptx,struct peggy_txmicropay *micropays,int32_t num)
{
    uint64_t nxt64bits,both[2];
    if ( (nxt64bits= peggy_onesigner(Ptx)) != 0 )
    {
        if ( Ptx->numoutputs != 1 || Ptx->numinputs != 1 || micropays[0].vin != 0 || micropays[0].vout != 0 || num != 1 )
            return(-1);
        if ( actionflag != 0 && (len= peggy_create_micropay(txbuf,len,accts,blocknum,blocktimestamp,nxt64bits,micropays,Ptx->inputs,Ptx->outputs)) < 0 )
            return(-1);
    }
    else if ( peggy_twosigners(both,Ptx) > 0 )
    {
        if ( Ptx->numoutputs != 2 || Ptx->numinputs != 2 || num != 2 )
            return(-1);
        if ( micropays[0].vin != 0 || micropays[0].vout != 0 || micropays[1].vin != 1 || micropays[1].vout != 1 )
            return(-1);
        if ( actionflag != 0 )
        {
            if ( (len= peggy_create_micropair(txbuf,len,accts,blocknum,blocktimestamp,both[0],&micropays[0],&Ptx->inputs[0],&Ptx->outputs[0],both[1],&micropays[1],&Ptx->inputs[1],&Ptx->outputs[1])) < 0 )
                return(-1);
        }
    }
    if ( len > 0 )
        return(txind777_create(accts->txinds,blocknum,blocktimestamp,txbuf,len));
    return(-1);
}

int64_t peggy_txind_prices(uint8_t *txbuf,int32_t len,struct accts777_info *accts,uint32_t blocknum,uint32_t blocktimestamp,int32_t actionflag,struct peggy_tx *Ptx,struct peggy_txprices *prices,uint32_t stakedblock)
{
    if ( Ptx->numoutputs != 0 || Ptx->numinputs != 0 )
    {
        printf("peggy_txind_prices: unexpected numinputs.%d numoutputs.%d\n",Ptx->numoutputs,Ptx->numinputs);
        return(-1);
    }
    if ( actionflag != 0 )
    {
        if ( (len= peggy_create_prices(txbuf,len,accts,blocknum,blocktimestamp,stakedblock == 0 ? peggy_onesigner(Ptx) : 0,prices,stakedblock)) < 0 )
            return(-1);
        // printf("len.%d txinds.%p\n",len,accts->txinds);
        return(txind777_create(accts->txinds,blocknum,blocktimestamp,txbuf,len));
    }
    return(-1);
}

int32_t txind777_txbuf_lock(uint8_t *txbuf,int32_t len,struct peggy_lock *lock)
{
    if ( txbuf != 0 )
    {
        len = txind777_txbuf(txbuf,len,lock->peg,sizeof(lock->peg));
        len = txind777_txbuf(txbuf,len,lock->denom,sizeof(lock->denom));
        len = txind777_txbuf(txbuf,len,lock->minlockdays,sizeof(lock->minlockdays));
        len = txind777_txbuf(txbuf,len,lock->maxlockdays,sizeof(lock->maxlockdays));
        len = txind777_txbuf(txbuf,len,lock->clonesmear,sizeof(lock->clonesmear));
        len = txind777_txbuf(txbuf,len,lock->redemptiongapdays,sizeof(lock->redemptiongapdays));
        len = txind777_txbuf(txbuf,len,lock->extralockdays,sizeof(lock->extralockdays));
        len = txind777_txbuf(txbuf,len,lock->margin,sizeof(lock->margin));
    }
    return(len);
}

int64_t peggy_txind_bets(uint8_t *txbuf,int32_t len,struct accts777_info *accts,uint32_t blocknum,uint32_t blocktimestamp,int32_t actionflag,struct peggy_tx *Ptx,uint64_t value,char *voutcoinaddr,struct peggy_txbet *bets,int32_t numbets)
{
    uint64_t nxt64bits; int32_t i; int64_t txind=0,txinds[256];
    if ( Ptx->numoutputs != 0 || Ptx->numinputs != 0 || (nxt64bits= peggy_onesigner(Ptx)) == 0 )
        return(-1);
    if ( actionflag != 0 )
    {
        for (i=0; i<numbets; i++)
        {
            if ( (len= peggy_create_bet(txbuf,accts,blocknum,blocktimestamp,nxt64bits,value,voutcoinaddr,&bets[i])) < 0 )
                return(-1);
            txinds[i] = txind777_create(accts->txinds,blocknum,blocktimestamp,txbuf,len);
        }
        txind = txind777_bundle(accts->txinds,blocknum,blocktimestamp,txinds,numbets);
    }
    return(0);
}

int32_t peggy_univ2addr(char *coinaddr,struct peggy_univaddr *ua)
{
    return(btc_convrmd160(coinaddr,ua->addrtype,ua->rmd160));
}

int32_t peggy_addr2univ(struct peggy_univaddr *ua,char *coinaddr,char *coin)
{
    char hexstr[512]; uint8_t hex[21];
    if ( btc_convaddr(hexstr,coinaddr) == 0 )
    {
        decode_hex(hex,21,hexstr);
        memset(ua,0,sizeof(*ua));
        ua->addrtype = hex[0];
        memcpy(ua->rmd160,hex+1,20);
        strncpy(ua->coin,coin,sizeof(ua->coin)-1);
        return(0);
    }
    return(-1);
}

int64_t peggy_txind_send(uint8_t *txbuf,int32_t len,struct peggy_info *PEGS,uint32_t blocknum,uint32_t blocktimestamp,uint64_t signer64bits,uint64_t signer64bitsB,int64_t fundedvalue,struct peggy_input *in,uint32_t ratio,struct peggy_output *out)
{
    struct acct777 *acct; struct ramkv777 *kv; struct ramkv777_item *item;
    int64_t value = 0; int32_t i,chainlen,polarity,peg; uint32_t rawind; uint64_t satoshis,amount=0,marginamount = 0;
    struct peggy_unit readU; struct accts777_info *accts; struct peggy_time T; union peggy_addr *addr = &out->dest;
    if ( (accts= PEGS->accts) == 0 )
        return(-1);
    acct = accts777_find(0,accts,addr,out->type);
    if ( acct == 0 )
        acct = accts777_create(accts,addr,out->type,blocknum,blocktimestamp);
    if ( acct == 0 )
        return(-1);
    T.blocknum = blocknum, T.blocktimestamp = blocktimestamp;
    if ( in == 0 && fundedvalue != 0 )
        value = fundedvalue;
    else if ( in != 0 )
    {
        if ( (in->type == PEGGY_ADDRNXT || in->type == PEGGY_ADDR777) && acct777_balance(accts,blocknum,blocktimestamp,&in->src,in->type) >= in->amount )
            value = in->amount;
        else if ( in->type == PEGGY_ADDRPUBKEY )
        {
            if ( in->src.newunit.newlock.minlockdays != 0 )
            {
                if ( ratio != PRICE_RESOLUTION )
                    return(-1);
                chainlen = 1;
                if ( (peg= in->src.newunit.newlock.peg) < 0 )
                    peg = -peg, polarity = -1;
                else polarity = 1;
                value = peggy_redeem(PEGS,T,amount == 0,PEGS->contracts[peg]->name.name,polarity,signer64bits,in->src.sha256,in->src.newunit.newlock.minlockdays,chainlen);
            }
            else if ( acct777_balance(accts,blocknum,blocktimestamp,&in->src,in->type) >= in->amount )
                value = in->amount;
        }
        else if ( in->type == PEGGY_ADDRUNIT )
        {
            if ( ratio != PRICE_RESOLUTION || (out->type != PEGGY_ADDRCREATE && out->type != PEGGY_ADDRUNIT) ) // rollover or swap only
                return(-1);
        } else return(-1);
    }
    if ( (kv= accts777_getaddrkv(accts,out->type)) != 0 && (item= ramkv777_itemptr(kv,acct)) != 0 )
        rawind = item->rawind;
    else rawind = 0;
    len = txind777_txbuf(txbuf,len,rawind,sizeof(uint32_t));
    if ( out->type == PEGGY_ADDRBTCD )
    {
        char coinaddr[64];
        if ( peggy_univ2addr(coinaddr,&addr->coinaddr) < 0 || acct == 0 || opreturns_queue_payment(&accts->PaymentsQ,blocktimestamp,coinaddr,value) < 0 )
            return(-1);
    }
    else if ( out->type == PEGGY_ADDRCREATE )
    {
        if ( value > 0 )
        {
            if ( addr->newunit.newlock.margin == 0 )
                amount = value;
            else marginamount = value;
            satoshis = peggy_createunit(PEGS,T,0,accts->peggyhash.txid,0,signer64bits,addr->newunit.sha256,&addr->newunit.newlock,amount,marginamount);
            len = txind777_txbuf_lock(txbuf,len,&addr->newunit.newlock);
            if ( in != 0 && in->type == PEGGY_ADDRUNIT )
            {
                for (i=0; i<sizeof(bits256); i++)
                    txbuf[len++] = in->src.sha256.bytes[i];
                if ( peggy_swap(accts,signer64bits,signer64bitsB,in->src.sha256,addr->newunit.sha256) < 0 )
                    return(-1);
            }
        } else return((int32_t)peggy_createunit(PEGS,T,&readU,accts->peggyhash.txid,0,signer64bits,addr->newunit.sha256,&addr->newunit.newlock,amount,marginamount));
    }
    else if ( acct != 0 )
    {
        if ( in != 0 && in->type == PEGGY_ADDRUNIT )
        {
            for (i=0; i<sizeof(bits256); i++)
                txbuf[len++] = in->src.sha256.bytes[i];
            if ( peggy_swap(accts,signer64bits,signer64bitsB,in->src.sha256,addr->sha256) < 0 )
                return(-1);
        }
        else if ( acct777_pay(accts,0,acct,value,blocknum,blocktimestamp) < 0 )
            return(-1);
    }
    return(txind777_create(accts->txinds,blocknum,blocktimestamp,txbuf,len));
}

int32_t peggy_checktx(struct price_resolution vinsums[PEGGY_MAXINPUTS],struct accts777_info *accts,int32_t actionflag,struct peggy_tx *Ptx,uint32_t blocknum,uint32_t blocktimestamp)
{
    int32_t i;
    if ( Ptx->numoutputs == 0 && Ptx->numinputs == 0 )
        return(0);
    else if ( Ptx->numoutputs != 0 && Ptx->numinputs == 0 )
        return(-1);
    memset(vinsums,0,sizeof(*vinsums) * PEGGY_MAXINPUTS);
    if ( Ptx->numoutputs > 0 )
    {
        for (i=0; i<Ptx->numoutputs; i++)
        {
            if ( Ptx->outputs[i].vin < 0 || Ptx->outputs[i].vin >= Ptx->numinputs || Ptx->outputs[i].ratio > PRICE_RESOLUTION )
                return(-1);
            vinsums[Ptx->outputs[i].vin].Pval += Ptx->outputs[i].ratio;
            //if ( acct777_balance(&PEGS->accts,blocktimestamp,&Ptx->outputs[i].dest,Ptx->outputs[i].type) < 0 )
            //    return(-1);
        }
    }
    for (i=0; i<Ptx->numinputs; i++)
        if ( vinsums[i].Pval != PRICE_RESOLUTION )
        {
            printf("mismatched vinsum[%d] %.6f\n",i,Pval(&vinsums[i]));
            return(-1);
        }
    if ( Ptx->numinputs > 0 )
    {
        for (i=0; i<Ptx->numinputs; i++)
        {
            if ( acct777_balance(accts,blocknum,blocktimestamp,&Ptx->inputs[i].src,Ptx->inputs[i].type) < 0 )
                return(-1);
        }
    }
    return(0);
}

int64_t peggy_txind(int64_t *tipvaluep,struct peggy_info *PEGS,uint32_t blocknum,uint32_t blocktimestamp,int32_t actionflag,struct peggy_tx *Ptx,int32_t stakedblock)
{
    int32_t i,len = 0; uint64_t signer64bits,both[2]; int64_t txind=0,txinds[PEGGY_MAXOUTPUTS*2]; uint8_t txbuf[65536];
    struct price_resolution vinsums[PEGGY_MAXINPUTS]; struct accts777_info *accts;
    if ( (accts= PEGS->accts) == 0 )
    {
        printf("no PEGS->accts\n");
        return(-1);
    }
    if ( actionflag < 0 )
    {
        printf("undo not supported, rewind and redo\n");
        return(-1);
    }
    txbuf[len++] = Ptx->txtype, txbuf[len++] = Ptx->txtype, txbuf[len++] = Ptx->numinputs, txbuf[len++] = Ptx->numoutputs;
    len = txind777_txbuf(txbuf,len,blocknum,sizeof(blocknum));
    len = txind777_txbuf(txbuf,len,blocktimestamp,sizeof(blocktimestamp));
    if ( Ptx->txtype == PEGGY_TXNORMAL )
    {
        if ( (signer64bits= peggy_onesigner(Ptx)) != 0 )
        {
            txbuf[len++] = 1;
            len = txind777_txbuf(txbuf,len,signer64bits,sizeof(signer64bits));
            printf("peggy_onesigner\n");
            if ( Ptx->numinputs == 0 )
            {
                if ( Ptx->numoutputs == 1 )
                {
                    len = txind777_txbuf(txbuf,len,Ptx->funding.amount,sizeof(Ptx->funding.amount));
                    memcpy(txbuf,&Ptx->funding.src.coinaddr,sizeof(Ptx->funding.src.coinaddr)), len += sizeof(Ptx->funding.src.coinaddr);
                    if ( (txind= peggy_txind_send(txbuf,len,PEGS,blocknum,blocktimestamp,signer64bits,0,actionflag*Ptx->funding.amount,0,PRICE_RESOLUTION,&Ptx->outputs[0])) > 0 )
                        *tipvaluep = 0;
                }
                else return(-2);
            }
            else if ( Ptx->numinputs == 1 )
            {
                if ( Ptx->numoutputs >= 1 )
                {
                    if ( peggy_checktx(vinsums,accts,actionflag,Ptx,blocknum,blocktimestamp) < 0 )
                        return(-3);
                    if ( actionflag != 0 )
                    {
                        for (i=0; i<Ptx->numoutputs; i++)
                            if ( (txinds[i] = peggy_txind_send(txbuf,len,PEGS,blocknum,blocktimestamp,signer64bits,0,0,Ptx->inputs,(uint32_t)vinsums[i].Pval,&Ptx->outputs[i])) < 0 )
                                return(-1);
                        txind = txind777_bundle(accts->txinds,blocknum,blocktimestamp,txinds,Ptx->numoutputs);
                    }
                    return(txind);
                }
            }
            else if ( Ptx->numoutputs == 1 )
            {
                if ( Ptx->outputs[0].ratio == PRICE_RESOLUTION )
                {
                    if ( actionflag != 0 )
                    {
                        for (i=0; i<Ptx->numoutputs; i++)
                            if ( (txinds[i]= peggy_txind_send(txbuf,len,PEGS,blocknum,blocktimestamp,signer64bits,0,0,&Ptx->inputs[i],Ptx->outputs[0].ratio,Ptx->outputs)) < 0 )
                                return(-1);
                        txind = txind777_bundle(accts->txinds,blocknum,blocktimestamp,txinds,Ptx->numinputs);
                    }
                    return(txind);
                } else printf("error non unit ratio\n");
            }
            return(-1);
        }
        else if ( peggy_twosigners(both,Ptx) > 0 )
        {
            txbuf[len++] = 2;
            len = txind777_txbuf(txbuf,len,both[0],sizeof(both[0]));
            len = txind777_txbuf(txbuf,len,both[1],sizeof(both[1]));
            printf("peggy_twosigners\n");
            if ( Ptx->numoutputs != 1 || Ptx->numinputs != 1 || both[0] != Ptx->sigs[0].signer64bits || both[1] != Ptx->sigs[1].signer64bits )
                return(-1);
            if ( actionflag != 0 )
            {
                if ( (txind= peggy_txind_send(txbuf,len,PEGS,blocknum,blocktimestamp,both[0],both[1],0,&Ptx->inputs[0],PRICE_RESOLUTION,&Ptx->outputs[0])) < 0 )
                    return(-1);
            }
            return(txind);
        } else printf("neither one or two signers\n");
        return(-1);
    }
    else if ( Ptx->txtype == PEGGY_TXPRICES )
        return(peggy_txind_prices(txbuf,len,accts,blocknum,blocktimestamp,actionflag,Ptx,&Ptx->details.price,stakedblock));
    else
    {
        printf("details tx\n");
        if ( peggy_checktx(vinsums,accts,actionflag,Ptx,blocknum,blocktimestamp) < 0 )
            return(-1);
        else if ( Ptx->txtype == PEGGY_TXBET )
        {
            char coinaddr[64];
            len = txind777_txbuf(txbuf,len,Ptx->funding.amount,sizeof(Ptx->funding.amount));
            memcpy(txbuf,&Ptx->funding.src.coinaddr,sizeof(Ptx->funding.src.coinaddr)), len += sizeof(Ptx->funding.src.coinaddr);
            //for (i=0; i<BTCDADDRSIZE; i++)
            //    txbuf[len++] = Ptx->funding.src.coinaddr[i];
            if ( peggy_univ2addr(coinaddr,&Ptx->funding.src.coinaddr) < 0 )
            {
                printf("illegal coinaddr\n");
                return(-1);
            }
            if ( (txind= peggy_txind_bets(txbuf,len,accts,blocknum,blocktimestamp,actionflag,Ptx,Ptx->funding.amount,coinaddr,Ptx->details.bets,Ptx->numdetails)) > 0 )
                *tipvaluep = 0;
        }
        else if ( Ptx->txtype == PEGGY_TXMICROPAY )
            return(peggy_txind_micropay(txbuf,len,accts,blocknum,blocktimestamp,actionflag,Ptx,Ptx->details.micropays,Ptx->numdetails));
    }
    return(txind);
}

int64_t peggy_process(void *_PEGS,int32_t flags,void *fca,uint64_t fundedvalue,uint8_t *data,int32_t datalen,uint32_t blocknum,uint32_t blocktimestamp,uint32_t stakedblock)
{
    struct peggy_tx Ptx; int32_t len,signedcount; int64_t txind = -1,tipvalue; struct peggy_info *PEGS = _PEGS;
    tipvalue = fundedvalue;
    if ( (len= serdes777_deserialize(&signedcount,&Ptx,blocktimestamp,data,datalen)) < 0 )
    {
        printf("peggy_process peggy_deserialize error datalen.%d (%d %d %d)\n",datalen,stakedblock,blocknum,blocktimestamp);
        txind = -1;
    }
    else if ( Ptx.expiration != 0 && Ptx.expiration < blocktimestamp )
    {
        printf("peggy_process peggytx already expired at %u vs %u\n",Ptx.expiration,blocktimestamp);
        txind = -1;
    }
    else if ( Ptx.txtype == PEGGY_TXTUNE )
        txind = peggy_txind_tune(PEGS,blocknum,blocktimestamp,flags,&Ptx,Ptx.details.tune,Ptx.numdetails);
    else txind = peggy_txind(&tipvalue,PEGS,blocknum,blocktimestamp,flags,&Ptx,stakedblock);
    if ( txind < 0 )
        tipvalue = fundedvalue;
    if ( tipvalue != 0 )
        peggy_thanks_you(PEGS,tipvalue);
    if ( stakedblock != 0 )
    {
        uint64_t sums[PEGGY_MAXPRICEDPEGS]; struct price_resolution price,aveprice; struct peggy_time T;
        uint32_t key[2],nonz[PEGGY_MAXPRICEDPEGS],i,j,block,numprices=0,n,*feed; double startmilli;
        struct peggy_vote vote;//{ struct price_resolution price,tolerance; uint64_t nxt64bits,weight; };
        price.Pval = 0;
        memset(sums,0,sizeof(sums)), memset(nonz,0,sizeof(nonz));
        if ( blocknum <= PEGGY_NUMCOEFFS )
            block = 1;
        else block = blocknum - PEGGY_NUMCOEFFS + 1;
        startmilli = OS_milliseconds();
        for (n=i=0; block<=blocknum&&i<PEGGY_NUMCOEFFS; i++,block++)
        {
            key[0] = block, key[1] = 0;
            if ( (feed= ramkv777_read(&len,PEGS->accts->pricefeeds,key)) != 0 )
            {
                numprices = (uint32_t)(len / sizeof(len));
                for (j=0; j<numprices; j++)
                {
                    if ( feed[j] != 0 )
                    {
                        //int32_t den = 1;
                        //if ( PEGS->contracts[j]->name.baseid <= 8 )
                        //    den *= 5;
                        memset(&vote,0,sizeof(vote));
                        vote.pval = feed[j], vote.tolerance = (uint32_t)(((uint64_t)3 * PEGS->default_spread.Pval * feed[j])/PRICE_RESOLUTION);
                        PEGS->votes[j][nonz[j]++] = vote;
                        sums[j] += feed[j];
                    }
                }
                n++;
            }
        }
        for (j=0; j<numprices; j++)
        {
            if ( nonz[j] != 0 )
            {
                sums[j] /= nonz[j];
                price.Pval = sums[j];
            }
            aveprice = peggy_scaleprice(price,PEGS->contracts[j]->peggymils);
            if ( j > 0 )
            {
                T.blocknum = PEGS->numopreturns-1, T.blocktimestamp = blocktimestamp;
                price = peggy_priceconsensus(PEGS,T,PEGS->accts->pricefeeds->sha256.txid,j,PEGS->votes[j],nonz[j],0,0);
                price = peggy_scaleprice(price,PEGS->contracts[j]->peggymils);
                if ( Debuglevel > 2 )
                    fprintf(stderr,"%d %10s.{%14.6f} %7.4f%%\n",T.blocknum,PEGS->contracts[j]->name.name,Pval(&price),(fabs(Pval(&price)/Pval(&aveprice))-1)*100);
            }
        }
        if ( Debuglevel > 2 || blocktimestamp+600 > time(NULL) )
            printf("staked.%u n.%d i.%d blocknum.%d t%u | processed in %.3f microseconds | pricehash.%llx\n",stakedblock,n,i,blocknum,blocktimestamp,1000*(OS_milliseconds() - startmilli),(long long)PEGS->accts->pricefeeds->sha256.txid);
    }
    return(txind);
}

int64_t peggy_covercost(int32_t *nump,int64_t *posinterests,int64_t *neginterests,struct peggy_info *PEGS,struct peggy *PEG,struct price_resolution price,struct price_resolution shortprice)
{
    int32_t i,id; struct peggy_entry entry; struct peggy_unit *U; int64_t satoshis,covercost = 0;
    id = PEG->name.id;
    *posinterests = *neginterests = *nump = 0;
    for (i=0; i<PEGS->accts->numunits; i++)
    {
        U = &PEGS->accts->units[i];
        if ( (U->lock.peg == id || U->lock.peg == -id) && (PEG= peggy_findpeg(&entry,PEGS,U->lock.peg)) != 0 )
        {
            if ( U->estimated_interest > 0 )
                (*posinterests) += U->estimated_interest, (*nump)++;
            else if ( U->estimated_interest < 0 )
                (*neginterests) += U->estimated_interest, (*nump)++;
            if ( entry.polarity < 0 && U->lock.peg == -id )
            {
                satoshis = peggy_poolmainunits(&entry,-1,entry.polarity,price,shortprice,PEG->spread,PEG->pool.mainunitsize,U->lock.denom);
                covercost += satoshis;
                //printf("covercost price %.6f shortprice %.6f (%.8f - costbasis %.8f) %.8f -> %.8f price %.6f -> %.6f change %.8f est %.8f\n",Pval(&price),Pval(&shortprice),dstr(satoshis),dstr(U->costbasis),dstr(satoshis)-dstr(U->costbasis),dstr(covercost),dstr(U->costbasis)/Pval(&U->denomination),Pval(&shortprice),Pval(&shortprice)/(dstr(U->costbasis)/Pval(&U->denomination)),Pval(&price)*Pval(&price)*Pval(&U->denomination)*(Pval(&shortprice)/(dstr(U->costbasis)/Pval(&U->denomination))));
            }
        }
    }
    return(covercost);
}

double peggy_status(char **jsonstrp,struct peggy_info *PEGS,double *rates,uint32_t timestamp,char *name)
{
    int32_t j,rate,num,count,opporate,datenum,seconds,n = 0; struct price_resolution liability,liabilities,price,shortprice;
    int64_t pos,neg,possum,negsum,netbalance; struct tai t;
    double aprsum,depositsum,covercost,covercosts; struct peggy_entry entry; char numstr[64];
    struct peggy *PEG; cJSON *item,*array,*json = cJSON_CreateObject();
    array = cJSON_CreateArray();
    rates[0] = rates[1] = 0;
    for (pos=possum=neg=negsum=liabilities.Pval=liability.Pval=covercost=covercosts=depositsum=aprsum=count=0,j=1; j<PEGS->numpegs; j++)
    {
        item = cJSON_CreateObject();
        if ( (PEG= PEGS->contracts[j]) == 0 )
            continue;
        if ( (name != 0 && strcmp(PEG->name.name,name) != 0) || (PEG= peggy_find(&entry,PEGS,PEG->name.name,1)) == 0 )
            continue;
        rate = peggy_aprpercs(peggy_lockrate(&entry,PEGS,PEG,1,1));
        if ( (PEG= peggy_find(&entry,PEGS,PEG->name.name,-1)) == 0 )
            continue;
        opporate = peggy_aprpercs(peggy_lockrate(&entry,PEGS,PEG,1,1));
        rates[j*2] = (double)rate / 100.;
        rates[j*2+1] = (double)opporate / 100.;
        if ( rate != 0 )
            n++;
        if ( opporate != 0 )
            n++;
        aprsum += (rate + opporate);
        price = peggy_price(PEG,(timestamp - PEG->genesistime) /  PEGGY_MINUTE);
        shortprice = peggy_shortprice(PEG,PEG->price);
        liability.Pval = (PEG->pool.liability.num * price.Pval);
        liabilities.Pval += liability.Pval;
        covercost = peggy_covercost(&num,&pos,&neg,PEGS,PEG,price,shortprice);
        covercosts += covercost, possum += pos, negsum += neg, count += num;
        jaddstr(item,"base",PEG->name.name);
        jaddnum(item,"maxsupply",dstr(PEG->maxsupply));
        jaddnum(item,"maxnetbalance",dstr(PEG->maxnetbalance));
        jaddnum(item,"numunits",num);
        jaddnum(item,"pendinginterests",dstr(pos));
        jaddnum(item,"pendinginterest_fees",dstr(neg));
        
        price = peggy_scaleprice(price,PEG->peggymils);
        jaddnum(item,"price",Pval(&price));
        price = peggy_scaleprice(PEG->dayprice,PEG->peggymils);
        jaddnum(item,"dayprice",Pval(&price));
        jaddnum(item,"longunits",PEG->pool.liability.num);
        price = peggy_scaleprice(liability,PEG->peggymils);
        jaddnum(item,"liability",Pval(&price));
        
        jaddnum(item,"antiprice",Pval(&shortprice));
        jaddnum(item,"shortunits",PEG->pool.liability.numoppo);
        jaddnum(item,"covercost",dstr(covercost));
        
        jaddnum(item,"deposits",dstr(PEG->pool.funds.deposits));
        jaddnum(item,"margindeposits",dstr(PEG->pool.funds.margindeposits));
        jaddnum(item,"marginvalue",dstr(PEG->pool.funds.marginvalue));
        jaddnum(item,"basereserve",dstr(PEGS->basereserves[PEG->name.baseid].funds.deposits));
        
        sprintf(numstr,"%.2f%%",(double)rate/100.), jaddstr(item,"buy",numstr);
        sprintf(numstr,"%.2f%%",(double)opporate/100.), jaddstr(item,"sell",numstr);
        jaddi(array,item);
        depositsum += PEG->pool.funds.deposits;
    }
    jadd(json,"rates",array);
    datenum = OS_conv_unixtime(&t,&seconds,PEGS->genesistime);
    jaddnum(json,"start",(uint64_t)datenum*1000000 + (seconds/3600)*10000 + ((seconds%3600)/60)*100 + (seconds%60));
    datenum = OS_conv_unixtime(&t,&seconds,timestamp);
    jaddnum(json,"timestamp",(uint64_t)datenum*1000000 + (seconds/3600)*10000 + ((seconds%3600)/60)*100 + (seconds%60));
    jaddnum(json,"default_interest",(dailyrates[PEGS->interesttenths]));
    jaddnum(json,"posboost",PEGS->posboost);
    jaddnum(json,"negpenalty",PEGS->negpenalty);
    jaddnum(json,"numunits",PEGS->accts->numunits);
    jaddnum(json,"sumunits",count);
    jaddnum(json,"unitinterests",dstr(possum));
    jaddnum(json,"unitinterestfees",dstr(negsum));
    jaddnum(json,"netunitinterest",dstr(possum + negsum));
    jaddnum(json,"APR_reserves",dstr(PEGS->bank.APRfund_reserved));
    jaddnum(json,"APRfund",dstr(PEGS->bank.APRfund));
    jaddnum(json,"liabilities",Pval(&liabilities));
    jaddnum(json,"covercosts",dstr(covercosts));
    jaddnum(json,"depositsum",dstr(depositsum));
    jaddnum(json,"deposits",dstr(PEGS->bank.funds.deposits));
    jaddnum(json,"margindeposits",dstr(PEGS->bank.funds.margindeposits));
    jaddnum(json,"marginvalue",dstr(PEGS->bank.funds.marginvalue));
    jaddnum(json,"royalties",dstr(PEGS->bank.crypto777_royalty));
    jaddnum(json,"fees",dstr(PEGS->bank.privatebetfees));
    netbalance = (depositsum) + (PEGS->bank.funds.margindeposits) + (PEGS->bank.APRfund) - (PEGS->bank.APRfund_reserved) - SATOSHIDEN*(liabilities.Pval/PRICE_RESOLUTION) - (covercosts);
    jaddnum(json,"cashbalance",dstr(netbalance));
    netbalance = (depositsum) + (PEGS->bank.funds.marginvalue) + (PEGS->bank.APRfund) - (PEGS->bank.APRfund_reserved) - SATOSHIDEN*(liabilities.Pval/PRICE_RESOLUTION) - (covercosts);
    jaddnum(json,"netbalance",dstr(netbalance));
    if ( netbalance > PEGS->hwmbalance )
        PEGS->hwmbalance = netbalance;
    if ( netbalance < PEGS->worstbalance )
        PEGS->worstbalance = netbalance;
    if ( -(PEGS->hwmbalance - netbalance) < PEGS->maxdrawdown )
        PEGS->maxdrawdown = -(PEGS->hwmbalance - netbalance);
    jaddnum(json,"hwmbalance",dstr(PEGS->hwmbalance));
    jaddnum(json,"maxdrawdown",dstr(PEGS->maxdrawdown));
    jaddnum(json,"worstbalance",dstr(PEGS->worstbalance));
    if ( jsonstrp != 0 )
        *jsonstrp = jprint(json,1);
    if ( n != 0 )
        aprsum /= n;
    return(aprsum/100.);
}

char *peggyrates(uint32_t timestamp,char *name)
{
    char *jsonstr = 0; double rates[2 * PEGGY_MAXPEGS]; struct peggy_info *PEGS = opreturns_context("peggy",0);
    if ( timestamp == 0 )
        timestamp = (uint32_t)time(NULL);
    if ( PEGS != 0 )
        peggy_status(&jsonstr,PEGS,rates,timestamp,name);
    return(jsonstr);
}

void peggy_test()
{
    opreturns_init(0,(uint32_t)time(NULL),"PEGS");
    peggy_tx("{\"txtype\":0,\"outputs\":[{\"lockhash\":\"1259ec21d31a30898d7cd1609f80d9668b4778e3d97e941044b39f0c44d2e51b\",\"type\":1,\"denom\":10,\"margin\":0,\"minlockdays\":7,\"maxlockdays\":20,\"peg\":\"USD\"}],\"privkey\":\"1259ec21d31a30898d7cd1609f80d9668b4778e3d97e941044b39f0c44d2e51b\"}");
    getchar();
}
