//! Atomic swap loops and states
//! 
//! # A note on the terminology used
//! 
//! Alice = Buyer = Liquidity receiver = Taker  
//! ("*The process of an atomic swap begins with the person who makes the initial request — this is the liquidity receiver*" - Komodo Whitepaper).
//! 
//! Bob = Seller = Liquidity provider = Market maker  
//! ("*On the other side of the atomic swap, we have the liquidity provider — we call this person, Bob*" - Komodo Whitepaper).
//! 
//! # Algorithm updates
//! 
//! At the end of 2018 most UTXO coins have BIP65 (https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki).
//! The previous swap protocol discussions took place at 2015-2016 when there were just a few
//! projects that implemented CLTV opcode support:
//! https://bitcointalk.org/index.php?topic=1340621.msg13828271#msg13828271
//! https://bitcointalk.org/index.php?topic=1364951
//! So the Tier Nolan approach is a bit outdated, the main purpose was to allow swapping of a coin
//! that doesn't have CLTV at least as Alice side (as APayment is 2of2 multisig).
//! Nowadays the protocol can be simplified to the following (UTXO coins, BTC and forks):
//! 
//! 1. AFee: OP_DUP OP_HASH160 FEE_RMD160 OP_EQUALVERIFY OP_CHECKSIG
//! 
//! 2. BPayment:
//! OP_IF
//! <now + LOCKTIME*2> OP_CLTV OP_DROP <bob_pubB0> OP_CHECKSIG
//! OP_ELSE
//! OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <hash(bob_privN)> OP_EQUALVERIFY <alice_pubA0> OP_CHECKSIG
//! OP_ENDIF
//! 
//! 3. APayment:
//! OP_IF
//! <now + LOCKTIME> OP_CLTV OP_DROP <alice_pubA0> OP_CHECKSIG
//! OP_ELSE
//! OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <hash(bob_privN)> OP_EQUALVERIFY <bob_pubB0> OP_CHECKSIG
//! OP_ENDIF
//! 

// TODO: Rename Buyer to Taker everywhere (to avoid the ambiguity and reduce the cognitive load of using different termins in the code).
// TODO: Rename Seller to Maker everywhere.

/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
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
//
//  lp_swap.rs
//  marketmaker
//
use coins::{BoxedTx, ExchangeableCoin};
use coins::utxo::{coin_from_iguana_info};
use common::{bits256, dstr, Timeout};
use common::log::TagParam;
use common::mm_ctx::MmArc;
use crc::crc32;
use futures::{Future, Stream};
use gstuff::now_ms;
use std::time::Duration;

use crate::lp;

/// Includes the grace time we add to the "normal" timeouts
/// in order to give different and/or heavy communication channels a chance.
const BASIC_COMM_TIMEOUT: u64 = 90;

const SWAP_STATUS: &[&TagParam] = &[&"swap"];

fn send (ctx: &MmArc, to: bits256, subject: String, payload: Vec<u8>) -> Box<(dyn Stream<Item=(), Error=String> + 'static)> {
    let crc = crc32::checksum_ieee (&payload);  // Checksum here helps us visually verify the logistics between the Maker and Taker logs.
    log!("Sending '" (subject) "' (" (payload.len()) " bytes, crc " (crc) ")");
    peers::send (ctx, to, subject.as_bytes(), payload)
}

macro_rules! recv_ {
    ($swap: expr, $status: expr, $subj: expr, $desc: expr, $timeout_sec: expr, $ec: expr, $validator: block) => {{
        let recv_subject = fomat! (($subj) '@' ($swap.session));
        $status.status (SWAP_STATUS, &fomat! ("Waiting " ($desc) '…'));
        let validator = Box::new ($validator) as Box<Fn(&[u8]) -> Result<(), String> + Send>;
        let recv_f = peers::recv (&$swap.ctx, recv_subject.as_bytes(), Box::new ({
            // NB: `peers::recv` is generic and not responsible for handling errors.
            //     Here, on the other hand, we should know enough to log the errors.
            //     Also through the macros the logging statements will carry informative line numbers on them.
            move |payload: &[u8]| -> bool {
                match validator (payload) {
                    Ok (()) => true,
                    Err (err) => {
                        log! ("Error validating payload '" ($subj) "' (" (payload.len()) " bytes, crc " (crc32::checksum_ieee (payload)) "): " (err) ". Retrying…");
                        false
                    }
                }
            }
        }));
        let recv_f = Timeout::new (recv_f, Duration::from_secs (BASIC_COMM_TIMEOUT + $timeout_sec));
        let payload = match recv_f.wait() {
            Ok (p) => p,
            Err (err) => {
                $status.append (&fomat! (" Error: " (err)));
                // cf. https://github.com/artemii235/SuperNET/blob/99217fe947dab67c304a9490a3ae6b57ad587110/iguana/exchanges/LP_swap.c#L985
                return Err (($ec, fomat! ("Error getting '" (recv_subject) "': " (err))))
            }
        };
        $status.append (" Done.");
        payload
    }};
}

/*
#define TX_WAIT_TIMEOUT 1800 // hard to increase this without hitting protocol limits (2/4 hrs)

#ifndef NOTETOMIC
extern void *LP_eth_client;
#endif

uint32_t LP_atomic_locktime(char *base,char *rel)
{
    if ( strcmp(base,"BTC") == 0 && strcmp(rel,"BTC") == 0 )
        return(INSTANTDEX_LOCKTIME * 10);
    else if ( LP_is_slowcoin(base) > 0 || LP_is_slowcoin(rel) > 0 )
        return(INSTANTDEX_LOCKTIME * 4);
    else return(INSTANTDEX_LOCKTIME);
}

void basilisk_rawtx_purge(struct basilisk_rawtx *rawtx)
{
    if ( rawtx->vins != 0 )
        free_json(rawtx->vins), rawtx->vins = 0;
    //if ( rawtx->txbytes != 0 )
    //    free(rawtx->txbytes), rawtx->txbytes = 0;
}

void basilisk_swap_finished(struct basilisk_swap *swap)
{
    /*int32_t i;
    if ( (*swap).utxo != 0 && (*swap).sentflag == 0 )
    {
        LP_availableset((*swap).utxo);
        (*swap).utxo = 0;
        //LP_butxo_swapfields_set((*swap).utxo);
    }
    (*swap).I.finished = (uint32_t)time(NULL);*/
    if ( (*swap).I.finished == 0 )
    {
        if ( (*swap).I.iambob != 0 )
        {
            LP_availableset((*swap).bobdeposit.utxotxid,(*swap).bobdeposit.utxovout);
            LP_availableset((*swap).bobpayment.utxotxid,(*swap).bobpayment.utxovout);
        }
        else
        {
            LP_availableset((*swap).alicepayment.utxotxid,(*swap).alicepayment.utxovout);
            LP_availableset((*swap).myfee.utxotxid,(*swap).myfee.utxovout);
        }
    }
    // save to permanent storage
    basilisk_rawtx_purge(&(*swap).bobdeposit);
    basilisk_rawtx_purge(&(*swap).bobpayment);
    basilisk_rawtx_purge(&(*swap).alicepayment);
    basilisk_rawtx_purge(&(*swap).myfee);
    basilisk_rawtx_purge(&(*swap).otherfee);
    basilisk_rawtx_purge(&(*swap).aliceclaim);
    basilisk_rawtx_purge(&(*swap).alicespend);
    basilisk_rawtx_purge(&(*swap).bobreclaim);
    basilisk_rawtx_purge(&(*swap).bobspend);
    basilisk_rawtx_purge(&(*swap).bobrefund);
    basilisk_rawtx_purge(&(*swap).alicereclaim);
    /*for (i=0; i<(*swap).nummessages; i++)
        if ( (*swap).messages[i].data != 0 )
            free((*swap).messages[i].data), (*swap).messages[i].data = 0;
    free((*swap).messages), (*swap).messages = 0;
    (*swap).nummessages = 0;*/
    if ( (*swap).N.pair >= 0 )
        nn_close((*swap).N.pair), (*swap).N.pair = -1;
}

uint32_t basilisk_quoteid(struct basilisk_request *rp)
{
    struct basilisk_request R;
    R = *rp;
    R.unused = R.requestid = R.quoteid = R.DEXselector = 0;
    return(calc_crc32(0,(void *)&R,sizeof(R)));
}

uint32_t basilisk_requestid(struct basilisk_request *rp)
{
    struct basilisk_request R;
    R = *rp;
    R.requestid = R.quoteid = R.quotetime = R.DEXselector = 0;
    R.destamount = R.unused = 0;
    memset(R.desthash.bytes,0,sizeof(R.desthash.bytes));
    if ( 0 )
    {
        int32_t i;
        for (i=0; i<sizeof(R); i++)
            printf("%02x",((uint8_t *)&R)[i]);
        printf(" <- crc.%u\n",calc_crc32(0,(void *)&R,sizeof(R)));
        char str[65],str2[65]; printf("B REQUESTID: t.%u r.%u q.%u %s %.8f %s -> %s %.8f %s crc.%u q%u\n",R.timestamp,R.requestid,R.quoteid,R.src,dstr(R.srcamount),bits256_str(str,R.srchash),R.dest,dstr(R.destamount),bits256_str(str2,R.desthash),calc_crc32(0,(void *)&R,sizeof(R)),basilisk_quoteid(&R));
    }
    return(calc_crc32(0,(void *)&R,sizeof(R)));
}

int32_t LP_pubkeys_data(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,datalen = 0;
    datalen += iguana_rwnum(1,&data[datalen],sizeof((*swap).I.req.requestid),&(*swap).I.req.requestid);
    datalen += iguana_rwnum(1,&data[datalen],sizeof((*swap).I.req.quoteid),&(*swap).I.req.quoteid);
    data[datalen++] = (*swap).I.aliceconfirms;
    data[datalen++] = (*swap).I.bobconfirms;
    data[datalen++] = (*swap).I.alicemaxconfirms;
    data[datalen++] = (*swap).I.bobmaxconfirms;
    data[datalen++] = (*swap).I.otheristrusted;
    for (i=0; i<33; i++)
        data[datalen++] = (*swap).persistent_pubkey33[i];
    for (i=0; i<sizeof((*swap).deck)/sizeof((*swap).deck[0][0]); i++)
        datalen += iguana_rwnum(1,&data[datalen],sizeof((*swap).deck[i>>1][i&1]),&(*swap).deck[i>>1][i&1]);
    //printf("send >>>>>>>>> r.%u q.%u datalen.%d\n",(*swap).I.req.requestid,(*swap).I.req.quoteid,datalen);
    return(datalen);
}

int32_t LP_pubkeys_verify(struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    uint32_t requestid,quoteid; int32_t i,nonz=0,alicemaxconfirms,bobmaxconfirms,aliceconfirms,bobconfirms,len = 0; uint8_t other33[33];
    if ( datalen == sizeof((*swap).otherdeck)+38+sizeof(uint32_t)*2 )
    {
        len += iguana_rwnum(0,&data[len],sizeof(requestid),&requestid);
        len += iguana_rwnum(0,&data[len],sizeof(quoteid),&quoteid);
        if ( requestid != (*swap).I.req.requestid || quoteid != (*swap).I.req.quoteid )
        {
            printf("SWAP requestid.%u quoteid.%u mismatch received r.%u q.%u\n",(*swap).I.req.requestid,(*swap).I.req.quoteid,requestid,quoteid);
            return(-1);
        }
        aliceconfirms = data[len++];
        bobconfirms = data[len++];
        alicemaxconfirms = data[len++];
        bobmaxconfirms = data[len++];
        if ( aliceconfirms != (*swap).I.aliceconfirms || bobconfirms != (*swap).I.bobconfirms )
        {
            printf("MISMATCHED required confirms me.(%d %d) vs (%d %d) max.(%d %d) othermax.(%d %d)\n",(*swap).I.aliceconfirms,(*swap).I.bobconfirms,aliceconfirms,bobconfirms,(*swap).I.alicemaxconfirms,(*swap).I.bobmaxconfirms,alicemaxconfirms,bobmaxconfirms);
            if ( alicemaxconfirms > (*swap).I.alicemaxconfirms )
                alicemaxconfirms = (*swap).I.alicemaxconfirms;
            if ( bobmaxconfirms > (*swap).I.bobmaxconfirms )
                bobmaxconfirms = (*swap).I.bobmaxconfirms;
            if ( (*swap).I.aliceconfirms < aliceconfirms )
                (*swap).I.aliceconfirms = aliceconfirms;
            if ( (*swap).I.bobconfirms < bobconfirms )
                (*swap).I.bobconfirms = bobconfirms;
            if ( (*swap).I.aliceconfirms > (*swap).I.alicemaxconfirms || (*swap).I.bobconfirms > (*swap).I.bobmaxconfirms )
            {
                printf("numconfirms (%d %d) exceeds max (%d %d)\n",(*swap).I.aliceconfirms,(*swap).I.bobconfirms,(*swap).I.alicemaxconfirms,(*swap).I.bobmaxconfirms);
                return(-1);
            }
        }
        if ( ((*swap).I.otherstrust= data[len++]) != 0 )
        {
            if ( (*swap).I.otheristrusted != 0 )
            {
                (*swap).I.aliceconfirms = (*swap).I.bobconfirms = 0;
                printf("mutually trusted swap, adjust required confirms to: alice.%d bob.%d\n",(*swap).I.aliceconfirms,(*swap).I.bobconfirms);
            }
        }
        printf("NUMCONFIRMS for SWAP alice.%d bob.%d, otheristrusted.%d othertrusts.%d\n",(*swap).I.aliceconfirms,(*swap).I.bobconfirms,(*swap).I.otheristrusted,(*swap).I.otherstrust);
        for (i=0; i<33; i++)
            if ( (other33[i]= data[len++]) != 0 )
                nonz++;
        if ( nonz > 8 )
            memcpy((*swap).persistent_other33,other33,33);
        for (i=0; i<sizeof((*swap).otherdeck)/sizeof((*swap).otherdeck[0][0]); i++)
            len += iguana_rwnum(0,&data[len],sizeof((*swap).otherdeck[i>>1][i&1]),&(*swap).otherdeck[i>>1][i&1]);
        return(0);
    }
    printf("pubkeys verify size mismatch %d != %d\n",datalen,(int32_t)(sizeof((*swap).otherdeck)+38+sizeof(uint32_t)*2));
    return(-1);
}

int32_t LP_choosei_data(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,datalen; //char str[65];
    datalen = iguana_rwnum(1,data,sizeof((*swap).I.choosei),&(*swap).I.choosei);
    if ( (*swap).I.iambob != 0 )
    {
        for (i=0; i<32; i++)
            data[datalen++] = (*swap).I.pubB0.bytes[i];
        for (i=0; i<32; i++)
            data[datalen++] = (*swap).I.pubB1.bytes[i];
        //printf("SEND pubB0/1 %s\n",bits256_str(str,(*swap).I.pubB0));
    }
    else
    {
        for (i=0; i<32; i++)
            data[datalen++] = (*swap).I.pubA0.bytes[i];
        for (i=0; i<32; i++)
            data[datalen++] = (*swap).I.pubA1.bytes[i];
        //printf("SEND pubA0/1 %s\n",bits256_str(str,(*swap).I.pubA0));
    }
    return(datalen);
}

int32_t LP_choosei_verify(struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    int32_t otherchoosei=-1,i,len = 0; uint8_t pubkey33[33];
    if ( datalen == sizeof(otherchoosei)+sizeof(bits256)*2 )
    {
        len += iguana_rwnum(0,data,sizeof(otherchoosei),&otherchoosei);
        if ( otherchoosei >= 0 && otherchoosei < INSTANTDEX_DECKSIZE )
        {
            (*swap).I.otherchoosei = otherchoosei;
            if ( (*swap).I.iambob != 0 )
            {
                for (i=0; i<32; i++)
                    (*swap).I.pubA0.bytes[i] = data[len++];
                for (i=0; i<32; i++)
                    (*swap).I.pubA1.bytes[i] = data[len++];
                //printf("GOT pubA0/1 %s\n",bits256_str(str,(*swap).I.pubA0));
                (*swap).I.privBn = (*swap).privkeys[(*swap).I.otherchoosei];
                memset(&(*swap).privkeys[(*swap).I.otherchoosei],0,sizeof((*swap).privkeys[(*swap).I.otherchoosei]));
                revcalc_rmd160_sha256((*swap).I.secretBn,(*swap).I.privBn);//.bytes,sizeof((*swap).privBn));
                vcalc_sha256(0,(*swap).I.secretBn256,(*swap).I.privBn.bytes,sizeof((*swap).I.privBn));
                (*swap).I.pubBn = bitcoin_pubkey33((*swap).ctx,pubkey33,(*swap).I.privBn);
                //printf("set privBn.%s %s\n",bits256_str(str,(*swap).I.privBn),bits256_str(str2,*(bits256 *)(*swap).I.secretBn256));
                //basilisk_bobscripts_set(swap,1,1);
            }
            else
            {
                for (i=0; i<32; i++)
                    (*swap).I.pubB0.bytes[i] = data[len++];
                for (i=0; i<32; i++)
                    (*swap).I.pubB1.bytes[i] = data[len++];
                //printf("GOT pubB0/1 %s\n",bits256_str(str,(*swap).I.pubB0));
                (*swap).I.privAm = (*swap).privkeys[(*swap).I.otherchoosei];
                memset(&(*swap).privkeys[(*swap).I.otherchoosei],0,sizeof((*swap).privkeys[(*swap).I.otherchoosei]));
                revcalc_rmd160_sha256((*swap).I.secretAm,(*swap).I.privAm);//.bytes,sizeof((*swap).privAm));
                vcalc_sha256(0,(*swap).I.secretAm256,(*swap).I.privAm.bytes,sizeof((*swap).I.privAm));
                (*swap).I.pubAm = bitcoin_pubkey33((*swap).ctx,pubkey33,(*swap).I.privAm);
                //printf("set privAm.%s %s\n",bits256_str(str,(*swap).I.privAm),bits256_str(str2,*(bits256 *)(*swap).I.secretAm256));
                (*swap).bobdeposit.I.pubkey33[0] = 2;
                (*swap).bobpayment.I.pubkey33[0] = 2;
                for (i=0; i<32; i++)
                    (*swap).bobpayment.I.pubkey33[i+1] = (*swap).bobdeposit.I.pubkey33[i+1] = (*swap).I.pubA0.bytes[i];
                //printf("SET bobdeposit pubkey33.(02%s)\n",bits256_str(str,(*swap).I.pubA0));
                //basilisk_bobscripts_set(swap,0);
            }
            return(0);
        }
    }
    printf("illegal otherchoosei.%d datalen.%d vs %d\n",otherchoosei,datalen,(int32_t)(sizeof(otherchoosei)+sizeof(bits256)*2));
    return(-1);
}

int32_t LP_mostprivs_data(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,j,datalen;
    datalen = 0;
    for (i=0; i<sizeof((*swap).privkeys)/sizeof(*(*swap).privkeys); i++)
    {
        for (j=0; j<32; j++)
            data[datalen++] = (i == (*swap).I.otherchoosei) ? 0 : (*swap).privkeys[i].bytes[j];
    }
    if ( (*swap).I.iambob != 0 )
    {
        for (i=0; i<32; i++)
            data[datalen++] = (*swap).I.pubBn.bytes[i];
        for (i=0; i<20; i++)
            data[datalen++] = (*swap).I.secretBn[i];
        for (i=0; i<32; i++)
            data[datalen++] = (*swap).I.secretBn256[i];
    }
    else
    {
        for (i=0; i<32; i++)
            data[datalen++] = (*swap).I.pubAm.bytes[i];
        for (i=0; i<20; i++)
            data[datalen++] = (*swap).I.secretAm[i];
        for (i=0; i<32; i++)
            data[datalen++] = (*swap).I.secretAm256[i];
    }
    return(datalen);
}

int32_t basilisk_verify_pubpair(int32_t *wrongfirstbytep,struct basilisk_swap *swap,int32_t ind,uint8_t pub0,bits256 pubi,uint64_t txid)
{
    if ( pub0 != ((*swap).I.iambob ^ 1) + 0x02 )
    {
        (*wrongfirstbytep)++;
        printf("wrongfirstbyte[%d] %02x\n",ind,pub0);
        return(-1);
    }
    else if ( (*swap).otherdeck[ind][1] != pubi.txid )
    {
        printf("otherdeck[%d] priv ->pub mismatch %llx != %llx\n",ind,(long long)(*swap).otherdeck[ind][1],(long long)pubi.txid);
        return(-1);
    }
    else if ( (*swap).otherdeck[ind][0] != txid )
    {
        printf("otherdeck[%d] priv mismatch %llx != %llx\n",ind,(long long)(*swap).otherdeck[ind][0],(long long)txid);
        return(-1);
    }
    return(0);
}

int32_t basilisk_verify_privi(void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t j,wrongfirstbyte,len = 0; bits256 privkey,pubi; char str[65],str2[65]; uint8_t secret160[20],pubkey33[33]; uint64_t txid; struct basilisk_swap *swap = ptr;
    memset(privkey.bytes,0,sizeof(privkey));
    if ( datalen == sizeof(bits256) )
    {
        for (j=0; j<32; j++)
            privkey.bytes[j] = data[len++];
        revcalc_rmd160_sha256(secret160,privkey);//.bytes,sizeof(privkey));
        memcpy(&txid,secret160,sizeof(txid));
        pubi = bitcoin_pubkey33((*swap).ctx,pubkey33,privkey);
        if ( basilisk_verify_pubpair(&wrongfirstbyte,swap,(*swap).I.choosei,pubkey33[0],pubi,txid) == 0 )
        {
            if ( (*swap).I.iambob != 0 )
            {
                (*swap).I.privAm = privkey;
                vcalc_sha256(0,(*swap).I.secretAm256,privkey.bytes,sizeof(privkey));
                printf("set privAm.%s %s\n",bits256_str(str,(*swap).I.privAm),bits256_str(str2,*(bits256 *)(*swap).I.secretAm256));
                basilisk_bobscripts_set(swap,0,1);
            }
            else
            {
                (*swap).I.privBn = privkey;
                vcalc_sha256(0,(*swap).I.secretBn256,privkey.bytes,sizeof(privkey));
                printf("set privBn.%s %s\n",bits256_str(str,(*swap).I.privBn),bits256_str(str2,*(bits256 *)(*swap).I.secretBn256));
            }
            basilisk_dontforget_update(swap,0);
            char str[65]; printf("privi verified.(%s)\n",bits256_str(str,privkey));
            return(0);
        } else printf("pubpair doesnt verify privi\n");
    } else printf("verify privi size mismatch %d != %d\n",datalen,(int32_t)sizeof(bits256));
    return(-1);
}

int32_t LP_mostprivs_verify(struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    int32_t i,j,wrongfirstbyte=0,errs=0,len = 0; bits256 otherpriv,pubi; uint8_t secret160[20],otherpubkey[33]; uint64_t txid;
    //printf("verify privkeys choosei.%d otherchoosei.%d datalen.%d vs %d\n",(*swap).choosei,(*swap).otherchoosei,datalen,(int32_t)sizeof((*swap).privkeys)+20+32);
    memset(otherpriv.bytes,0,sizeof(otherpriv));
    if ( (*swap).I.cutverified == 0 && (*swap).I.otherchoosei >= 0 && datalen == sizeof((*swap).privkeys)+20+2*32 )
    {
        for (i=errs=0; i<sizeof((*swap).privkeys)/sizeof(*(*swap).privkeys); i++)
        {
            for (j=0; j<32; j++)
                otherpriv.bytes[j] = data[len++];
            if ( i != (*swap).I.choosei )
            {
                pubi = bitcoin_pubkey33((*swap).ctx,otherpubkey,otherpriv);
                revcalc_rmd160_sha256(secret160,otherpriv);//.bytes,sizeof(otherpriv));
                memcpy(&txid,secret160,sizeof(txid));
                errs += basilisk_verify_pubpair(&wrongfirstbyte,swap,i,otherpubkey[0],pubi,txid);
            }
        }
        if ( errs == 0 && wrongfirstbyte == 0 )
        {
            (*swap).I.cutverified = 1, printf("CUT VERIFIED\n");
            if ( (*swap).I.iambob != 0 )
            {
                for (i=0; i<32; i++)
                    (*swap).I.pubAm.bytes[i] = data[len++];
                for (i=0; i<20; i++)
                    (*swap).I.secretAm[i] = data[len++];
                for (i=0; i<32; i++)
                    (*swap).I.secretAm256[i] = data[len++];
                //basilisk_bobscripts_set(swap,1,1);
            }
            else
            {
                for (i=0; i<32; i++)
                    (*swap).I.pubBn.bytes[i] = data[len++];
                for (i=0; i<20; i++)
                    (*swap).I.secretBn[i] = data[len++];
                for (i=0; i<32; i++)
                    (*swap).I.secretBn256[i] = data[len++];
                //basilisk_bobscripts_set(swap,0);
            }
        } else printf("failed verification: wrong firstbyte.%d errs.%d\n",wrongfirstbyte,errs);
    }
    //printf("privkeys errs.%d wrongfirstbyte.%d\n",errs,wrongfirstbyte);
    return(errs);
}

int32_t LP_waitfor(int32_t pairsock,struct basilisk_swap *swap,int32_t timeout,int32_t (*verify)(struct basilisk_swap *swap,uint8_t *data,int32_t datalen))
{
    struct nn_pollfd pfd; void *data; int32_t datalen,retval = -1; uint32_t expiration = (uint32_t)time(NULL) + timeout;
    while ( time(NULL) < expiration )
    {
        memset(&pfd,0,sizeof(pfd));
        pfd.fd = pairsock;
        pfd.events = NN_POLLIN;
        if ( nn_poll(&pfd,1,1) > 0 )
        {
            //printf("start wait\n");
            if ( (datalen= nn_recv(pairsock,&data,NN_MSG,0)) >= 0 )
            {
                //printf("wait for got.%d\n",datalen);
                retval = (*verify)(swap,data,datalen);
                (*swap).received = (uint32_t)time(NULL);
                nn_freemsg(data);
                //printf("retval.%d\n",retval);
                return(retval);
            } // else printf("error nn_recv\n");
        }
    }
    printf("waitfor timedout aliceid.%llu requestid.%u quoteid.%u\n",(long long)(*swap).aliceid,(*swap).I.req.requestid,(*swap).I.req.quoteid);
    return(retval);
}

int32_t swap_nn_send(int32_t sock,uint8_t *data,int32_t datalen,uint32_t flags,int32_t timeout)
{
    struct nn_pollfd pfd; int32_t i;
    for (i=0; i<timeout*1000; i++)
    {
        memset(&pfd,0,sizeof(pfd));
        pfd.fd = sock;
        pfd.events = NN_POLLOUT;
        if ( nn_poll(&pfd,1,1) > 0 )
            return(nn_send(sock,data,datalen,flags));
        usleep(1000);
    }
    return(-1);
}

int32_t LP_waitsend(char *statename,int32_t timeout,int32_t pairsock,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen,int32_t (*verify)(struct basilisk_swap *swap,uint8_t *data,int32_t datalen),int32_t (*datagen)(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen))
{
    int32_t datalen,sendlen,retval = -1;
    //printf("waitsend.%s timeout.%d\n",statename,timeout);
    if ( LP_waitfor(pairsock,swap,timeout,verify) == 0 )
    {
        //printf("waited for %s\n",statename);
        if ( (datalen= (*datagen)(swap,data,maxlen)) > 0 )
        {
            if ( (sendlen= swap_nn_send(pairsock,data,datalen,0,timeout)) == datalen )
            {
                //printf("sent.%d after waitfor.%s\n",sendlen,statename);
                retval = 0;
            } else printf("send %s error\n",statename);
        } else printf("%s datagen no data\n",statename);
    } else printf("didnt get valid data after %d\n",timeout);
    return(retval);
}

int32_t LP_sendwait(char *statename,int32_t timeout,int32_t pairsock,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen,int32_t (*verify)(struct basilisk_swap *swap,uint8_t *data,int32_t datalen),int32_t (*datagen)(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen))
{
    int32_t datalen,sendlen,retval = -1;
    //printf("sendwait.%s\n",statename);
    if ( (datalen= (*datagen)(swap,data,maxlen)) > 0 )
    {
        //printf("generated %d for %s, timeout.%d\n",datalen,statename,timeout);
        if ( (sendlen= swap_nn_send(pairsock,data,datalen,0,timeout)) == datalen )
        {
            //printf("sendwait.%s sent %d\n",statename,sendlen);
            if ( LP_waitfor(pairsock,swap,timeout,verify) == 0 )
            {
                //printf("waited! sendwait.%s sent %d\n",statename,sendlen);
                retval = 0;
            } else printf("didnt get %s\n",statename);
        } else printf("send %s error\n",statename);
    } else printf("no datagen for %s\n",statename);
    return(retval);
}

void LP_swapsfp_update(uint32_t requestid,uint32_t quoteid)
{
    static FILE *swapsfp;
    portable_mutex_lock(&LP_listmutex);
    if ( swapsfp == 0 )
    {
        char fname[512];
        sprintf(fname,"%s/SWAPS/list",GLOBAL_DBDIR), OS_compatible_path(fname);
        if ( (swapsfp= fopen(fname,"rb+")) == 0 )
            swapsfp = fopen(fname,"wb+");
        else fseek(swapsfp,0,SEEK_END);
        //printf("LIST fp.%p\n",swapsfp);
    }
    if ( swapsfp != 0 )
    {
        fwrite(&requestid,1,sizeof(requestid),swapsfp);
        fwrite(&quoteid,1,sizeof(quoteid),swapsfp);
        fflush(swapsfp);
    }
    portable_mutex_unlock(&LP_listmutex);
}

struct basilisk_rawtx *LP_swapdata_rawtx(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx)
{
    if ( rawtx->I.datalen != 0 && rawtx->I.datalen <= maxlen )
    {
        memcpy(data,rawtx->txbytes,rawtx->I.datalen);
        return(rawtx);
    }
    printf("swapdata rawtx has null txbytes\n");
    return(0);
}

int32_t LP_rawtx_spendscript(struct basilisk_swap *swap,int32_t height,struct basilisk_rawtx *rawtx,int32_t v,uint8_t *recvbuf,int32_t recvlen,int32_t suppress_pubkeys)
{
    bits256 otherhash,myhash,txid; int64_t txfee,val; int32_t i,offset=0,datalen=0,retval=-1,hexlen,n; uint8_t *data; cJSON *txobj,*skey,*vouts,*vout; char *hexstr,bobstr[65],alicestr[65],redeemaddr[64],checkaddr[64]; uint32_t quoteid,msgbits; struct iguana_info *coin;
    LP_etomicsymbol(bobstr,(*swap).I.bobtomic,(*swap).I.bobstr);
    LP_etomicsymbol(alicestr,(*swap).I.alicetomic,(*swap).I.alicestr);
    if ( (coin= LP_coinfind(rawtx->symbol)) == 0 )
    {
        printf("LP_rawtx_spendscript couldnt find coin.(%s)\n",rawtx->symbol);
        return(-1);
    }
    for (i=0; i<32; i++)
        otherhash.bytes[i] = recvbuf[offset++];
    for (i=0; i<32; i++)
        myhash.bytes[i] = recvbuf[offset++];

    offset += iguana_rwnum(0,&recvbuf[offset],sizeof(quoteid),&quoteid);
    offset += iguana_rwnum(0,&recvbuf[offset],sizeof(msgbits),&msgbits);
    datalen = recvbuf[offset++];
    datalen += (int32_t)recvbuf[offset++] << 8;
    if ( datalen > 1024 )
    {
        printf("LP_rawtx_spendscript %s datalen.%d too big\n",rawtx->name,datalen);
        return(-1);
    }
    rawtx->I.redeemlen = recvbuf[offset++];
#ifndef NOTETOMIC
    uint8arrayToHex(rawtx->I.ethTxid, &recvbuf[offset], 32);
    printf("ETH txid received: %s\n", rawtx->I.ethTxid);
#endif
    offset += 32;
    data = &recvbuf[offset];
    if ( rawtx->I.redeemlen > 0 && rawtx->I.redeemlen < 0x100 )
    {
        memcpy(rawtx->redeemscript,&data[datalen],rawtx->I.redeemlen);
        //for (i=0; i<rawtx->I.redeemlen; i++)
        //    printf("%02x",rawtx->redeemscript[i]);
        bitcoin_address(coin->symbol,redeemaddr,coin->taddr,coin->p2shtype,rawtx->redeemscript,rawtx->I.redeemlen);
        //printf(" received redeemscript.(%s) %s taddr.%d\n",redeemaddr,coin->symbol,coin->taddr);
        LP_swap_coinaddr(coin,checkaddr,0,data,datalen,0);
        if ( strcmp(redeemaddr,checkaddr) != 0 )
        {
            printf("REDEEMADDR MISMATCH??? %s != %s\n",redeemaddr,checkaddr);
            return(-1);
        }
    }
    //printf("recvlen.%d datalen.%d redeemlen.%d\n",recvlen,datalen,rawtx->redeemlen);
    if ( rawtx->I.datalen == 0 )
    {
        //for (i=0; i<datalen; i++)
        //    printf("%02x",data[i]);
        //printf(" <- received\n");
        memcpy(rawtx->txbytes,data,datalen);
        rawtx->I.datalen = datalen;
    }
    else if ( datalen != rawtx->I.datalen || memcmp(rawtx->txbytes,data,datalen) != 0 )
    {
        for (i=0; i<rawtx->I.datalen; i++)
            printf("%02x",rawtx->txbytes[i]);
        printf(" <- rawtx\n");
        printf("%s rawtx data compare error, len %d vs %d <<<<<<<<<< warning\n",rawtx->name,rawtx->I.datalen,datalen);
        return(-1);
    }


    if ( recvlen != datalen+rawtx->I.redeemlen + 107 )
        printf("RECVLEN %d != %d + %d\n",recvlen,datalen,rawtx->I.redeemlen);
    txid = bits256_calctxid(coin->symbol,data,datalen);
    //char str[65]; printf("rawtx.%s txid %s\n",rawtx->name,bits256_str(str,txid));
    if ( bits256_cmp(txid,rawtx->I.actualtxid) != 0 && bits256_nonz(rawtx->I.actualtxid) == 0 )
        rawtx->I.actualtxid = txid;
    if ( (txobj= bitcoin_data2json(coin->symbol,coin->taddr,coin->pubtype,coin->p2shtype,coin->isPoS,height,&rawtx->I.signedtxid,&rawtx->msgtx,rawtx->extraspace,sizeof(rawtx->extraspace),data,datalen,0,suppress_pubkeys,coin->zcash)) != 0 )
    {
        rawtx->I.actualtxid = rawtx->I.signedtxid;
        rawtx->I.locktime = rawtx->msgtx.lock_time;
        if ( (vouts= jarray(&n,txobj,"vout")) != 0 && v < n )
        {
            vout = jitem(vouts,v);
            if ( strcmp("BTC",coin->symbol) == 0 && rawtx == &(*swap).otherfee )
                txfee = LP_MIN_TXFEE;
            else
            {
                if ( strcmp(coin->symbol,bobstr) == 0 )
                    txfee = (*swap).I.Btxfee;
                else if ( strcmp(coin->symbol,alicestr) == 0 )
                    txfee = (*swap).I.Atxfee;
                else txfee = LP_MIN_TXFEE;
            }
            if ( rawtx->I.amount > 2*txfee)
                val = rawtx->I.amount-2*txfee;
            else val = 1;
            if ( j64bits(vout,"satoshis") >= val && (skey= jobj(vout,"scriptPubKey")) != 0 && (hexstr= jstr(skey,"hex")) != 0 )
            {
                if ( (hexlen= (int32_t)strlen(hexstr) >> 1) < sizeof(rawtx->spendscript) )
                {
                    decode_hex(rawtx->spendscript,hexlen,hexstr);
                    rawtx->I.spendlen = hexlen;
                    //if ( swap != 0 )
                    //    basilisk_txlog((*swap).myinfoptr,swap,rawtx,-1); // bobdeposit, bobpayment or alicepayment
                    retval = 0;
                    if ( rawtx == &(*swap).otherfee )
                    {
                        LP_swap_coinaddr(coin,rawtx->p2shaddr,0,data,datalen,0);
                        //printf("got %s txid.%s (%s) -> %s\n",rawtx->name,bits256_str(str,rawtx->I.signedtxid),jprint(txobj,0),rawtx->p2shaddr);
                    } else bitcoin_address(coin->symbol,rawtx->p2shaddr,coin->taddr,coin->p2shtype,rawtx->spendscript,hexlen);
                }
            } else printf("%s satoshis %.8f ERROR.(%s) txfees.[%.8f %.8f: %.8f] amount.%.8f -> %.8f\n",rawtx->name,dstr(j64bits(vout,"satoshis")),jprint(txobj,0),dstr((*swap).I.Atxfee),dstr((*swap).I.Btxfee),dstr(txfee),dstr(rawtx->I.amount),dstr(rawtx->I.amount)-dstr(txfee));
        }
        free_json(txobj);
    }
    return(retval);
}

uint32_t LP_swapdata_rawtxsend(int32_t pairsock,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx,uint32_t nextbits,int32_t suppress_swapsend)
{
    uint8_t sendbuf[32768]; int32_t sendlen,retval = -1;
    if ( LP_swapdata_rawtx(swap,data,maxlen,rawtx) != 0 )
    {
        if ( bits256_nonz(rawtx->I.signedtxid) != 0 && bits256_nonz(rawtx->I.actualtxid) == 0 )
        {
            basilisk_dontforget_update(swap,rawtx);
            rawtx->I.actualtxid = LP_broadcast_tx(rawtx->name,rawtx->symbol,rawtx->txbytes,rawtx->I.datalen);
            if ( bits256_cmp(rawtx->I.actualtxid,rawtx->I.signedtxid) != 0 )
            {
                char str[65],str2[65];
                printf("%s rawtxsend.[%d] %s vs %s\n",rawtx->name,rawtx->I.datalen,bits256_str(str,rawtx->I.signedtxid),bits256_str(str2,rawtx->I.actualtxid));
                if ( bits256_nonz(rawtx->I.signedtxid) != 0 )
                    rawtx->I.actualtxid = rawtx->I.signedtxid;
                else rawtx->I.signedtxid = rawtx->I.actualtxid;
            }
            if ( bits256_nonz(rawtx->I.actualtxid) != 0 && msgbits != 0 )
            {
#ifndef NOTETOMIC
                if ( (*swap).I.bobtomic[0] != 0 || (*swap).I.alicetomic[0] != 0 )
                {
                    char *ethTxId = sendEthTx(swap, rawtx);
                    if (ethTxId != NULL) {
                        strcpy(rawtx->I.ethTxid, ethTxId);
                        free(ethTxId);
                    } else {
                        printf("Error sending ETH tx\n");
                        return(-1);
                    }
                }
#endif
                sendlen = 0;
                sendbuf[sendlen++] = rawtx->I.datalen & 0xff;
                sendbuf[sendlen++] = (rawtx->I.datalen >> 8) & 0xff;
                sendbuf[sendlen++] = rawtx->I.redeemlen;
                if ( rawtx->I.ethTxid[0] != 0 && strlen(rawtx->I.ethTxid) == 66  )
                {
                    uint8_t ethTxidBytes[32];
                    // ETH txid always starts with 0x
                    decode_hex(ethTxidBytes, 32, rawtx->I.ethTxid + 2);
                    memcpy(&sendbuf[sendlen], ethTxidBytes, 32);
                }
                else
                {
                    // fill with zero bytes to always have fixed message size
                    memset(&sendbuf[sendlen], 0, 32);
                }
                sendlen += 32;
                //int32_t z; for (z=0; z<rawtx->I.datalen; z++) printf("%02x",rawtx->txbytes[z]); printf(" >>>>>>> send.%d %s\n",rawtx->I.datalen,rawtx->name);
                //printf("datalen.%d redeemlen.%d\n",rawtx->I.datalen,rawtx->I.redeemlen);
                memcpy(&sendbuf[sendlen],rawtx->txbytes,rawtx->I.datalen), sendlen += rawtx->I.datalen;
                if ( rawtx->I.redeemlen > 0 && rawtx->I.redeemlen < 0x100 )
                {
                    memcpy(&sendbuf[sendlen],rawtx->redeemscript,rawtx->I.redeemlen);
                    sendlen += rawtx->I.redeemlen;
                }

                basilisk_dontforget_update(swap,rawtx);
                //printf("sendlen.%d datalen.%d redeemlen.%d\n",sendlen,rawtx->datalen,rawtx->redeemlen);
                if ( suppress_swapsend == 0 )
                {
                    retval = LP_swapsend(pairsock,swap,msgbits,sendbuf,sendlen,nextbits,rawtx->I.crcs);
                    if ( LP_waitmempool(rawtx->symbol,rawtx->I.destaddr,rawtx->I.signedtxid,0,LP_SWAPSTEP_TIMEOUT*10) < 0 )
                    {
                        char str[65]; printf("failed to find %s %s %s in the mempool?\n",rawtx->name,rawtx->I.destaddr,bits256_str(str,rawtx->I.actualtxid));
                        retval = -1;
                    }
                    return(retval);
                }
                else
                {
                    printf("suppress swapsend %x\n",msgbits);
                    return(0);
                }
            }
        }
        return(nextbits);
    } //else if ( (*swap).I.iambob == 0 )
        printf("error from basilisk_swapdata_rawtx.%s %p len.%d\n",rawtx->name,rawtx->txbytes,rawtx->I.datalen);
    return(0);
}

uint32_t LP_swapwait(uint32_t expiration,uint32_t requestid,uint32_t quoteid,int32_t duration,int32_t sleeptime)
{
    char *retstr; uint32_t finished = 0; cJSON *retjson=0;
    if ( sleeptime != 0 )
    {
        printf("wait %d:%d for SWAP.(r%u/q%u) to complete\n",duration,sleeptime,requestid,quoteid);
        sleep(sleeptime/3);
    }
    while ( expiration == 0 || time(NULL) < expiration )
    {
        if ( (retstr= basilisk_swapentry(0,requestid,quoteid,1)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( jstr(retjson,"status") != 0 && strcmp(jstr(retjson,"status"),"finished") == 0 )
                {
                    finished = (uint32_t)time(NULL);
                    free(retstr), retstr = 0;
                    break;
                }
                else if ( expiration != 0 && time(NULL) > expiration )
                    printf("NOT FINISHED.(%s)\n",jprint(retjson,0));
                free_json(retjson), retjson = 0;
            }
            free(retstr);
        }
        if ( sleeptime != 0 )
            sleep(sleeptime);
        if ( duration < 0 )
            break;
    }
    if ( retjson != 0 )
    {
        free_json(retjson);
        if ( (retstr= basilisk_swapentry(0,requestid,quoteid,1)) != 0 )
        {
            printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>\nSWAP completed! %u-%u %s\n",requestid,quoteid,retstr);
            free(retstr);
        }
        return(finished);
    }
    else
    {
        if ( expiration != 0 && time(NULL) > expiration )
            printf("\nSWAP did not complete! %u-%u %s\n",requestid,quoteid,jprint(retjson,0));
        if ( duration > 0 )
            LP_pendswap_add(expiration,requestid,quoteid);
        return(0);
    }
}

int32_t LP_calc_waittimeout(char *symbol)
{
    int32_t waittimeout = TX_WAIT_TIMEOUT;
    if ( strcmp(symbol,"BTC") == 0 )
        waittimeout *= 8;
    else if ( LP_is_slowcoin(symbol) != 0 )
        waittimeout *= 4;
    return(waittimeout);
}
*/
struct Swap (*mut lp::basilisk_swap);
// We need to share the `swap` with `validator` callbacks running on the `peers` loop.
// TODO: Replace `Swap` with a truly thread-safe Rust version of the struct.
unsafe impl Send for Swap {}

// AG: The explicit state here constitutes an early and experimental design aimed towards
// serializable and resumable SWAP. The `AtomicSwapState` is essentially a list of `goto` labels,
// allowing us to jump anywhere in the SWAP loops.
// Given that the SWAP is the centerpiece of this software
// and improving the quality of the code here might reap us some noticeable benefits,
// we should probably take another go at designing this, as discussed in
// https://github.com/artemii235/SuperNET/commit/d66ab944bfd8c5e8fb17f1d36ac303797156b88e#r31674919
// In particular,
// 1) I'd like the design to emerge from a realistic save-resume scenario(s),
// that is, where the saves and resumes actually happen, at least from under a unit test;
// 2) I'd like the transitions to be implemented as pure functions,
// cf. https://github.com/artemii235/SuperNET/tree/mm2-dice/mm2src#purely-functional-core
// 3) Preferably untangling them from the portions of the shared state that are not relevant to them,
// that is, avoiding the "big ball of mud" and "object orgy" antipatterns of a single shared state structure.

/// Contains all available states of Atomic swap of both sides (seller and buyer)
enum AtomicSwapState {
    PubkeyExchange,
    SendBuyerFee,
    WaitBuyerFee {sending_f: Box<Stream<Item=(), Error=String>>},
    SendSellerPayment,
    WaitSellerPayment {sending_f: Box<Stream<Item=(), Error=String>>},
    SendBuyerPayment,
    WaitBuyerPayment {sending_f: Box<Stream<Item=(), Error=String>>},
    SpendBuyerPayment,
    WaitBuyerPaymentSpent {sending_f: Box<Stream<Item=(), Error=String>>},
    SpendSellerPayment,
    RefundBuyerPayment,
    RefundSellerPayment,
}

pub struct AtomicSwap {
    basilisk_swap: *mut lp::basilisk_swap,
    ctx: MmArc,
    state: Option<AtomicSwapState>,
    buffer: Vec<u8>,
    buffer_len: u64,
    buyer_coin: Box<dyn ExchangeableCoin>,
    seller_coin: Box<dyn ExchangeableCoin>,
    buyer_payment: Option<BoxedTx>,
    seller_payment: Option<BoxedTx>,
    buyer: bits256,
    seller: bits256,
    session: String,
    secret: Vec<u8>,
}

impl AtomicSwap {
    pub unsafe fn new(
        basilisk_swap: *mut lp::basilisk_swap,
        ctx: MmArc,
        buyer: bits256,
        seller: bits256,
        session: String
    ) -> Result<AtomicSwap, String> {
        let alice_coin_ptr = lp::LP_coinfind((*basilisk_swap).I.alicestr.as_mut_ptr());
        let alice_coin = try_s!(coin_from_iguana_info(alice_coin_ptr));
        let bob_coin_ptr = lp::LP_coinfind((*basilisk_swap).I.bobstr.as_mut_ptr());
        let bob_coin = try_s!(coin_from_iguana_info(bob_coin_ptr));

        Ok(AtomicSwap {
            basilisk_swap,
            ctx,
            state: Some (AtomicSwapState::PubkeyExchange),
            buffer_len: 2 * 1024 * 1024,
            buffer: vec![0; 2 * 1024 * 1024],
            buyer_coin: alice_coin,
            seller_coin: bob_coin,
            buyer_payment: None,
            seller_payment: None,
            buyer,
            seller,
            session,
            secret: vec![]
        })
    }
}

pub fn seller_swap_loop(swap: &mut AtomicSwap) -> Result<(), (i32, String)> {
    // NB: We can communicate the SWAP status to UI progress indicators via documented tags,
    // cf. https://github.com/artemii235/SuperNET/commit/d66ab944bfd8c5e8fb17f1d36ac303797156b88e#r31676734
    // (but first we need to establish a use case for such indication with the UI guys,
    //  in order to avoid premature throw-away design, cf. https://www.agilealliance.org/glossary/simple-design).
    let mut status = swap.ctx.log.status_handle();

    macro_rules! send {
        ($subj: expr, $slice: expr) => {
            send (&swap.ctx, swap.buyer, fomat!(($subj) '@' (swap.session)), $slice.into())
        };
    }
    macro_rules! recv {
        ($subj: expr, $desc: expr, $timeout_sec: expr, $ec: expr, $validator: block) => {
            recv_! (swap, status, $subj, $desc, $timeout_sec, $ec, $validator)
        };
        // Use this form if there's a sending future to terminate upon receiving the answer.
        ($sending_f: ident, $subj: expr, $desc: expr, $timeout_sec: expr, $ec: expr, $validator: block) => {{
            let payload = recv_! (swap, status, $subj, $desc, $timeout_sec, $ec, $validator);
            drop ($sending_f);
            payload
        }};
    }
    // Note that `err!` updates the current `status`. We assume there is no blind spots in the `status`.
    // NB: If we want to replace the `err!` with `?` then we should move the `status` ownership to the call site.
    //     (Which IMHO would break the status code flow and encapsulation a little).
    macro_rules! err {
        ($ec: expr, $($msg: tt)+) => {{
            let mut msg = fomat! (' ' $($msg)+);
            status.append (&msg);
            msg.remove (0);
            return Err (($ec, msg))
        }};
    }

    loop {
        let next_state = match unwrap!(swap.state.take()) {
            AtomicSwapState::PubkeyExchange => unsafe {
                let _ = recv!("pubkeys", "for Taker public keys", 90, -2000, {
                    let swap = Swap(swap.basilisk_swap);
                    move |payload: &[u8]| {
                        let rc = lp::LP_pubkeys_verify(swap.0, payload.as_ptr() as *mut u8, payload.len() as i32);
                        if rc == 0 {Ok(())} else {ERR!("LP_pubkeys_verify != 0: {}", rc)}
                    }
                });

                let rc = lp::LP_pubkeys_data(swap.basilisk_swap, swap.buffer.as_mut_ptr(), swap.buffer_len as i32);
                if rc <= 0 {err!(-2000, "LP_pubkeys_data <= 0: "(rc))}
                let sending_f = send!("pubkeys-reply", &swap.buffer[.. rc as usize]);

                // NB: As of now `LP_choosei_verify` has side-effects and doesn't fit the `validator` very well.
                //     cf. https://discordapp.com/channels/@me/472006550194618379/521651286861414410
                //     (Preferred refactoring here might be to separate choosei parsing and verification from updating the swap,
                //      performing the parsing and verification in the `validator`).
                // TODO: The description here is my guess, should verify what really happens and how to describe it to the user.
                let payload = recv!(sending_f, "choosei", "for the Taker to pick the key", 30, -2001, {|_: &[u8]| Ok(())});
                let rc = lp::LP_choosei_verify(swap.basilisk_swap, payload.as_ptr() as *mut u8, payload.len() as i32);
                if rc != 0 {err!(-2001, "LP_choosei_verify!= 0: "(rc))}

                let rc = lp::LP_choosei_data(swap.basilisk_swap, swap.buffer.as_mut_ptr(), swap.buffer_len as i32);
                if rc <= 0 {err!(-2001, "LP_choosei_data <= 0: "(rc))}
                let sending_f = send!("choosei-reply", &swap.buffer[.. rc as usize]);

                // TODO: Replace "mostpriv" with a human-readable label of what it is we're waiting for.
                let _ = recv!(sending_f, "mostprivs", "for \"mostpriv\"", 30, -2002, {
                    let swap = Swap(swap.basilisk_swap);
                    move |payload: &[u8]| {
                        let rc = lp::LP_mostprivs_verify(swap.0, payload.as_ptr() as *mut u8, payload.len() as i32);
                        if rc == 0 {Ok(())} else {ERR!("LP_mostprivs_verify != 0: {}", rc)}
                    }
                });

                let rc = lp::LP_mostprivs_data(swap.basilisk_swap, swap.buffer.as_mut_ptr(), swap.buffer_len as i32);
                if rc <= 0 {err!(-2002, "LP_mostprivs_data <= 0: "(rc))}
                let sending_f = send!("mostprivs-reply", &swap.buffer[.. rc as usize]);

                AtomicSwapState::WaitBuyerFee {sending_f}
            },
            AtomicSwapState::WaitBuyerFee {sending_f} => {
                let payload = recv!(sending_f, "buyer-fee", "for Taker fee", 600, -2003, {|_: &[u8]| Ok(())});
                let _buyer_fee = match swap.buyer_coin.tx_from_raw_bytes(&payload) {
                    Ok(tx) => tx,
                    Err(err) => err!(-2003, "!tx_from_raw_bytes: "(err)),
                };

                AtomicSwapState::SendSellerPayment
            },
            AtomicSwapState::SendSellerPayment => unsafe {
                let payment_amount = dstr((*swap.basilisk_swap).I.bobsatoshis);

                let payment_fut = swap.seller_coin.send_seller_payment(
                    (now_ms() / 1000) as u32 + 2000,
                    &(*swap.basilisk_swap).I.pubA0,
                    &(*swap.basilisk_swap).I.pubB0,
                    &(*swap.basilisk_swap).I.secretBn,
                    payment_amount,
                );

                status.status(SWAP_STATUS, "Waiting for the Maker deposit to land…");
                let transaction = match payment_fut.wait() {
                    Ok(t) => t,
                    Err(err) => err!(-2006, "!send_seller_payment: "(err))
                };

                let sending_f = send!("seller-payment", transaction.to_raw_bytes());
                swap.seller_payment = Some(transaction.clone());

                AtomicSwapState::WaitBuyerPayment {sending_f}
            },
            AtomicSwapState::WaitBuyerPayment {sending_f} => unsafe {
                let payload = recv!(sending_f, "buyer-payment", "for Taker fee", 600, -2006, {|_: &[u8]| Ok(())});

                let buyer_payment = match swap.buyer_coin.tx_from_raw_bytes(&payload) {
                    Ok(tx) => tx,
                    Err(err) => err!(-2006, "!buyer_coin.tx_from_raw_bytes: "(err))
                };

                swap.buyer_payment = Some(buyer_payment.clone());

                let wait_fut = swap.buyer_coin.wait_for_confirmations(
                    buyer_payment,
                    (*swap.basilisk_swap).I.aliceconfirms
                );

                status.status(SWAP_STATUS, "Waiting for Taker fee confirmation…");
                if let Err(err) = wait_fut.wait() {err!(-2006, "!buyer_coin.wait_for_confirmations: "(err))}

                AtomicSwapState::SpendBuyerPayment
            },
            AtomicSwapState::SpendBuyerPayment => unsafe {
                let mut reversed_secret = (*swap.basilisk_swap).I.privBn.bytes.to_vec();
                reversed_secret.reverse();
                let spend_fut = swap.buyer_coin.send_seller_spends_buyer_payment(
                    swap.buyer_payment.clone().unwrap(),
                    &(*swap.basilisk_swap).I.myprivs[0].bytes,
                    &reversed_secret,
                    dstr((*swap.basilisk_swap).I.alicesatoshis)
                );
                status.status(SWAP_STATUS, "Waiting for Taker fee to be spent…");
                let _transaction = match spend_fut.wait() {
                    Ok(t) => t,
                    Err(err) => err!(-2007, "!send_seller_spends_buyer_payment: "(err))
                };
                return Ok(());
            },
            AtomicSwapState::RefundSellerPayment => {
                // TODO cover this case
                return Ok(());
            },
            _ => unimplemented!(),
        };
        swap.state = Some(next_state);
    }
}

pub fn buyer_swap_loop(swap: &mut AtomicSwap) -> Result<(), (i32, String)> {
    // NB: We can communicate the SWAP status to UI progress indicators via documented tags,
    // cf. https://github.com/artemii235/SuperNET/commit/d66ab944bfd8c5e8fb17f1d36ac303797156b88e#r31676734
    // (but first we need to establish a use case for such indication with the UI guys,
    //  in order to avoid premature throw-away design, cf. https://www.agilealliance.org/glossary/simple-design).
    let mut status = swap.ctx.log.status_handle();

    macro_rules! send {
        ($subj: expr, $slice: expr) => {
            send (&swap.ctx, swap.seller, fomat!(($subj) '@' (swap.session)), $slice.into())
        };
    }
    macro_rules! recv {
        ($subj: expr, $desc: expr, $timeout_sec: expr, $ec: expr, $validator: block) => {
            recv_! (swap, status, $subj, $desc, $timeout_sec, $ec, $validator)
        };
        // Use this form if there's a sending future to terminate upon receiving the answer.
        ($sending_f: ident, $subj: expr, $desc: expr, $timeout_sec: expr, $ec: expr, $validator: block) => {{
            let payload = recv_! (swap, status, $subj, $desc, $timeout_sec, $ec, $validator);
            drop ($sending_f);
            payload
        }};
    }
    // Note that `err!` updates the current `status`. We assume there is no blind spots in the `status`.
    // NB: If we want to replace the `err!` with `?` then we should move the `status` ownership to the call site.
    //     (Which IMHO would break the status code flow and encapsulation a little).
    macro_rules! err {
        ($ec: expr, $($msg: tt)+) => {{
            let mut msg = fomat! (' ' $($msg)+);
            status.append (&msg);
            msg.remove (0);
            return Err (($ec, msg))
        }};
    }

    loop {
        let next_state = match unwrap!(swap.state.take()) {
            AtomicSwapState::PubkeyExchange => unsafe {
                let rc = lp::LP_pubkeys_data(swap.basilisk_swap, swap.buffer.as_mut_ptr(), swap.buffer_len as i32);
                if rc <= 0 {err!(-1000, "LP_pubkeys_data <= 0: "(rc))}
                let sending_f = send!("pubkeys", &swap.buffer[.. rc as usize]);

                let _ = recv!(sending_f, "pubkeys-reply", "for Maker public keys", 90, -1000, {
                    let swap = Swap(swap.basilisk_swap);
                    move |payload: &[u8]|
                        if lp::LP_pubkeys_verify(swap.0, payload.as_ptr() as *mut u8, payload.len() as i32) == 0 {Ok(())}
                        else {ERR!("!LP_pubkeys_verify")}
                });

                let rc = lp::LP_choosei_data(swap.basilisk_swap, swap.buffer.as_mut_ptr(), swap.buffer_len as i32);
                if rc <= 0 {err!(-1000, "LP_choosei_data <= 0: "(rc))}
                let sending_f = send!("choosei", &swap.buffer[.. rc as usize]);

                // NB: As of now `LP_choosei_verify` has side-effects and doesn't fit the `validator` very well.
                //     cf. https://discordapp.com/channels/@me/472006550194618379/521651286861414410
                //     (Preferred refactoring here might be to separate choosei parsing and verification from updating the swap,
                //      performing the parsing and verification in the `validator`).
                let payload = recv!(sending_f, "choosei-reply", "for the seller to confirm the key choice", 30, -1001, {|_: &[u8]| Ok(())});
                let rc = lp::LP_choosei_verify(swap.basilisk_swap, payload.as_ptr() as *mut u8, payload.len() as i32);
                if rc != 0 {err!(-1001, "LP_choosei_verify != 0: "(rc))}

                let rc = lp::LP_mostprivs_data(swap.basilisk_swap, swap.buffer.as_mut_ptr(), swap.buffer_len as i32);
                if rc <= 0 {err!(-1002, "LP_mostprivs_data <= 0: "(rc))}
                let sending_f = send!("mostprivs", &swap.buffer[.. rc as usize]);

                // TODO: Replace "mostpriv" with a human-readable label of what it is we're waiting for.
                let _ = recv!(sending_f, "mostprivs-reply", "for \"mostpriv\" reply", 30, -1002, {
                    let swap = Swap(swap.basilisk_swap);
                    move |payload: &[u8]| {
                        if lp::LP_mostprivs_verify(swap.0, payload.as_ptr() as *mut u8, payload.len() as i32) == 0 {Ok(())}
                        else {ERR!("LP_mostprivs_verify != 0: {}", rc)}
                    }
                });

                AtomicSwapState::SendBuyerFee
            },
            AtomicSwapState::SendBuyerFee => unsafe {
                let fee_addr_pub_key = unwrap!(hex::decode("03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06"));
                let payment_amount = dstr((*swap.basilisk_swap).I.alicesatoshis);
                let fee_amount = payment_amount / 777.0;
                status.status(SWAP_STATUS, "Sending Taker fee…");
                let fee_tx = swap.buyer_coin.send_buyer_fee(&fee_addr_pub_key, fee_amount).wait();
                let transaction = match fee_tx {
                    Ok (t) => t,
                    Err (err) => err!(-1004, "!send_buyer_fee: " (err))
                };

                let sending_f = send!("buyer-fee", transaction.to_raw_bytes());

                AtomicSwapState::WaitSellerPayment {sending_f}
            },
            AtomicSwapState::WaitSellerPayment {sending_f} => unsafe {
                let payload = recv!(sending_f, "seller-payment", "for Maker deposit", 600, -1005, {|_: &[u8]| Ok(())});
                let seller_payment = match swap.seller_coin.tx_from_raw_bytes(&payload) {
                    Ok(p) => p,
                    Err(err) => err!(-1005, "Error parsing the 'seller-payment': "(err))
                };
                swap.seller_payment = Some(seller_payment.clone());

                status.status(SWAP_STATUS, "Waiting for the confirmation of the Maker payment…");
                if let Err(err) = swap.seller_coin.wait_for_confirmations(seller_payment, (*swap.basilisk_swap).I.bobconfirms).wait() {
                    err!(-1005, "!seller_coin.wait_for_confirmations: "(err))
                }

                AtomicSwapState::SendBuyerPayment
            },
            AtomicSwapState::SendBuyerPayment => unsafe {
                let payment_amount = dstr((*swap.basilisk_swap).I.alicesatoshis);

                let payment_fut = swap.buyer_coin.send_buyer_payment(
                    (now_ms() / 1000) as u32 + 1000,
                    &(*swap.basilisk_swap).I.pubA0,
                    &(*swap.basilisk_swap).I.pubB0,
                    &(*swap.basilisk_swap).I.secretBn,
                    payment_amount,
                );

                status.status(SWAP_STATUS, "Sending the Taker fee…");
                let transaction = match payment_fut.wait() {
                    Ok(t) => t,
                    Err(err) => err!(-1006, "!send_buyer_payment: "(err))
                };

                let msg = transaction.to_raw_bytes();

                let sending_f = send!("buyer-payment", msg);
                swap.buyer_payment = Some(transaction.clone());

                AtomicSwapState::WaitBuyerPaymentSpent {sending_f}
            },
            AtomicSwapState::WaitBuyerPaymentSpent {sending_f} => {
                status.status(SWAP_STATUS, "Waiting for buyer payment spend…");
                let wait_spend_fut = swap.buyer_coin.wait_for_tx_spend(swap.buyer_payment.clone().unwrap(), now_ms() / 1000 + 1000);
                let got = wait_spend_fut.wait();
                drop(sending_f);

                match got {
                    Ok(transaction) => {
                        let secret = transaction.extract_secret();
                        if let Ok(bytes) = secret {
                            swap.secret = bytes;
                            AtomicSwapState::SpendSellerPayment
                        } else {
                            AtomicSwapState::RefundBuyerPayment
                        }
                    },
                    Err(err) => {
                        status.append(&fomat!(" Error: "(err)));
                        AtomicSwapState::RefundBuyerPayment
                    }
                }
            },
            AtomicSwapState::SpendSellerPayment => unsafe {
                // TODO: A human-readable label for send_buyer_spends_seller_payment.
                status.status(SWAP_STATUS, "send_buyer_spends_seller_payment…");
                let spend_fut = swap.seller_coin.send_buyer_spends_seller_payment(
                    swap.seller_payment.clone().unwrap(),
                    &(*swap.basilisk_swap).I.myprivs[0].bytes,
                    &swap.secret,
                    dstr((*swap.basilisk_swap).I.alicesatoshis)
                );
                let _transaction = match spend_fut.wait() {
                    Ok(t) => t,
                    Err(err) => err!(-1, "Error: "(err))
                };
                return Ok(());
            },
            AtomicSwapState::RefundBuyerPayment => unsafe {
                status.status(SWAP_STATUS, "Refunding the Taker payment…");
                let refund_fut = swap.buyer_coin.send_buyer_refunds_payment(
                    swap.buyer_payment.clone().unwrap(),
                    &(*swap.basilisk_swap).I.myprivs[0].bytes,
                    dstr((*swap.basilisk_swap).I.alicesatoshis)
                );

                let _transaction = match refund_fut.wait() {
                    Ok(t) => t,
                    Err(err) => err!(-1, "Error: "(err))
                };
                return Ok(());
            },
            _ => unimplemented!(),
        };
        swap.state = Some(next_state);
    }
}

/*
bits256 instantdex_derivekeypair(void *ctx,bits256 *newprivp,uint8_t pubkey[33],bits256 privkey,bits256 orderhash)
{
    bits256 sharedsecret;
    sharedsecret = curve25519_shared(privkey,orderhash);
    vcalc_sha256cat(newprivp->bytes,orderhash.bytes,sizeof(orderhash),sharedsecret.bytes,sizeof(sharedsecret));
    return(bitcoin_pubkey33(ctxf,pubkey,*newprivp));
}

bits256 basilisk_revealkey(bits256 privkey,bits256 pubkey)
{
    return(pubkey);
}

int32_t instantdex_pubkeyargs(struct basilisk_swap *swap,int32_t numpubs,bits256 privkey,bits256 hash,int32_t firstbyte)
{
    char buf[3]; int32_t i,n,m,len=0; bits256 pubi,reveal; uint64_t txid; uint8_t secret160[20],pubkey[33];
    sprintf(buf,"%c0",'A' - 0x02 + firstbyte);
    if ( numpubs > 2 )
    {
        if ( (*swap).I.numpubs+2 >= numpubs )
            return(numpubs);
        //printf(">>>>>> start generating %s\n",buf);
    }
    for (i=n=m=0; i<numpubs*100 && n<numpubs; i++)
    {
        pubi = instantdex_derivekeypair((*swap).ctx,&privkey,pubkey,privkey,hash);
        //printf("i.%d n.%d numpubs.%d %02x vs %02x\n",i,n,numpubs,pubkey[0],firstbyte);
        if ( pubkey[0] != firstbyte )
            continue;
        if ( n < 2 )
        {
            if ( bits256_nonz((*swap).I.mypubs[n]) == 0 )
            {
                (*swap).I.myprivs[n] = privkey;
                memcpy((*swap).I.mypubs[n].bytes,pubkey+1,sizeof(bits256));
                reveal = basilisk_revealkey(privkey,(*swap).I.mypubs[n]);
                if ( (*swap).I.iambob != 0 )
                {
                    if ( n == 0 )
                        (*swap).I.pubB0 = reveal;
                    else if ( n == 1 )
                        (*swap).I.pubB1 = reveal;
                }
                else if ( (*swap).I.iambob == 0 )
                {
                    if ( n == 0 )
                        (*swap).I.pubA0 = reveal;
                    else if ( n == 1 )
                        (*swap).I.pubA1 = reveal;
                }
            }
        }
        if ( m < INSTANTDEX_DECKSIZE )
        {
            (*swap).privkeys[m] = privkey;
            revcalc_rmd160_sha256(secret160,privkey);//.bytes,sizeof(privkey));
            memcpy(&txid,secret160,sizeof(txid));
            len += iguana_rwnum(1,(uint8_t *)&(*swap).deck[m][0],sizeof(txid),&txid);
            len += iguana_rwnum(1,(uint8_t *)&(*swap).deck[m][1],sizeof(pubi.txid),&pubi.txid);
            m++;
            if ( m > (*swap).I.numpubs )
                (*swap).I.numpubs = m;
        }
        n++;
    }
    //if ( n > 2 || m > 2 )
    //    printf("n.%d m.%d len.%d numpubs.%d\n",n,m,len,(*swap).I.numpubs);
    return(n);
}

void basilisk_rawtx_setparms(char *name,uint32_t quoteid,struct basilisk_rawtx *rawtx,struct iguana_info *coin,int32_t numconfirms,int32_t vintype,uint64_t satoshis,int32_t vouttype,uint8_t *pubkey33,int32_t jumblrflag)
{
#ifdef BASILISK_DISABLEWAITTX
    numconfirms = 0;
#endif
    strcpy(rawtx->name,name);
    //printf("set coin.%s %s -> %s\n",coin->symbol,coin->smartaddr,name);
    strcpy(rawtx->symbol,coin->symbol);
    rawtx->I.numconfirms = numconfirms;
    if ( (rawtx->I.amount= satoshis) < LP_MIN_TXFEE )
        rawtx->I.amount = LP_MIN_TXFEE;
    rawtx->I.vintype = vintype; // 0 -> std, 2 -> 2of2, 3 -> spend bobpayment, 4 -> spend bobdeposit
    rawtx->I.vouttype = vouttype; // 0 -> fee, 1 -> std, 2 -> 2of2, 3 -> bobpayment, 4 -> bobdeposit
    if ( rawtx->I.vouttype == 0 )
    {
        if ( strcmp(coin->symbol,"BTC") == 0 && (quoteid % 10) == 0 )
            decode_hex(rawtx->I.rmd160,20,TIERNOLAN_RMD160);
        else decode_hex(rawtx->I.rmd160,20,INSTANTDEX_RMD160);
        bitcoin_address(coin->symbol,rawtx->I.destaddr,coin->taddr,coin->pubtype,rawtx->I.rmd160,20);
    }
    if ( pubkey33 != 0 )
    {
        memcpy(rawtx->I.pubkey33,pubkey33,33);
        bitcoin_address(coin->symbol,rawtx->I.destaddr,coin->taddr,coin->pubtype,rawtx->I.pubkey33,33);
        bitcoin_addr2rmd160(coin->symbol,coin->taddr,&rawtx->I.addrtype,rawtx->I.rmd160,rawtx->I.destaddr);
    }
    if ( rawtx->I.vouttype <= 1 && rawtx->I.destaddr[0] != 0 )
    {
        rawtx->I.spendlen = bitcoin_standardspend(rawtx->spendscript,0,rawtx->I.rmd160);
        //printf("%s spendlen.%d %s <- %.8f\n",name,rawtx->I.spendlen,rawtx->I.destaddr,dstr(rawtx->I.amount));
    } //else printf("%s vouttype.%d destaddr.(%s)\n",name,rawtx->I.vouttype,rawtx->I.destaddr);
}

struct basilisk_swap *bitcoin_swapinit(bits256 privkey,uint8_t *pubkey33,bits256 pubkey25519,struct basilisk_swap *swap,int32_t optionduration,uint32_t statebits,struct LP_quoteinfo *qp,int32_t dynamictrust)
{
    //FILE *fp; char fname[512];
    uint8_t *alicepub33=0,*bobpub33=0; int32_t jumblrflag=-2,x = -1; struct iguana_info *bobcoin,*alicecoin; char bobstr[65],alicestr[65];
    strcpy((*swap).I.etomicsrc,qp->etomicsrc);
    strcpy((*swap).I.etomicdest,qp->etomicdest);
    strcpy((*swap).I.bobstr,(*swap).I.req.src);
    strcpy((*swap).I.alicestr,(*swap).I.req.dest);
    LP_etomicsymbol(bobstr,(*swap).I.bobtomic,(*swap).I.bobstr);
    LP_etomicsymbol(alicestr,(*swap).I.alicetomic,(*swap).I.alicestr);
    if ( (alicecoin= LP_coinfind(alicestr)) == 0 )
    {
        printf("missing alicecoin src.%p dest.%p\n",LP_coinfind(alicestr),LP_coinfind(bobstr));
        free(swap);
        return(0);
    }
    if ( (bobcoin= LP_coinfind(bobstr)) == 0 )
    {
        printf("missing bobcoin src.%p dest.%p\n",LP_coinfind((*swap).I.req.src),LP_coinfind((*swap).I.req.dest));
        free(swap);
        return(0);
    }
    if ( alicecoin == 0 || bobcoin == 0 )
    {
        printf("couldnt find ETOMIC\n");
        free(swap);
        return(0);
    }
    if ( ((*swap).I.Atxfee= qp->desttxfee) < 0 )
    {
        printf("bitcoin_swapinit %s Atxfee %.8f rejected\n",(*swap).I.req.dest,dstr((*swap).I.Atxfee));
        free(swap);
        return(0);
    }
    if ( ((*swap).I.Btxfee= qp->txfee) < 0 )
    {
        printf("bitcoin_swapinit %s Btxfee %.8f rejected\n",(*swap).I.req.src,dstr((*swap).I.Btxfee));
        free(swap);
        return(0);
    }
    (*swap).I.putduration = (*swap).I.callduration = LP_atomic_locktime(bobstr,alicestr);
    if ( optionduration < 0 )
        (*swap).I.putduration -= optionduration;
    else if ( optionduration > 0 )
        (*swap).I.callduration += optionduration;
    if ( ((*swap).I.bobsatoshis= (*swap).I.req.srcamount) <= 0 )
    {
        printf("bitcoin_swapinit %s bobsatoshis %.8f rejected\n",(*swap).I.req.src,dstr((*swap).I.bobsatoshis));
        free(swap);
        return(0);
    }
    if ( ((*swap).I.alicesatoshis= (*swap).I.req.destamount) <= 0 )
    {
        printf("bitcoin_swapinit %s alicesatoshis %.8f rejected\n",(*swap).I.req.dest,dstr((*swap).I.alicesatoshis));
        free(swap);
        return(0);
    }
#ifndef NOTETOMIC
    if (strcmp(alicestr, "ETOMIC") == 0) {
        (*swap).I.alicerealsat = (*swap).I.alicesatoshis;
        (*swap).I.alicesatoshis = 100000000;
    }
    if (strcmp(bobstr, "ETOMIC") == 0) {
        (*swap).I.bobrealsat = (*swap).I.bobsatoshis;
        (*swap).I.bobsatoshis = 100000000;
    }
#endif
    if ( ((*swap).I.bobinsurance= ((*swap).I.bobsatoshis / INSTANTDEX_INSURANCEDIV)) < LP_MIN_TXFEE )
        (*swap).I.bobinsurance = LP_MIN_TXFEE;
    if ( ((*swap).I.aliceinsurance= ((*swap).I.alicesatoshis / INSTANTDEX_INSURANCEDIV)) < LP_MIN_TXFEE )
        (*swap).I.aliceinsurance = LP_MIN_TXFEE;
    (*swap).I.started = qp->timestamp;//(uint32_t)time(NULL);
    (*swap).I.expiration = (*swap).I.req.timestamp + (*swap).I.putduration + (*swap).I.callduration;
    OS_randombytes((uint8_t *)&(*swap).I.choosei,sizeof((*swap).I.choosei));
    if ( (*swap).I.choosei < 0 )
        (*swap).I.choosei = -(*swap).I.choosei;
    (*swap).I.choosei %= INSTANTDEX_DECKSIZE;
    (*swap).I.otherchoosei = -1;
    (*swap).I.myhash = pubkey25519;
    if ( statebits != 0 )
    {
        (*swap).I.iambob = 0;
        (*swap).I.otherhash = (*swap).I.req.desthash;
        (*swap).I.aliceistrusted = 1;
        if ( dynamictrust == 0 && LP_pubkey_istrusted((*swap).I.req.srchash) != 0 )
            dynamictrust = 1;
        (*swap).I.otheristrusted = (*swap).I.bobistrusted = dynamictrust;
    }
    else
    {
        (*swap).I.iambob = 1;
        (*swap).I.otherhash = (*swap).I.req.srchash;
        (*swap).I.bobistrusted = 1;
        if ( dynamictrust == 0 && LP_pubkey_istrusted((*swap).I.req.desthash) != 0 )
            dynamictrust = 1;
        (*swap).I.otheristrusted = (*swap).I.aliceistrusted = dynamictrust;
    }
    if ( bits256_nonz(privkey) == 0 || (x= instantdex_pubkeyargs(swap,2 + INSTANTDEX_DECKSIZE,privkey,(*swap).I.orderhash,0x02+(*swap).I.iambob)) != 2 + INSTANTDEX_DECKSIZE )
    {
        char str[65]; printf("couldnt generate privkeys %d %s\n",x,bits256_str(str,privkey));
        free(swap);
        return(0);
    }
    if ( strcmp("BTC",bobstr) == 0 )
    {
        (*swap).I.bobconfirms = 1;//(1 + sqrt(dstr((*swap).I.bobsatoshis) * .1));
        (*swap).I.aliceconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
    }
    else if ( strcmp("BTC",alicestr) == 0 )
    {
        (*swap).I.aliceconfirms = 1;//(1 + sqrt(dstr((*swap).I.alicesatoshis) * .1));
        (*swap).I.bobconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
    }
    else
    {
        (*swap).I.bobconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
        (*swap).I.aliceconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
    }
    if ( bobcoin->userconfirms > 0 )
        (*swap).I.bobconfirms = bobcoin->userconfirms;
    if ( alicecoin->userconfirms > 0 )
        (*swap).I.aliceconfirms = alicecoin->userconfirms;
    if ( ((*swap).I.bobmaxconfirms= bobcoin->maxconfirms) == 0 )
        (*swap).I.bobmaxconfirms = BASILISK_DEFAULT_MAXCONFIRMS;
    if ( ((*swap).I.alicemaxconfirms= alicecoin->maxconfirms) == 0 )
        (*swap).I.alicemaxconfirms = BASILISK_DEFAULT_MAXCONFIRMS;
    if ( (*swap).I.bobconfirms > (*swap).I.bobmaxconfirms )
        (*swap).I.bobconfirms = (*swap).I.bobmaxconfirms;
    if ( (*swap).I.aliceconfirms > (*swap).I.alicemaxconfirms )
        (*swap).I.aliceconfirms = (*swap).I.alicemaxconfirms;
    if ( bobcoin->isassetchain != 0 ) {
        if (strcmp(bobstr, "ETOMIC") != 0) {
            (*swap).I.bobconfirms = BASILISK_DEFAULT_MAXCONFIRMS / 2;
        } else {
            (*swap).I.bobconfirms = 1;
        }
    }
    if ( alicecoin->isassetchain != 0 ) {
        if (strcmp(alicestr, "ETOMIC") != 0) {
            (*swap).I.aliceconfirms = BASILISK_DEFAULT_MAXCONFIRMS / 2;
        } else {
            (*swap).I.aliceconfirms = 1;
        }
    }
    if ( strcmp("BAY",(*swap).I.req.src) != 0 && strcmp("BAY",(*swap).I.req.dest) != 0 )
    {
        (*swap).I.bobconfirms *= !(*swap).I.bobistrusted;
        (*swap).I.aliceconfirms *= !(*swap).I.aliceistrusted;
    }
    printf(">>>>>>>>>> jumblrflag.%d <<<<<<<<< r.%u q.%u, %.8f bobconfs.%d, %.8f aliceconfs.%d taddr.%d %d\n",jumblrflag,(*swap).I.req.requestid,(*swap).I.req.quoteid,dstr((*swap).I.bobsatoshis),(*swap).I.bobconfirms,dstr((*swap).I.alicesatoshis),(*swap).I.aliceconfirms,bobcoin->taddr,alicecoin->taddr);
    if ( (*swap).I.etomicsrc[0] != 0 || (*swap).I.etomicdest[0] != 0 )
        printf("etomic src (%s %s) dest (%s %s)\n",(*swap).I.bobtomic,(*swap).I.etomicsrc,(*swap).I.alicetomic,(*swap).I.etomicdest);
    if ( (*swap).I.iambob != 0 )
    {
        basilisk_rawtx_setparms("myfee",(*swap).I.req.quoteid,&(*swap).myfee,bobcoin,0,0,LP_DEXFEE((*swap).I.bobsatoshis) + 0*bobcoin->txfee,0,0,jumblrflag);
        basilisk_rawtx_setparms("otherfee",(*swap).I.req.quoteid,&(*swap).otherfee,alicecoin,0,0,LP_DEXFEE((*swap).I.alicesatoshis) + 0*alicecoin->txfee,0,0,jumblrflag);
        bobpub33 = pubkey33;
    }
    else
    {
        basilisk_rawtx_setparms("otherfee",(*swap).I.req.quoteid,&(*swap).otherfee,bobcoin,0,0,LP_DEXFEE((*swap).I.bobsatoshis) + 0*bobcoin->txfee,0,0,jumblrflag);
        basilisk_rawtx_setparms("myfee",(*swap).I.req.quoteid,&(*swap).myfee,alicecoin,0,0,LP_DEXFEE((*swap).I.alicesatoshis) + 0*alicecoin->txfee,0,0,jumblrflag);
        alicepub33 = pubkey33;
    }
    (*swap).myfee.I.locktime = (*swap).I.started + 1;
    (*swap).otherfee.I.locktime = (*swap).I.started + 1;
    basilisk_rawtx_setparms("bobdeposit",(*swap).I.req.quoteid,&(*swap).bobdeposit,bobcoin,(*swap).I.bobconfirms,0,LP_DEPOSITSATOSHIS((*swap).I.bobsatoshis) + 2*bobcoin->txfee,4,0,jumblrflag);
    basilisk_rawtx_setparms("bobrefund",(*swap).I.req.quoteid,&(*swap).bobrefund,bobcoin,1,4,LP_DEPOSITSATOSHIS((*swap).I.bobsatoshis),1,bobpub33,jumblrflag);
    (*swap).bobrefund.I.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("aliceclaim",(*swap).I.req.quoteid,&(*swap).aliceclaim,bobcoin,1,4,LP_DEPOSITSATOSHIS((*swap).I.bobsatoshis),1,alicepub33,jumblrflag);
    (*swap).aliceclaim.I.suppress_pubkeys = 1;
    (*swap).aliceclaim.I.locktime = (*swap).I.started + (*swap).I.putduration+(*swap).I.callduration + 1;
    
    basilisk_rawtx_setparms("bobpayment",(*swap).I.req.quoteid,&(*swap).bobpayment,bobcoin,(*swap).I.bobconfirms,0,(*swap).I.bobsatoshis + 2*bobcoin->txfee,3,0,jumblrflag);
    basilisk_rawtx_setparms("alicespend",(*swap).I.req.quoteid,&(*swap).alicespend,bobcoin,(*swap).I.bobconfirms,3,(*swap).I.bobsatoshis,1,alicepub33,jumblrflag);
    (*swap).alicespend.I.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("bobreclaim",(*swap).I.req.quoteid,&(*swap).bobreclaim,bobcoin,(*swap).I.bobconfirms,3,(*swap).I.bobsatoshis,1,bobpub33,jumblrflag);
    (*swap).bobreclaim.I.suppress_pubkeys = 1;
    (*swap).bobreclaim.I.locktime = (*swap).I.started + (*swap).I.putduration + 1;
    basilisk_rawtx_setparms("alicepayment",(*swap).I.req.quoteid,&(*swap).alicepayment,alicecoin,(*swap).I.aliceconfirms,0,(*swap).I.alicesatoshis + 2*alicecoin->txfee,2,0,jumblrflag);
    basilisk_rawtx_setparms("bobspend",(*swap).I.req.quoteid,&(*swap).bobspend,alicecoin,(*swap).I.aliceconfirms,2,(*swap).I.alicesatoshis,1,bobpub33,jumblrflag);
    (*swap).bobspend.I.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("alicereclaim",(*swap).I.req.quoteid,&(*swap).alicereclaim,alicecoin,(*swap).I.aliceconfirms,2,(*swap).I.alicesatoshis,1,alicepub33,jumblrflag);
    (*swap).alicereclaim.I.suppress_pubkeys = 1;
#ifndef NOTETOMIC
    if (strcmp(alicestr, "ETOMIC") == 0) {
        (*swap).alicepayment.I.eth_amount = (*swap).I.alicerealsat;
        if ((*swap).I.iambob == 1) {
            (*swap).otherfee.I.eth_amount = LP_DEXFEE((*swap).I.alicerealsat);
        } else {
            (*swap).myfee.I.eth_amount = LP_DEXFEE((*swap).I.alicerealsat);
        }
    }
    if (strcmp(bobstr, "ETOMIC") == 0) {
        (*swap).bobpayment.I.eth_amount = (*swap).I.bobrealsat;
        (*swap).bobdeposit.I.eth_amount = LP_DEPOSITSATOSHIS((*swap).I.bobrealsat);
    }
#endif
    //char str[65],str2[65],str3[65]; printf("IAMBOB.%d %s %s %s [%s %s]\n",(*swap).I.iambob,bits256_str(str,qp->txid),bits256_str(str2,qp->txid2),bits256_str(str3,qp->feetxid),bobstr,alicestr);
    return(swap);
}

struct basilisk_swap *LP_swapinit(int32_t iambob,int32_t optionduration,bits256 privkey,struct basilisk_request *rp,struct LP_quoteinfo *qp,int32_t dynamictrust)
{
    static void *ctx;
    struct basilisk_swap *swap; bits256 pubkey25519; uint8_t pubkey33[33];
    if ( ctx == 0 )
        ctx = bitcoin_ctx();
    swap = calloc(1,sizeof(*swap));
    memcpy((*swap).uuidstr,qp->uuidstr,sizeof((*swap).uuidstr));
    (*swap).aliceid = qp->aliceid;
    (*swap).I.req.quoteid = rp->quoteid;
    (*swap).ctx = ctx;
    vcalc_sha256(0,(*swap).I.orderhash.bytes,(uint8_t *)rp,sizeof(*rp));
    (*swap).I.req = *rp;
    G.LP_skipstatus[G.LP_numskips] = ((uint64_t)rp->requestid << 32) | rp->quoteid;
    if ( G.LP_numskips < sizeof(G.LP_skipstatus)/sizeof(*G.LP_skipstatus) )
        G.LP_numskips++;
    //printf("LP_swapinit request.%u iambob.%d (%s/%s) quoteid.%u\n",rp->requestid,iambob,rp->src,rp->dest,rp->quoteid);
    bitcoin_pubkey33((*swap).ctx,pubkey33,privkey);
    pubkey25519 = curve25519(privkey,curve25519_basepoint9());
    (*swap).persistent_pubkey = pubkey25519;
    (*swap).persistent_privkey = privkey;
    memcpy((*swap).persistent_pubkey33,pubkey33,33);
    calc_rmd160_sha256((*swap).changermd160,pubkey33,33);
    if ( bitcoin_swapinit(privkey,pubkey33,pubkey25519,swap,optionduration,!iambob,qp,dynamictrust) == 0 )
    {
        printf("error doing swapinit\n");
        free(swap);
        swap = 0;
    }
    return(swap);
}
*/
