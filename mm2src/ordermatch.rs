
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
//  ordermatch.rs
//  marketmaker
//
use common::{find_coin, lp, free_c_ptr, c_char_to_string, sat_to_f, SATOSHIS, SMALLVAL, CJSON};
use common::mm_ctx::{MmArc, MmWeak};
use gstuff::now_ms;
use fxhash::{FxHashMap};
use libc::{self, c_void, c_char, strcpy, strlen, strcmp, calloc, rand};
use serde_json::{Value as Json};
use std::collections::{VecDeque};
use std::collections::hash_map::Entry;
use std::ffi::{CString};
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;

#[link="c"]
extern {
    fn printf(_: *const libc::c_char, ...) -> libc::c_int;
}

struct OrdermatchContext {
    pub lp_trades: Mutex<FxHashMap<u64, lp::LP_trade>>,
    lp_trades_queue: Mutex<VecDeque<lp::LP_trade>>,
}
impl OrdermatchContext {
    /// Obtains a reference to this crate context, creating it if necessary.
    fn from_ctx (ctx: &MmArc) -> Result<Arc<OrdermatchContext>, String> {
        let mut ordermatch_ctx = try_s! (ctx.ordermatch_ctx.lock());
        if ordermatch_ctx.is_none() {
            let arc = Arc::new (OrdermatchContext {
                lp_trades: Mutex::new (FxHashMap::default()),
                lp_trades_queue: Mutex::new (VecDeque::new())
            });
            *ordermatch_ctx = Some (arc.clone());
            Ok (arc)
        } else if let Some (ref ordermatch_ctx) = *ordermatch_ctx {
            let ordermatch_ctx: Arc<OrdermatchContext> = match ordermatch_ctx.clone().downcast() {
                Ok (p) => p,
                Err (_) => return ERR! ("Error casting into OrdermatchContext")
            };
            Ok (ordermatch_ctx)
        } else {panic!()}
    }

    /// Obtains a reference to this crate context, creating it if necessary.
    #[allow(dead_code)]
    fn from_ctx_weak (ctx_weak: &MmWeak) -> Result<Arc<OrdermatchContext>, String> {
        let ctx = try_s! (MmArc::from_weak (ctx_weak) .ok_or ("Context expired"));
        Self::from_ctx (&ctx)
    }

    fn add_trade_to_queue(&self, trade: lp::LP_trade) {
        let mut queue = unwrap!(self.lp_trades_queue.lock());
        queue.push_back(trade);
    }

    fn pop_trade_from_queue(&self) -> Option<lp::LP_trade> {
        let mut queue = unwrap!(self.lp_trades_queue.lock());
        queue.pop_front()
    }

    fn is_trade_queue_empty(&self) -> bool {
        let queue = unwrap!(self.lp_trades_queue.lock());
        queue.is_empty()
    }
}
/*
struct LP_quoteinfo LP_Alicequery,LP_Alicereserved;
double LP_Alicemaxprice;
bits256 LP_Alicedestpubkey,LP_bobs_reserved;
uint32_t Alice_expiration,Bob_expiration;
struct { uint64_t aliceid; double bestprice; uint32_t starttime,counter; } Bob_competition[512];


void LP_failedmsg(uint32_t requestid,uint32_t quoteid,double val,char *uuidstr)
{
    char *msg; cJSON *retjson;
    if ( IPC_ENDPOINT >= 0 )
    {
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"method","failed");
        jaddstr(retjson,"uuid",uuidstr);
        jaddnum(retjson,"error",val);
        jaddnum(retjson,"requestid",requestid);
        jaddnum(retjson,"quoteid",quoteid);
        msg = jprint(retjson,1);
        LP_queuecommand(0,msg,IPC_ENDPOINT,-1,0);
        free(msg);
    }
}

double LP_bob_competition(int32_t *counterp,uint64_t aliceid,double price,int32_t counter)
{
    int32_t i,firsti = -1; uint32_t now = (uint32_t)time(NULL);
    *counterp = 0;
    for (i=0; i<sizeof(Bob_competition)/sizeof(*Bob_competition); i++)
    {
        if ( Bob_competition[i].aliceid == aliceid )
        {
            if ( counter < 0 || now > Bob_competition[i].starttime+LP_AUTOTRADE_TIMEOUT )
            {
                //printf("aliceid.%llu expired\n",(long long)aliceid);
                Bob_competition[i].bestprice = 0.;
                Bob_competition[i].starttime = now;
                Bob_competition[i].counter = 0;
            }
            if ( price != 0. && (Bob_competition[i].bestprice == 0. || price < Bob_competition[i].bestprice) )
            {
                Bob_competition[i].bestprice = price;
                //printf("Bob competition aliceid.%llu <- bestprice %.8f\n",(long long)aliceid,price);
            }
            Bob_competition[i].counter += counter;
            *counterp = Bob_competition[i].counter;
            return(Bob_competition[i].bestprice);
        }
        else if ( Bob_competition[i].aliceid == 0 )
            firsti = i;
    }
    if ( firsti < 0 )
        firsti = (LP_rand() % (sizeof(Bob_competition)/sizeof(*Bob_competition)));
    Bob_competition[firsti].starttime = (uint32_t)time(NULL);
    Bob_competition[firsti].counter = counter;
    Bob_competition[firsti].aliceid = aliceid;
    Bob_competition[firsti].bestprice = price;
    *counterp = counter;
    //printf("Bob competition aliceid.%llu %.8f\n",(long long)aliceid,price);
    return(price);
}

uint64_t LP_txfeecalc(struct iguana_info *coin,uint64_t txfee,int32_t txlen)
{
    if ( coin != 0 )
    {
        if ( strcmp(coin->symbol,"BTC") == 0 )
        {
            if ( txlen == 0 )
                txlen = LP_AVETXSIZE;
            coin->rate = LP_getestimatedrate(coin);
            if ( (txfee= SATOSHIDEN * coin->rate * txlen) <= 20000 )
            {
                //coin->rate = -1.;
                coin->rate = _LP_getestimatedrate(coin);
                if ( (txfee= SATOSHIDEN * coin->rate * txlen) <= 20000 )
                    txfee = 20000;
            }
        } else txfee = coin->txfee;
        if ( txfee < LP_MIN_TXFEE )
            txfee = LP_MIN_TXFEE;
    }
    return(txfee);
}

int32_t LP_quote_checkmempool(struct LP_quoteinfo *qp,struct LP_utxoinfo *autxo,struct LP_utxoinfo *butxo)
{
    int32_t selector,spendvini; bits256 spendtxid;
    if ( butxo != 0 && (selector= LP_mempool_vinscan(&spendtxid,&spendvini,qp->srccoin,qp->coinaddr,qp->txid,qp->vout,qp->txid2,qp->vout2)) >= 0 )
    {
        char str[65]; printf("LP_tradecommand selector.%d in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
        return(-1);
    }
    if ( autxo != 0 && (selector= LP_mempool_vinscan(&spendtxid,&spendvini,qp->destcoin,qp->destaddr,qp->desttxid,qp->destvout,qp->feetxid,qp->feevout)) >= 0 )
    {
        char str[65]; printf("LP_tradecommand dest selector.%d in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
        return(-1);
    }
    return(0);
}

double LP_quote_validate(struct LP_utxoinfo *autxo,struct LP_utxoinfo *butxo,struct LP_quoteinfo *qp,int32_t iambob)
{
    double qprice=0.; char str[65],srccoin[65],destcoin[65],bobtomic[64],alicetomic[64]; cJSON *txout; uint64_t txfee,desttxfee,srcvalue=0,srcvalue2=0,destvalue=0,destvalue2=0;
    LP_etomicsymbol(srccoin,bobtomic,qp->srccoin);
    LP_etomicsymbol(destcoin,alicetomic,qp->destcoin);
  //printf(">>>>>>> quote satoshis.(%.8f %.8f) %s %.8f -> %s %.8f\n",dstr(qp->satoshis),dstr(qp->destsatoshis),qp->srccoin,dstr(qp->satoshis),qp->destcoin,dstr(qp->destsatoshis));
    if ( butxo != 0 )
    {
        if ( LP_iseligible(&srcvalue,&srcvalue2,1,srccoin,qp->txid,qp->vout,qp->satoshis,qp->txid2,qp->vout2) == 0 )
        {
            //printf("bob not eligible %s (%.8f %.8f)\n",jprint(LP_quotejson(qp),1),dstr(srcvalue),dstr(srcvalue2));
            return(-2);
        }
        if ( (txout= LP_gettxout(srccoin,qp->coinaddr,qp->txid,qp->vout)) != 0 )
            free_json(txout);
        else
        {
            printf("%s %s payment %s/v%d is spent\n",srccoin,qp->coinaddr,bits256_str(str,qp->txid),qp->vout);
            return(-21);
        }
        if ( (txout= LP_gettxout(srccoin,qp->coinaddr,qp->txid2,qp->vout2)) != 0 )
            free_json(txout);
        else
        {
            printf("%s %s deposit %s/v%d is spent\n",srccoin,qp->coinaddr,bits256_str(str,qp->txid2),qp->vout2);
            return(-22);
        }
        if ( bits256_cmp(butxo->deposit.txid,qp->txid2) != 0 || butxo->deposit.vout != qp->vout2 )
        {
            char str[65],str2[65]; printf("%s != %s v%d != %d\n",bits256_str(str,butxo->deposit.txid),bits256_str(str2,qp->txid2),butxo->deposit.vout,qp->vout2);
            return(-6);
        }
        if ( strcmp(butxo->coinaddr,qp->coinaddr) != 0 )
        {
            printf("(%s) != (%s)\n",butxo->coinaddr,qp->coinaddr);
            return(-7);
        }
    }
    if ( autxo != 0 )
    {
        if ( LP_iseligible(&destvalue,&destvalue2,0,destcoin,qp->desttxid,qp->destvout,qp->destsatoshis,qp->feetxid,qp->feevout) == 0 )
        {
            //alice not eligible 0.36893923 -> dest 0.55020000 1.49130251 (0.61732249 0.00104324) 14b8b74808d2d34a70e5eddd1cad47d855858f8b23cac802576d4d37b5f8af8f/v1 abec6e76169bcb738235ca67fab02cc55390f39e422aa71f1badf8747c290cc4/v1
            char str[65],str2[65]; printf("alice not eligible %.8f -> dest %.8f %.8f (%.8f %.8f) %s/v%d %s/v%d\n",dstr(qp->satoshis),dstr(qp->destsatoshis),(double)qp->destsatoshis/qp->satoshis,dstr(destvalue),dstr(destvalue2),bits256_str(str,qp->desttxid),qp->destvout,bits256_str(str2,qp->feetxid),qp->feevout);
            return(-3);
        }
        if ( (txout= LP_gettxout(destcoin,qp->destaddr,qp->desttxid,qp->destvout)) != 0 )
            free_json(txout);
        else
        {
            printf("%s %s Apayment %s/v%d is spent\n",destcoin,qp->destaddr,bits256_str(str,qp->desttxid),qp->destvout);
            return(-23);
        }
        if ( (txout= LP_gettxout(destcoin,qp->destaddr,qp->feetxid,qp->feevout)) != 0 )
            free_json(txout);
        else
        {
            printf("%s %s dexfee %s/v%d is spent\n",destcoin,qp->destaddr,bits256_str(str,qp->feetxid),qp->feevout);
            return(-24);
        }
    }
    //printf("checked autxo and butxo\n");
    if ( LP_quote_checkmempool(qp,autxo,butxo) < 0 )
        return(-4);
    if ( iambob == 0 && autxo != 0 )
    {
        if ( bits256_cmp(autxo->fee.txid,qp->feetxid) != 0 || autxo->fee.vout != qp->feevout )
            return(-9);
        if ( strcmp(autxo->coinaddr,qp->destaddr) != 0 )
            return(-10);
    }
    if ( strcmp(destcoin, "ETOMIC") != 0 && autxo != 0 && destvalue < qp->desttxfee+qp->destsatoshis )
    {
        printf("destvalue %.8f  destsatoshis %.8f is too small txfee %.8f?\n",dstr(destvalue),dstr(qp->destsatoshis),dstr(qp->desttxfee));
        return(-11);
    }
    if ( strcmp(srccoin, "ETOMIC") != 0 && butxo != 0 && srcvalue < qp->txfee+qp->satoshis )
    {
        printf("srcvalue %.8f [%.8f] satoshis %.8f is too small txfee %.8f?\n",dstr(srcvalue),dstr(srcvalue) - dstr(qp->txfee+qp->satoshis),dstr(qp->satoshis),dstr(qp->txfee));
        return(-33);
    }
    LP_txfees(&txfee,&desttxfee,qp->srccoin,qp->destcoin);
    if ( txfee < qp->txfee )
        txfee = qp->txfee;
    if ( desttxfee < qp->desttxfee )
        desttxfee = qp->desttxfee;
    if ( qp->satoshis != 0 )
        qprice = ((double)qp->destsatoshis / (qp->satoshis-qp->txfee));
    //printf("qprice %.8f <- %.8f/%.8f txfees.(%.8f %.8f) vs (%.8f %.8f)\n",qprice,dstr(qp->destsatoshis),dstr(qp->satoshis),dstr(qp->txfee),dstr(qp->desttxfee),dstr(txfee),dstr(desttxfee));
    if ( qp->txfee < LP_REQUIRED_TXFEE*txfee || qp->desttxfee < LP_REQUIRED_TXFEE*desttxfee )
    {
        printf("error -14: txfee %.8f < %.8f or desttxfee %.8f < %.8f\n",dstr(qp->txfee),dstr(LP_REQUIRED_TXFEE*txfee),dstr(qp->desttxfee),dstr(LP_REQUIRED_TXFEE*desttxfee));
        return(-14);
    }
    if ( butxo != 0 && strcmp(srccoin, "ETOMIC") != 0)
    {
        if ( qp->satoshis < (srcvalue / LP_MINVOL) || srcvalue < qp->txfee*LP_MINSIZE_TXFEEMULT )
        {
            printf("utxo payment %.8f is less than %f covered by Q %.8f or <10x txfee %.8f [%d %d]\n",dstr(srcvalue),1./LP_MINVOL,dstr(qp->satoshis),dstr(qp->txfee),qp->satoshis < (srcvalue / LP_MINVOL),srcvalue < qp->txfee*LP_MINSIZE_TXFEEMULT);
            return(-12);
        }
    }
    if ( autxo != 0 )
    {
        if ( qp->destsatoshis < (destvalue / LP_MINCLIENTVOL) || destvalue < qp->desttxfee*LP_MINSIZE_TXFEEMULT )
        {
            printf("destsatoshis %.8f is less than %f of value %.8f or < 10x txfee %.8f\n",dstr(qp->destsatoshis),1./LP_MINCLIENTVOL,dstr(destvalue),dstr(qp->desttxfee));
            return(-13);
        }
    }
    return(qprice);
}

int32_t LP_arrayfind(cJSON *array,bits256 txid,int32_t vout)
{
    int32_t i,n = cJSON_GetArraySize(array); cJSON *item;
    for (i=0; i<n; i++)
    {
        item = jitem(array,i);
        if ( vout == jint(item,"vout") && bits256_cmp(txid,jbits256(item,"txid")) == 0 )
            return(i);
    }
    return(-1);
}

int32_t LP_nanobind(void *ctx,char *pairstr)
{
    int32_t i,r,pairsock = -1; uint16_t mypullport; char bindaddr[128];
    if ( LP_canbind != 0 )
    {
        if ( (pairsock= nn_socket(AF_SP,NN_PAIR)) < 0 )
            printf("error creating utxo->pair\n");
        else
        {
            for (i=0; i<10000; i++)
            {
                r = (10000 + (LP_rand() % 50000)) & 0xffff;
                if ( LP_fixed_pairport != 0 )
                    r = LP_fixed_pairport;
                nanomsg_transportname(0,pairstr,LP_myipaddr,r);
                nanomsg_transportname(1,bindaddr,LP_myipaddr,r);
                if ( nn_bind(pairsock,bindaddr) >= 0 )
                {
                    //timeout = 1;
                    //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                    //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                    //printf("nanobind %s to %d\n",pairstr,pairsock);
                    return(pairsock);
                } // else printf("error binding to %s for %s\n",bindaddr,pairstr);
                if ( LP_fixed_pairport != 0 )
                    break;
            }
            printf("%d ports all used\n",i);
            nn_close(pairsock);
            pairsock = -1;
        }
    } else pairsock = LP_initpublicaddr(ctx,&mypullport,pairstr,"127.0.0.1",0,1);
    return(pairsock);
}
*/

unsafe fn lp_nearest_utxovalue(
    utxos: *mut *mut lp::LP_address_utxo,
    n: i32,
    targetval: u64,
) -> i32 {
    let mut replacei: i32;
    let mut bestheight: i32;
    let mut mini: i32 = -1i32;
    let mut up: *mut lp::LP_address_utxo = null_mut();
    let mut bestup: *mut lp::LP_address_utxo = null_mut();
    let mut dist: i64;
    let mut mindist: u64 = (1i64 << 60) as u64;
    //printf("LP_nearest_utxovalue %s %s utxos[%d] target %.8f\n",coin->symbol,coinaddr,n,dstr(targetval));
    let mut i = 0;
    while i < n {
        up = *utxos.offset(i as isize);
        if !up.is_null() {
            dist = (*up).U.value.wrapping_sub(targetval) as i64;
            //printf("nearest i.%d target %.8f val %.8f dist %.8f mindist %.8f mini.%d spent.%d\n",i,dstr(targetval),dstr(up->U.value),dstr(dist),dstr(mindist),mini,up->spendheight);
            if (*up).spendheight <= 0 {
                if dist >= 0 && (dist as u64) < mindist {
                    //printf("(%.8f %.8f %.8f).%d ",dstr(up->U.value),dstr(dist),dstr(mindist),mini);
                    mini = i;
                    mindist = dist as u64
                }
            }
        }
        i += 1
    }
    if mini >= 0 && {
        bestup = *utxos.offset(mini as isize);
        !bestup.is_null()
    } {
        let bestdist = (*bestup).U.value.wrapping_sub(targetval) as i64;
        replacei = -1;
        bestheight = (*bestup).U.height;
        i = 0;
        while i < n {
            if i != mini && {
                up = *utxos.offset(i as isize);
                !up.is_null()
            } {
                dist = (*up).U.value.wrapping_sub(targetval) as i64;
                if dist > 0 && (*up).U.height < bestheight {
                    if (dist as f64 / bestdist as f64)
                        < ((bestheight as f64 - (*up).U.height as f64)
                            / 1000 as f64).sqrt() {
                        replacei = i;
                        bestheight = (*up).U.height
                    }
                }
            }
            i += 1
        }
        //else printf("almost ratio %.3f dist %.8f vs best %.8f, ht %d vs best ht %d\n",(double)dist/bestdist,dstr(dist),dstr(bestdist),up->U.height,bestheight);
        if replacei >= 0 {
            //printf("REPLACE bestdist %.8f height %d with dist %.8f height %d\n",dstr(bestdist),bestup->U.height,dstr(utxos[replacei]->U.value - targetval),utxos[replacei]->U.height);
            return replacei;
        }
    }
    //printf("return mini.%d\n",mini);
    return mini;
}

unsafe fn lp_butxo_set(
    butxo: *mut lp::LP_utxoinfo,
    iambob: i32,
    coin: *mut lp::iguana_info,
    up: *mut lp::LP_address_utxo,
    up2: *mut lp::LP_address_utxo,
    satoshis: i64,
) -> () {
    (*butxo).pubkey = lp::G.LP_mypub25519;
    strcpy(
        (*butxo).coin.as_mut_ptr(),
        (*coin).symbol.as_mut_ptr(),
    );
    strcpy(
        (*butxo).coinaddr.as_mut_ptr(),
        (*coin).smartaddr.as_mut_ptr(),
    );
    (*butxo).payment.txid = (*up).U.txid;
    (*butxo).payment.vout = (*up).U.vout;
    (*butxo).payment.value = (*up).U.value;
    (*butxo).iambob = iambob;
    if (*butxo).iambob != 0 {
        (*butxo).deposit.txid = (*up2).U.txid;
        (*butxo).deposit.vout = (*up2).U.vout;
        (*butxo).deposit.value = (*up2).U.value
    } else {
        (*butxo).fee.txid = (*up2).U.txid;
        (*butxo).fee.vout = (*up2).U.vout;
        (*butxo).fee.value = (*up2).U.value
    }
    (*butxo).swap_satoshis = satoshis;
}
/*
void LP_abutxo_set(struct LP_utxoinfo *autxo,struct LP_utxoinfo *butxo,struct LP_quoteinfo *qp)
{
    if ( butxo != 0 )
    {
        memset(butxo,0,sizeof(*butxo));
        butxo->pubkey = qp->srchash;
        safecopy(butxo->coin,qp->srccoin,sizeof(butxo->coin));
        safecopy(butxo->coinaddr,qp->coinaddr,sizeof(butxo->coinaddr));
        butxo->payment.txid = qp->txid;
        butxo->payment.vout = qp->vout;
        //butxo->payment.value = qp->value;
        butxo->iambob = 1;
        butxo->deposit.txid = qp->txid2;
        butxo->deposit.vout = qp->vout2;
        //butxo->deposit.value = up2->U.value;
        butxo->swap_satoshis = qp->satoshis;
    }
    if ( autxo != 0 )
    {
        memset(autxo,0,sizeof(*autxo));
        autxo->pubkey = qp->desthash;
        safecopy(autxo->coin,qp->destcoin,sizeof(autxo->coin));
        safecopy(autxo->coinaddr,qp->destaddr,sizeof(autxo->coinaddr));
        autxo->payment.txid = qp->desttxid;
        autxo->payment.vout = qp->destvout;
        //autxo->payment.value = qp->value;
        autxo->iambob = 0;
        autxo->fee.txid = qp->feetxid;
        autxo->fee.vout = qp->feevout;
        //autxo->deposit.value = up2->U.value;
        autxo->swap_satoshis = qp->destsatoshis;
    }
}
*/
unsafe fn lp_base_satoshis(
    relvolume: f64,
    price: f64,
    txfee: u64,
    desttxfee: u64,
) -> u64 {
    //printf("basesatoshis %.8f (rel %.8f / price %.8f)\n",dstr(SATOSHIDEN * ((relvolume) / price) + 2*txfee),relvolume,price);
    if relvolume > desttxfee as f64 / 100000000i64 as u64 as f64
        && price > 1e-15f64
        {
            return (100000000i64 as u64 as f64 * (relvolume / price)
                + (2u64).wrapping_mul(txfee) as f64)
                as u64;
        } else {
        return 0 as u64;
    };
}

unsafe fn lp_address_myutxopair(
    butxo: *mut lp::LP_utxoinfo,
    iambob: i32,
    utxos: *mut *mut lp::LP_address_utxo,
    max: i32,
    mut coin: *mut lp::iguana_info,
    mut coinaddr: *mut libc::c_char,
    txfee: u64,
    relvolume: f64,
    price: f64,
    desttxfee: u64,
) -> *mut lp::LP_utxoinfo {
    let mut ap: *mut lp::LP_address = null_mut();
    let fee: u64;
    let targetval: u64;
    let targetval2: u64;
    let m: i32;
    let mut mini: i32;
    let mut up: *mut lp::LP_address_utxo;
    let mut up2: *mut lp::LP_address_utxo = null_mut();
    let ratio: f64;
    if (*coin).etomic[0usize] as libc::c_int != 0 {
        coin = lp::LP_coinfind(b"ETOMIC\x00" as *const u8 as *const libc::c_char as *mut libc::c_char);
        if !coin.is_null() {
            coinaddr = (*coin).smartaddr.as_mut_ptr()
        }
    }
    if coin.is_null() {
        return 0 as *mut lp::LP_utxoinfo;
    } else {
        *butxo = lp::LP_utxoinfo::default();
        if iambob != 0 {
            if strcmp(
                (*coin).symbol.as_mut_ptr(),
                b"ETOMIC\x00" as *const u8 as *const libc::c_char,
            ) == 0
                {
                    targetval = (100000000u64)
                        .wrapping_add((3u64).wrapping_mul(txfee))
                } else {
                targetval = lp_base_satoshis(relvolume, price, txfee, desttxfee)
                    .wrapping_add((3u64).wrapping_mul(txfee))
            }
            targetval2 = targetval
                .wrapping_div(8u64)
                .wrapping_mul(9u64)
                .wrapping_add((3u64).wrapping_mul(txfee));
            fee = txfee;
            ratio = 100 as f64
        } else {
            if strcmp(
                (*coin).symbol.as_mut_ptr(),
                b"ETOMIC\x00" as *const u8 as *const libc::c_char,
            ) == 0
                {
                    targetval = (100000000u64)
                        .wrapping_add((3u64).wrapping_mul(desttxfee))
                } else {
                targetval = (relvolume * 100000000i64 as u64 as f64
                    + (3u64).wrapping_mul(desttxfee) as f64)
                    as u64
            }
            targetval2 = targetval
                .wrapping_div(777)
                .wrapping_add((3 as u64).wrapping_mul(desttxfee));
            fee = desttxfee;
            ratio = 1000 as f64
        }
        if !coin.is_null() && {
            ap = lp::LP_address(coin, coinaddr);
            !ap.is_null()
        } {
            m = lp::LP_address_utxo_ptrs(coin, iambob, utxos, max, ap, coinaddr);
            if m > 1i32 {
                let mut i: i32 = 0;
                while i < m {
                    if (**utxos.offset(i as isize)).U.value >= targetval {
                        printf(
                            b"%.8f \x00" as *const u8 as *const libc::c_char,
                            (**utxos.offset(i as isize)).U.value as f64
                                / 100000000i64 as u64 as f64,
                        );
                    }
                    i += 1
                }
                printf(
                    b"targetval %.8f vol %.8f price %.8f txfee %.8f %s %s\n\x00" as *const u8
                        as *const libc::c_char,
                    targetval as f64 / 100000000i64 as u64 as f64,
                    relvolume,
                    price,
                    fee as f64 / 100000000i64 as u64 as f64,
                    (*coin).symbol.as_mut_ptr(),
                    coinaddr,
                );
                loop {
                    mini = -1i32;
                    if targetval != 0 && {
                        mini = lp_nearest_utxovalue(
                            utxos,
                            m,
                            targetval.wrapping_add(fee),
                        );
                        mini >= 0
                    } {
                        up = *utxos.offset(mini as isize);
                        let ref mut fresh256 = *utxos.offset(mini as isize);
                        *fresh256 = null_mut();
                        //printf("found mini.%d %.8f for targetval %.8f -> targetval2 %.8f, ratio %.2f\n",mini,dstr(up->U.value),dstr(targetval),dstr(targetval2),(double)up->U.value/targetval);
                        if ((*up).U.value as f64 / targetval as f64)
                            < ratio - 1i32 as f64
                            {
                                mini = lp_nearest_utxovalue(
                                    utxos,
                                    m,
                                    (targetval2.wrapping_add((2 as u64).wrapping_mul(fee))
                                        as f64 * 1.01f64)
                                        as u64,
                                );
                                if mini >= 0 {
                                    if !up.is_null() && {
                                        up2 = *utxos.offset(mini as isize);
                                        !up2.is_null()
                                    } {
                                        lp_butxo_set(
                                            butxo,
                                            iambob,
                                            coin,
                                            up,
                                            up2,
                                            targetval as i64,
                                        );
                                        return butxo;
                                    } else {
                                        /*printf(
                                            b"cant find utxos[mini %d]\n\x00" as *const u8
                                                as *const libc::c_char,
                                            mini,
                                        );*/
                                    }
                                }
                            }
                    } else if targetval != 0 && mini >= 0 {
                        printf(
                            b"targetval %.8f mini.%d\n\x00" as *const u8 as *const libc::c_char,
                            targetval as f64
                                / 100000000i64 as u64 as f64,
                            mini,
                        );
                    }
                    if targetval == 0 || mini < 0 {
                        break;
                    }
                }
            }
        }
        //else printf("no %s %s utxos pass LP_address_utxo_ptrs filter %.8f %.8f\n",coin->symbol,coinaddr,dstr(targetval),dstr(targetval2));
        printf(
            b"address_myutxopair couldnt find %s %s targets %.8f %.8f\n\x00" as *const u8
                as *const libc::c_char,
            (*coin).symbol.as_mut_ptr(),
            coinaddr,
            targetval as f64 / 100000000.0,
            targetval2 as f64 / 100000000.0,
        );
        return null_mut();
    };
}
/*
int32_t LP_connectstartbob(void *ctx,int32_t pubsock,char *base,char *rel,double price,struct LP_quoteinfo *qp)
{
    char pairstr[512],otheraddr[64]; cJSON *reqjson; bits256 privkey; int32_t i,pair=-1,retval = -1,DEXselector = 0; int64_t dtrust; struct basilisk_swap *swap; struct iguana_info *ecoin,*coin,*kmdcoin;
    qp->quotetime = (uint32_t)time(NULL);
    if ( (coin= LP_coinfind(qp->srccoin)) == 0 )
    {
        printf("cant find coin.%s\n",qp->srccoin);
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,-3000,qp->uuidstr);
        return(-1);
    }
    privkey = LP_privkey(coin->symbol,coin->smartaddr,coin->taddr);
    if ( coin->etomic[0] != 0 )
    {
        if ( (ecoin= LP_coinfind("ETOMIC")) != 0 )
            privkey = LP_privkey(ecoin->symbol,ecoin->smartaddr,ecoin->taddr);
    }
    if ( bits256_nonz(privkey) != 0 && bits256_cmp(G.LP_mypub25519,qp->srchash) == 0 )
    {
        LP_requestinit(&qp->R,qp->srchash,qp->desthash,base,qp->satoshis-qp->txfee,rel,qp->destsatoshis-qp->desttxfee,qp->timestamp,qp->quotetime,DEXselector,qp->fill,qp->gtc);
        dtrust = LP_dynamictrust(qp->othercredits,qp->desthash,LP_kmdvalue(qp->destcoin,qp->destsatoshis));
        if ( (swap= LP_swapinit(1,0,privkey,&qp->R,qp,dtrust > 0)) == 0 )
        {
            printf("cant initialize swap\n");
            LP_failedmsg(qp->R.requestid,qp->R.quoteid,-3001,qp->uuidstr);
            return(-1);
        }
        if ( (pair= LP_nanobind(ctx,pairstr)) >= 0 )
        {
            swap->N.pair = pair;
            if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_bobloop,(void *)swap) == 0 )
            {
                reqjson = LP_quotejson(qp);
                LP_swapsfp_update(qp->R.requestid,qp->R.quoteid);
                jaddstr(reqjson,"method","connected");
                jaddstr(reqjson,"pair",pairstr);
                if ( (kmdcoin= LP_coinfind("KMD")) != 0 )
                    jadd(reqjson,"proof",LP_instantdex_txids(0,kmdcoin->smartaddr));
                //char str[65]; printf("BOB pubsock.%d binds to %d (%s)\n",pubsock,pair,bits256_str(str,qp->desthash));
                LP_importaddress(qp->destcoin,qp->destaddr);
                LP_otheraddress(qp->srccoin,otheraddr,qp->destcoin,qp->destaddr);
                LP_importaddress(qp->srccoin,otheraddr);
                {
                    bits256 zero;
                    memset(zero.bytes,0,sizeof(zero));
                    for (i=0; i<1; i++)
                    {
                        LP_reserved_msg(1,qp->srccoin,qp->destcoin,qp->desthash,jprint(reqjson,0));
                        break;
                        sleep(10);
                        if ( swap->received != 0 )
                        {
                            printf("swap %u-%u has started t%u\n",swap->I.req.requestid,swap->I.req.quoteid,swap->received);
                            break;
                        }
                        printf("bob tries %u-%u again i.%d\n",swap->I.req.requestid,swap->I.req.quoteid,i);
                        LP_reserved_msg(1,qp->srccoin,qp->destcoin,zero,jprint(reqjson,0));
                    }
                    sleep(1);
                    printf("send CONNECT for %u-%u\n",qp->R.requestid,qp->R.quoteid);
                    LP_reserved_msg(1,qp->srccoin,qp->destcoin,zero,jprint(reqjson,0));
                    if ( IPC_ENDPOINT >= 0 )
                        LP_queuecommand(0,jprint(reqjson,0),IPC_ENDPOINT,-1,0);
                }
                if ( qp->mpnet != 0 && qp->gtc == 0 )
                {
                    char *msg = jprint(reqjson,0);
                    LP_mpnet_send(0,msg,1,qp->destaddr);
                    free(msg);
                }
                free_json(reqjson);
                retval = 0;
            }
            else
            {
                LP_failedmsg(qp->R.requestid,qp->R.quoteid,-3002,qp->uuidstr);
                printf("error launching swaploop\n");
            }
        }
        else
        {
            LP_failedmsg(qp->R.requestid,qp->R.quoteid,-3003,qp->uuidstr);
            printf("couldnt bind to any port %s\n",pairstr);
        }
    }
    else
    {
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,-3004,qp->uuidstr);
        printf("cant find privkey for %s\n",coin->smartaddr);
    }
    if ( retval < 0 )
    {
        if ( pair >= 0 )
            nn_close(pair);
        LP_availableset(qp->txid,qp->vout);
        LP_availableset(qp->txid2,qp->vout2);
    }
    return(retval);
}

void LP_gtc_iteration(void *ctx,char *myipaddr,int32_t mypubsock)
{
    struct LP_gtcorder *gtc,*tmp; struct LP_quoteinfo *qp; uint64_t destvalue,destvalue2; uint32_t oldest = 0;
    if ( Alice_expiration != 0 )
        return;
    DL_FOREACH_SAFE(GTCorders,gtc,tmp)
    {
        qp = &gtc->Q;
        if ( gtc->cancelled == 0 && (oldest == 0 || gtc->pending < oldest) )
            oldest = gtc->pending;
    }
    DL_FOREACH_SAFE(GTCorders,gtc,tmp)
    {
        qp = &gtc->Q;
        if ( gtc->cancelled == 0 && LP_iseligible(&destvalue,&destvalue2,0,qp->destcoin,qp->desttxid,qp->destvout,qp->destsatoshis,qp->feetxid,qp->feevout) == 0 )
        {
            gtc->cancelled = (uint32_t)time(NULL);
            LP_failedmsg(qp->R.requestid,qp->R.quoteid,-9997,qp->uuidstr);
        }
        if ( gtc->cancelled != 0 )
        {
            portable_mutex_lock(&LP_gtcmutex);
            DL_DELETE(GTCorders,gtc);
            free(gtc);
            portable_mutex_unlock(&LP_gtcmutex);
        }
        else
        {
            if ( gtc->pending <= oldest+60 && time(NULL) > gtc->pending+LP_AUTOTRADE_TIMEOUT*10 )
            {
                gtc->pending = qp->timestamp = (uint32_t)time(NULL);
                LP_query(ctx,myipaddr,mypubsock,"request",qp);
                LP_Alicequery = *qp, LP_Alicemaxprice = gtc->Q.maxprice, Alice_expiration = qp->timestamp + 2*LP_AUTOTRADE_TIMEOUT, LP_Alicedestpubkey = qp->srchash;
                char str[65]; printf("LP_gtc fill.%d gtc.%d %s/%s %.8f vol %.8f dest.(%s) maxprice %.8f etomicdest.(%s) uuid.%s fill.%d gtc.%d\n",qp->fill,qp->gtc,qp->srccoin,qp->destcoin,dstr(qp->satoshis),dstr(qp->destsatoshis),bits256_str(str,LP_Alicedestpubkey),gtc->Q.maxprice,qp->etomicdest,qp->uuidstr,qp->fill,qp->gtc);
                break;
            }
        }
    }
}
*/

lazy_static! {static ref GTC_LOCK: Mutex<()> = Mutex::new(());}

unsafe fn lp_gtc_addorder(qp: *mut lp::LP_quoteinfo) -> () {
    let _lock = unwrap!(GTC_LOCK.lock());
    let gtc = calloc(
        1usize,
        ::std::mem::size_of::<lp::LP_gtcorder>() as usize,
    ) as *mut lp::LP_gtcorder;
    (*gtc).Q = *qp;
    (*gtc).pending = (now_ms() / 1000) as u32;
    if !lp::GTCorders.is_null() {
        (*gtc).prev = (*lp::GTCorders).prev;
        (*(*lp::GTCorders).prev).next = gtc;
        (*lp::GTCorders).prev = gtc;
        (*gtc).next = null_mut();
    } else {
        lp::GTCorders = gtc;
        (*lp::GTCorders).prev = lp::GTCorders;
        (*lp::GTCorders).next = null_mut();
    }
}

fn lp_trade(
    qp: *mut lp::LP_quoteinfo,
    price: f64,
    timeout: i32,
    trade_id: u32,
    dest_pub_key: lp::bits256,
    uuid: *mut c_char,
) -> Result<String, String> {
    unsafe {
        (*qp).txid2 = lp::bits256::default();
        (*qp).txid = lp::bits256::default();
        (*qp).aliceid = lp::LP_aliceid_calc((*qp).desttxid, (*qp).destvout, (*qp).feetxid, (*qp).feevout);
        (*qp).tradeid = if trade_id > 0 {
            trade_id
        } else {
            lp::LP_rand()
        };
        (*qp).srchash = dest_pub_key;
        strcpy((*qp).uuidstr.as_ptr() as *mut c_char, uuid);
        (*qp).maxprice = price;
        (*qp).timestamp = (now_ms()  / 1000) as u32;
        if (*qp).gtc != 0 {
            let uuid_len = strlen((*qp).uuidstr.as_ptr());
            strcpy(
                (*qp).uuidstr[uuid_len - 6..].as_ptr() as *mut c_char,
                CString::new("cccccc").unwrap().as_ptr()
            );
            lp_gtc_addorder(qp);
        }
        // TODO: discuss if LP_query should run in case of gtc order as LP_gtciteration will run it anyway
        lp::LP_query(CString::new("request").unwrap().as_ptr() as *mut c_char, qp);
        lp::LP_Alicequery = *qp;
        lp::LP_Alicemaxprice = (*qp).maxprice;
        lp::Alice_expiration = (*qp).timestamp + timeout as u32;
        lp::LP_Alicedestpubkey = (*qp).srchash;
        if (*qp).gtc == 0 {
            let msg = lp::jprint(lp::LP_quotejson(qp), 1);
            lp::LP_mpnet_send(1, msg, 1, null_mut());
            free_c_ptr(msg as *mut c_void);
        }
        Ok(try_s!(c_char_to_string(lp::LP_recent_swaps(0, uuid))))
    }
}
/*
int32_t LP_quotecmp(int32_t strictflag,struct LP_quoteinfo *qp,struct LP_quoteinfo *qp2)
{
    if ( bits256_nonz(LP_Alicedestpubkey) != 0 )
    {
        if (bits256_cmp(LP_Alicedestpubkey,qp->srchash) != 0 )
        {
            printf("reject quote from non-matching pubkey\n");
            return(-1);
        } else printf("dont reject quote from destpubkey\n");
    }
    if ( bits256_cmp(qp->desthash,qp2->desthash) == 0 && strcmp(qp->srccoin,qp2->srccoin) == 0 && strcmp(qp->destcoin,qp2->destcoin) == 0 && bits256_cmp(qp->desttxid,qp2->desttxid) == 0 && qp->destvout == qp2->destvout && bits256_cmp(qp->feetxid,qp2->feetxid) == 0 && qp->feevout == qp2->feevout && qp->destsatoshis == qp2->destsatoshis && qp->txfee >= qp2->txfee && qp->desttxfee == qp2->desttxfee )
    {
        if ( strictflag == 0 || (qp->aliceid == qp2->aliceid && qp->R.requestid == qp2->R.requestid && qp->R.quoteid == qp2->R.quoteid && qp->vout == qp2->vout && qp->vout2 == qp2->vout2 && qp->satoshis == qp2->satoshis && bits256_cmp(qp->txid,qp2->txid) == 0 && bits256_cmp(qp->txid2,qp2->txid2) == 0 && bits256_cmp(qp->srchash,qp2->srchash) == 0) )
            return(0);
        else printf("strict compare failure\n");
    }
    return(-1);
}

void LP_alicequery_clear()
{
    memset(&LP_Alicequery,0,sizeof(LP_Alicequery));
    memset(&LP_Alicedestpubkey,0,sizeof(LP_Alicedestpubkey));
    LP_Alicemaxprice = 0.;
    Alice_expiration = 0;
}

int32_t LP_alice_eligible(uint32_t quotetime)
{
    if ( Alice_expiration != 0 && quotetime > Alice_expiration )
    {
        if ( LP_Alicequery.uuidstr[0] != 0 )
            LP_failedmsg(LP_Alicequery.R.requestid,LP_Alicequery.R.quoteid,-9999,LP_Alicequery.uuidstr);
        printf("time expired for Alice_request\n");
        LP_alicequery_clear();
    }
    return(Alice_expiration == 0 || time(NULL) < Alice_expiration);
}

char *LP_cancel_order(char *uuidstr)
{
    int32_t num = 0; cJSON *retjson;
    if ( uuidstr != 0 )
    {
        if ( uuidstr[0] == 'G' )
        {
            struct LP_gtcorder *gtc,*tmp;
            DL_FOREACH_SAFE(GTCorders,gtc,tmp)
            {
                if ( strcmp(gtc->Q.uuidstr,uuidstr) == 0 )
                {
                    retjson = cJSON_CreateObject();
                    jaddstr(retjson,"result","success");
                    jaddstr(retjson,"cancelled",uuidstr);
                    jaddnum(retjson,"pending",gtc->pending);
                    if ( gtc->cancelled == 0 )
                    {
                        gtc->cancelled = (uint32_t)time(NULL);
                        jaddstr(retjson,"status","uuid canceled");
                        LP_failedmsg(gtc->Q.R.requestid,gtc->Q.R.quoteid,-9997,gtc->Q.uuidstr);
                    }
                    else
                    {
                        jaddstr(retjson,"status","uuid already canceled");
                        LP_failedmsg(gtc->Q.R.requestid,gtc->Q.R.quoteid,-9996,gtc->Q.uuidstr);
                    }
                }
            }
            return(clonestr("{\"error\":\"gtc uuid not found\"}"));
        }
        else
        {
            num = LP_trades_canceluuid(uuidstr);
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"result","success");
            jaddnum(retjson,"numentries",num);
            if ( strcmp(LP_Alicequery.uuidstr,uuidstr) == 0 )
            {
                LP_failedmsg(LP_Alicequery.R.requestid,LP_Alicequery.R.quoteid,-9998,LP_Alicequery.uuidstr);
                LP_alicequery_clear();
                jaddstr(retjson,"status","uuid canceled");
            } else jaddstr(retjson,"status","will stop trade negotiation, but if swap started it wont cancel");
        }
        return(jprint(retjson,1));
    }
    return(clonestr("{\"error\":\"uuid not cancellable\"}"));
}

char *LP_connectedalice(struct LP_quoteinfo *qp,char *pairstr) // alice
{
    cJSON *retjson; char otheraddr[64],*msg; double bid,ask,price,qprice; int32_t changed,pairsock = -1; int32_t DEXselector = 0; struct LP_utxoinfo *autxo,A,B,*butxo; struct basilisk_swap *swap; struct iguana_info *coin;
    if ( bits256_cmp(qp->desthash,G.LP_mypub25519) != 0 )
    {
        LP_aliceid(qp->tradeid,qp->aliceid,"error1",0,0);
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4000,qp->uuidstr);
        return(clonestr("{\"result\",\"update stats\"}"));
    }
    printf("CONNECTED mpnet.%d fill.%d gtc.%d numpending.%d tradeid.%u requestid.%u quoteid.%u pairstr.%s\n",qp->mpnet,qp->fill,qp->gtc,G.LP_pendingswaps,qp->tradeid,qp->R.requestid,qp->R.quoteid,pairstr!=0?pairstr:"");
    LP_requestinit(&qp->R,qp->srchash,qp->desthash,qp->srccoin,qp->satoshis-qp->txfee,qp->destcoin,qp->destsatoshis-qp->desttxfee,qp->timestamp,qp->quotetime,DEXselector,qp->fill,qp->gtc);
    //printf("calculated requestid.%u quoteid.%u\n",qp->R.requestid,qp->R.quoteid);
    if ( LP_Alicequery.srccoin[0] != 0 && LP_Alicequery.destcoin[0] != 0 )
    {
        LP_mypriceset(0,&changed,LP_Alicequery.destcoin,LP_Alicequery.srccoin,0.);
        LP_mypriceset(0,&changed,LP_Alicequery.srccoin,LP_Alicequery.destcoin,0.);
    }
    LP_alicequery_clear();
    memset(&LP_Alicereserved,0,sizeof(LP_Alicereserved));
    LP_aliceid(qp->tradeid,qp->aliceid,"connected",qp->R.requestid,qp->R.quoteid);
    autxo = &A;
    butxo = &B;
    memset(autxo,0,sizeof(*autxo));
    memset(butxo,0,sizeof(*butxo));
    LP_abutxo_set(autxo,butxo,qp);
    if ( (qprice= LP_quote_validate(autxo,butxo,qp,0)) <= SMALLVAL )
    {
        LP_availableset(qp->desttxid,qp->vout);
        LP_availableset(qp->feetxid,qp->feevout);
        LP_aliceid(qp->tradeid,qp->aliceid,"error4",0,0);
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,qprice,qp->uuidstr);
        printf("quote %s/%s validate error %.0f\n",qp->srccoin,qp->destcoin,qprice);
        return(clonestr("{\"error\":\"quote validation error\"}"));
    }
    if ( LP_myprice(0,&bid,&ask,qp->srccoin,qp->destcoin) <= SMALLVAL || bid <= SMALLVAL )
    {
        printf("this node has no price for %s/%s (%.8f %.8f)\n",qp->destcoin,qp->srccoin,bid,ask);
        LP_availableset(qp->desttxid,qp->vout);
        LP_availableset(qp->feetxid,qp->feevout);
        LP_aliceid(qp->tradeid,qp->aliceid,"error5",0,0);
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4002,qp->uuidstr);
        return(clonestr("{\"error\":\"no price set\"}"));
    }
    //LP_RTmetrics_update(qp->srccoin,qp->destcoin);
    printf("%s/%s bid %.8f ask %.8f values %.8f %.8f\n",qp->srccoin,qp->destcoin,bid,ask,dstr(butxo->payment.value),dstr(butxo->deposit.value));
    price = bid;
    if ( (coin= LP_coinfind(qp->destcoin)) == 0 )
    {
        LP_aliceid(qp->tradeid,qp->aliceid,"error6",0,0);
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4003,qp->uuidstr);
        return(clonestr("{\"error\":\"cant get alicecoin\"}"));
    }
    qp->privkey = LP_privkey(coin->symbol,qp->destaddr,coin->taddr);
    if ( bits256_nonz(qp->privkey) != 0 )//&& qp->quotetime >= qp->timestamp-3 )
    {
        retjson = cJSON_CreateObject();
        if ( (swap= LP_swapinit(0,0,qp->privkey,&qp->R,qp,LP_dynamictrust(qp->othercredits,qp->srchash,LP_kmdvalue(qp->srccoin,qp->satoshis)) > 0)) == 0 )
        {
            jaddstr(retjson,"error","couldnt swapinit");
            LP_availableset(qp->desttxid,qp->vout);
            LP_availableset(qp->feetxid,qp->feevout);
            LP_aliceid(qp->tradeid,qp->aliceid,"error7",qp->R.requestid,qp->R.quoteid);
            LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4004,qp->uuidstr);
            return(jprint(retjson,1));
        }
        if ( pairstr == 0 || pairstr[0] == 0 || (pairsock= nn_socket(AF_SP,NN_PAIR)) < 0 )
        {
            LP_aliceid(qp->tradeid,qp->aliceid,"error8",qp->R.requestid,qp->R.quoteid);
            LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4005,qp->uuidstr);
            jaddstr(retjson,"error","couldnt create pairsock");
        }
        else if ( nn_connect(pairsock,pairstr) >= 0 )
        {
            //timeout = 1;
            //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
            //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
            swap->tradeid = qp->tradeid;
            swap->N.pair = pairsock;
            //autxo->S.swap = swap;
            //swap->utxo = autxo;
            LP_importaddress(qp->srccoin,qp->coinaddr);
            LP_otheraddress(qp->destcoin,otheraddr,qp->srccoin,qp->coinaddr);
            LP_importaddress(qp->srccoin,otheraddr);
            LP_aliceid(qp->tradeid,qp->aliceid,"started",qp->R.requestid,qp->R.quoteid);
            printf("alice pairstr.(%s) pairsock.%d pthread_t %ld\n",pairstr,pairsock,sizeof(pthread_t));
            if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_aliceloop,(void *)swap) == 0 )
            {
                retjson = LP_quotejson(qp);
                jaddstr(retjson,"result","success");
                LP_swapsfp_update(qp->R.requestid,qp->R.quoteid);
                if ( IPC_ENDPOINT >= 0 )
                {
                    msg = jprint(retjson,0);
                    LP_queuecommand(0,msg,IPC_ENDPOINT,-1,0);
                    free(msg);
                }
                //jaddnum(retjson,"requestid",qp->R.requestid);
                //jaddnum(retjson,"quoteid",qp->R.quoteid);
            }
            else
            {
                LP_aliceid(qp->tradeid,qp->aliceid,"error9",qp->R.requestid,qp->R.quoteid);
                jaddstr(retjson,"error","couldnt aliceloop");
                LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4006,qp->uuidstr);
            }
        }
        else
        {
            LP_aliceid(qp->tradeid,qp->aliceid,"error10",qp->R.requestid,qp->R.quoteid);
            printf("connect error %s\n",nn_strerror(nn_errno()));
            LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4007,qp->uuidstr);
        }
        //printf("connected result.(%s)\n",jprint(retjson,0));
        if ( jobj(retjson,"error") != 0 )
        {
            LP_availableset(qp->desttxid,qp->vout);
            LP_availableset(qp->feetxid,qp->feevout);
        }
        return(jprint(retjson,1));
    }
    else
    {
        LP_availableset(qp->desttxid,qp->vout);
        LP_availableset(qp->feetxid,qp->feevout);
        LP_aliceid(qp->tradeid,qp->aliceid,"error11",0,0);
        printf("no privkey found coin.%s %s taddr.%u\n",qp->destcoin,qp->destaddr,coin->taddr);
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4008,qp->uuidstr);
        return(clonestr("{\"error\",\"no privkey\"}"));
    }
}

int32_t LP_aliceonly(char *symbol)
{
    return(0);
}

int32_t LP_validSPV(char *symbol,char *coinaddr,bits256 txid,int32_t vout)
{
    struct electrum_info *ep,*backupep; cJSON *txobj; struct LP_address_utxo *up; struct iguana_info *coin; int32_t height; struct LP_transaction *tx;
    coin = LP_coinfind(symbol);
    if ( coin != 0 && (ep= coin->electrum) != 0 )
    {
        if ( (up= LP_address_utxofind(coin,coinaddr,txid,vout)) == 0 )
        {
            if ( (txobj= electrum_transaction(&height,symbol,ep,&txobj,txid,coinaddr)) != 0 )
                free_json(txobj);
            if ( (tx= LP_transactionfind(coin,txid)) != 0 )
            {
                if ( vout < tx->numvouts && tx->height > 0 )
                {
                    printf("added missing utxo for SPV checking\n");
                    LP_address_utxoadd(0,(uint32_t)time(NULL),"LP_validSPV",coin,coinaddr,txid,vout,tx->outpoints[vout].value,tx->height,-1);
                }
            }
        }
        if ( (up= LP_address_utxofind(coin,coinaddr,txid,vout)) != 0 )
        {
            if ( up->SPV > 0 )
                return(0);
            if ( up->SPV < 0 )
                return(-1);
            if ( (backupep= ep->prev) == 0 )
                backupep = ep;
            up->SPV = LP_merkleproof(coin,coinaddr,backupep,up->U.txid,up->U.height);
            if ( up->SPV < 0 )
                return(-1);
        }
    }
    return(0);
}

double LP_trades_alicevalidate(void *ctx,struct LP_quoteinfo *qp)
{
    double qprice; struct LP_utxoinfo A,B,*autxo,*butxo; char str[65];
    autxo = &A;
    butxo = &B;
    memset(autxo,0,sizeof(*autxo));
    memset(butxo,0,sizeof(*butxo));
    LP_abutxo_set(autxo,butxo,qp);
    if ( (qprice= LP_quote_validate(autxo,butxo,qp,0)) <= SMALLVAL )
    {
        printf("reserved quote validate error %.0f\n",qprice);
        return((int32_t)qprice);
    }
    if ( LP_validSPV(qp->srccoin,qp->coinaddr,qp->txid,qp->vout) < 0 )
    {
        sleep(1);
        if ( LP_validSPV(qp->srccoin,qp->coinaddr,qp->txid,qp->vout) < 0 )
        {
            printf("LP_trades_alicevalidate %s src %s failed SPV check\n",qp->srccoin,bits256_str(str,qp->txid));
            return(-44);
        }
    }
    else if ( LP_validSPV(qp->srccoin,qp->coinaddr,qp->txid2,qp->vout2) < 0 )
    {
        sleep(1);
        if ( LP_validSPV(qp->srccoin,qp->coinaddr,qp->txid2,qp->vout2) < 0 )
        {
            printf("LP_trades_alicevalidate %s src2 %s failed SPV check\n",qp->srccoin,bits256_str(str,qp->txid2));
            return(-55);
        }
    }
    return(qprice);
}

void LP_reserved(void *ctx,char *myipaddr,int32_t mypubsock,struct LP_quoteinfo *qp)
{
    double price=0.,maxprice = LP_Alicemaxprice;
    //if ( LP_quotecmp(0,qp,&LP_Alicequery) == 0 )
    {
        price = LP_pricecache(qp,qp->srccoin,qp->destcoin,qp->txid,qp->vout);
        if ( LP_pricevalid(price) > 0 && maxprice > SMALLVAL && price <= maxprice )
        {
            qp->tradeid = LP_Alicequery.tradeid;
            LP_Alicereserved = *qp;
            LP_alicequery_clear();
            //printf("send CONNECT\n");
            LP_query(ctx,myipaddr,mypubsock,"connect",qp);
        } else printf("LP_reserved %llu price %.8f vs maxprice %.8f\n",(long long)qp->aliceid,price,maxprice);
    } //else printf("probably a timeout, reject reserved due to not eligible.%d or mismatched quote price %.8f vs maxprice %.8f\n",LP_alice_eligible(qp->quotetime),price,maxprice);
}

double LP_trades_bobprice(double *bidp,double *askp,struct LP_quoteinfo *qp)
{
    double price; struct iguana_info *coin; char str[65];
    price = LP_myprice(1,bidp,askp,qp->srccoin,qp->destcoin);
    if ( (coin= LP_coinfind(qp->srccoin)) == 0 || price <= SMALLVAL || *askp <= SMALLVAL )
    {
        //printf("this node has no price for %s/%s\n",qp->srccoin,qp->destcoin);
        return(0.);
    }
    price = *askp;
    //printf("MYPRICE %s/%s %.8f vs qprice %.8f\n",qp->srccoin,qp->destcoin,price,(double)qp->destsatoshis/qp->satoshis);
    if ( LP_validSPV(qp->destcoin,qp->destaddr,qp->desttxid,qp->destvout) < 0 )
    {
        printf("LP_trades_bobprice %s dest %s failed SPV check\n",qp->destcoin,bits256_str(str,qp->desttxid));
        return(0.);
    }
    else if (LP_validSPV(qp->destcoin,qp->destaddr,qp->feetxid,qp->feevout) < 0 )
    {
        printf("LP_trades_bobprice %s dexfee %s failed SPV check\n",qp->destcoin,bits256_str(str,qp->feetxid));
        return(0.);
    }
    return(*askp);
}

double LP_trades_pricevalidate(struct LP_quoteinfo *qp,struct iguana_info *coin,double price)
{
    double qprice; struct LP_utxoinfo A,B,*autxo,*butxo;
    autxo = &A;
    butxo = &B;
    memset(autxo,0,sizeof(*autxo));
    memset(butxo,0,sizeof(*butxo));
    LP_abutxo_set(autxo,butxo,qp);
    if ( coin->etomic[0] == 0 && strcmp(qp->coinaddr,coin->smartaddr) != 0 )
    {
        printf("bob is patching qp->coinaddr %s mismatch != %s\n",qp->coinaddr,coin->smartaddr);
        strcpy(qp->coinaddr,coin->smartaddr);
    }
    if ( butxo == 0 || bits256_nonz(butxo->payment.txid) == 0 || bits256_nonz(butxo->deposit.txid) == 0 || butxo->payment.vout < 0 || butxo->deposit.vout < 0 )
    {
        char str[65],str2[65]; printf("couldnt find bob utxos for autxo %s/v%d %s/v%d %.8f -> %.8f\n",bits256_str(str,qp->txid),qp->vout,bits256_str(str2,qp->txid2),qp->vout2,dstr(qp->satoshis),dstr(qp->destsatoshis));
        return(-66);
    }
    if ( (qprice= LP_quote_validate(autxo,butxo,qp,1)) <= SMALLVAL )
    {
        printf("quote %s/%s validate error %.0f\n",qp->srccoin,qp->destcoin,qprice);
        return(-3);
    }
    if ( qprice < (price - 0.00000001) * 0.998)
    {
        printf(" quote price %.8f (%llu/%llu %.8f) too low vs %.8f for %s/%s price %.8f %.8f\n",qprice,(long long)qp->destsatoshis,(long long)(qp->satoshis-qp->txfee),(double)qp->destsatoshis/(qp->satoshis-qp->txfee),price,qp->srccoin,qp->destcoin,price,(price - 0.00000001) * 0.998);
        return(-77);
    }
    return(qprice);
}

struct LP_quoteinfo *LP_trades_gotrequest(void *ctx,struct LP_quoteinfo *qp,struct LP_quoteinfo *newqp,char *pairstr)
{
    int32_t voliters=10,priceiters=33;
    double price=0.,p=0.,qprice,myprice,bestprice,range,bid,ask; uint64_t satoshis; struct iguana_info *coin,*othercoin; struct LP_utxoinfo A,B,*autxo,*butxo; cJSON *reqjson,*retjson; char str[65],*retstr,*txidstr,*hexstr; struct LP_address_utxo *utxos[4096]; int32_t i,j,notarized,r,num,counter,max = (int32_t)(sizeof(utxos)/sizeof(*utxos));
    *newqp = *qp;
    qp = newqp;
printf("bob %s received REQUEST.(%s) mpnet.%d fill.%d gtc.%d\n",bits256_str(str,G.LP_mypub25519),qp->uuidstr+32,qp->mpnet,qp->fill,qp->gtc);
    if ( (coin= LP_coinfind(qp->srccoin)) == 0 || (othercoin= LP_coinfind(qp->destcoin)) == 0 )
        return(0);
    if ( (myprice= LP_trades_bobprice(&bid,&ask,qp)) == 0. )
    {
        printf("myprice %.8f bid %.8f ask %.8f\n",myprice,bid,ask);
        return(0);
    }
    autxo = &A;
    butxo = &B;
    memset(autxo,0,sizeof(*autxo));
    memset(butxo,0,sizeof(*butxo));
    LP_abutxo_set(autxo,butxo,qp);
    strcpy(qp->coinaddr,coin->smartaddr);
    if ( bits256_nonz(qp->srchash) == 0 || bits256_cmp(qp->srchash,G.LP_mypub25519) == 0 )
    {
        qprice = (double)qp->destsatoshis / (qp->satoshis - qp->txfee);
        strcpy(qp->gui,G.gui);
        if ( coin->etomic[0] != 0 )
            strcpy(qp->etomicsrc,coin->smartaddr);
        else if ( othercoin->etomic[0] != 0 )
            strcpy(qp->etomicsrc,othercoin->smartaddr);
        if ( coin->etomic[0] != 0 )//|| othercoin->etomic[0] != 0 )
        {
            struct iguana_info *ecoin;
            if ( (ecoin= LP_coinfind("ETOMIC")) != 0 )
                strcpy(qp->coinaddr,ecoin->smartaddr);
            else
            {
                printf("ETOMIC coin not found\n");
                return(0);
            }
        }
        strcpy(butxo->coinaddr,qp->coinaddr);
        qp->srchash = G.LP_mypub25519;
        memset(&qp->txid,0,sizeof(qp->txid));
        memset(&qp->txid2,0,sizeof(qp->txid2));
        qp->vout = qp->vout2 = -1;
    } else return(0);
    if ( qprice >= myprice )
    {
        r = (LP_rand() % 90) + 10;
        range = (qprice - myprice);
        price = myprice + ((r * range) / 100.);
        bestprice = LP_bob_competition(&counter,qp->aliceid,price,0);
        printf("%llu >>>>>>> myprice %.8f qprice %.8f r.%d range %.8f -> %.8f, bestprice %.8f counter.%d\n",(long long)qp->aliceid,myprice,qprice,r,range,price,bestprice,counter);
        if ( counter > 3 && price > bestprice+SMALLVAL ) // skip if late or bad price
            return(0);
    }
    else
    {
        printf("%s/%s ignore as qprice %.8f vs myprice %.8f\n",qp->srccoin,qp->destcoin,qprice,myprice);
        return(0);
    }
    //LP_RTmetrics_update(qp->srccoin,qp->destcoin);
    if ( LP_RTmetrics_blacklisted(qp->desthash) >= 0 )
    {
        printf("request from blacklisted %s, ignore\n",bits256_str(str,qp->desthash));
        return(0);
    }
    //printf("LP_address_utxo_reset.%s\n",coin->symbol);
    //LP_address_utxo_reset(coin);
    //printf("done LP_address_utxo_reset.%s\n",coin->symbol);
    if ( coin->etomic[0] != 0 )
        strcpy(qp->etomicsrc,coin->smartaddr);
    else if ( othercoin->etomic[0] != 0 )
        strcpy(qp->etomicsrc,othercoin->smartaddr);
    if ( coin->etomic[0] != 0 )//|| othercoin->etomic[0] != 0 )
    {
        struct iguana_info *ecoin;
        if ( (ecoin= LP_coinfind("ETOMIC")) != 0 )
            strcpy(qp->coinaddr,ecoin->smartaddr);
        else
        {
            printf("ETOMIC coin not found\n");
            return(0);
        }
    }
    LP_address_utxo_reset(&num,coin);
    i = 0;
    while ( i < priceiters && price >= myprice )
    {
        for (j=0; j<voliters; j++)
        {
            printf("priceiter.%d voliter.%d price %.8f vol %.8f\n",i,j,price,dstr(qp->destsatoshis));
            if ( (butxo= LP_address_myutxopair(&B,1,utxos,max,coin,qp->coinaddr,qp->txfee,dstr(qp->destsatoshis),price,qp->desttxfee)) != 0 )
            {
                strcpy(qp->gui,G.gui);
                strcpy(qp->coinaddr,coin->smartaddr);
                qp->srchash = G.LP_mypub25519;
                qp->txid = butxo->payment.txid;
                qp->vout = butxo->payment.vout;
                qp->txid2 = butxo->deposit.txid;
                qp->vout2 = butxo->deposit.vout;
                if (coin->etomic[0] == 0) {
                    qp->satoshis = butxo->swap_satoshis;// + qp->txfee;
                } else {
                    qp->satoshis = LP_basesatoshis(dstr(qp->destsatoshis), price, qp->txfee, qp->desttxfee);
                }
                qp->quotetime = (uint32_t)time(NULL);
                break;
            }
            if ( qp->fill != 0 )
                break;
            qp->destsatoshis = (qp->destsatoshis * 2) / 3;
        }
        if ( butxo != 0 && j < voliters )
        {
            if ( qp->satoshis <= qp->txfee )
                return(0);
            p = (double)qp->destsatoshis / (qp->satoshis - qp->txfee);
            if ( LP_trades_pricevalidate(qp,coin,p) < 0. )
            {
                if ( qp->fill != 0 )
                    return(0);
                price *= 0.995;
                i++;
                continue;
            }
            if ( i == 0 && p < myprice )
            {
                price = qprice;
                printf("reset price <- qprice %.8f\n",qprice);
            }
            else
            {
                if ( qprice >= p || qp->fill != 0 )
                    break;
                price *= 0.995;
            }
            if ( qp->fill != 0 )
                break;
            i++;
        }
        else if ( qp->fill != 0 || i == priceiters )
        {
            printf("i.%d cant find utxopair aliceid.%llu %s/%s %.8f -> relvol %.8f txfee %.8f\n",i,(long long)qp->aliceid,qp->srccoin,qp->destcoin,dstr(LP_basesatoshis(dstr(qp->destsatoshis),price,qp->txfee,qp->desttxfee)),dstr(qp->destsatoshis),dstr(qp->txfee));
            if ( qp->gtc != 0 && qp->fill != 0 && coin != 0 && coin->electrum == 0 )
            {
                LP_address_utxo_reset(&num,coin);
                satoshis = LP_basesatoshis(dstr(qp->destsatoshis),price,qp->txfee,qp->desttxfee) + 3*qp->txfee;
                if ( LP_getheight(&notarized,coin) > coin->bobfillheight+3 && fabs((double)coin->fillsatoshis - satoshis)/satoshis > 0.1 )
                {
                    printf("queue up do_autofill_merge %.8f\n",dstr(satoshis));
                    coin->do_autofill_merge = satoshis;
                }
            }
            return(0);
        }
        else
        {
            price *= 0.995;
            i++;
        }
    }
    printf("%s/%s i.%d j.%d qprice %.8f myprice %.8f price %.8f [%.8f]\n",qp->srccoin,qp->destcoin,i,j,qprice,myprice,price,p);
    if ( butxo != 0 && bits256_nonz(qp->txid) != 0 && bits256_nonz(qp->txid2) != 0 && LP_allocated(qp->txid,qp->vout) == 0 && LP_allocated(qp->txid2,qp->vout2) == 0 )
    {
        //printf("found unallocated txids\n");
        reqjson = LP_quotejson(qp);
        LP_unavailableset(qp->txid,qp->vout,qp->timestamp + LP_RESERVETIME,qp->desthash);
        LP_unavailableset(qp->txid2,qp->vout2,qp->timestamp + LP_RESERVETIME,qp->desthash);
        if ( qp->quotetime == 0 )
            qp->quotetime = (uint32_t)time(NULL);
        jaddnum(reqjson,"quotetime",qp->quotetime);
        jaddnum(reqjson,"pending",qp->timestamp + LP_RESERVETIME);
        jaddstr(reqjson,"method","reserved");
        {
            LP_reserved_msg(1,qp->srccoin,qp->destcoin,qp->desthash,jprint(reqjson,0));
            bits256 zero;
            memset(zero.bytes,0,sizeof(zero));
            LP_reserved_msg(1,qp->srccoin,qp->destcoin,zero,jprint(reqjson,0));
        }
        if ( qp->mpnet != 0 && qp->gtc == 0 )
        {
            char *msg = jprint(reqjson,0);
            LP_mpnet_send(0,msg,1,qp->destaddr);
            free(msg);
        }
        free_json(reqjson);
        //printf("Send RESERVED id.%llu\n",(long long)qp->aliceid);
        return(qp);
    } else printf("request processing selected ineligible utxos?\n");
    return(0);
}

struct LP_quoteinfo *LP_trades_gotreserved(void *ctx,struct LP_quoteinfo *qp,struct LP_quoteinfo *newqp)
{
    char *retstr; double qprice;
    char str[65]; printf("alice %s received RESERVED.(%s) %.8f mpnet.%d fill.%d gtc.%d\n",bits256_str(str,G.LP_mypub25519),qp->uuidstr+32,(double)qp->destsatoshis/(qp->satoshis+1),qp->mpnet,qp->fill,qp->gtc);
    *newqp = *qp;
    qp = newqp;
    if ( (qprice= LP_trades_alicevalidate(ctx,qp)) > 0. )
    {
        //printf("got qprice %.8f\n",qprice);
        LP_aliceid(qp->tradeid,qp->aliceid,"reserved",0,0);
        if ( (retstr= LP_quotereceived(qp)) != 0 )
            free(retstr);
        return(qp);
    } else LP_failedmsg(qp->R.requestid,qp->R.quoteid,qprice,qp->uuidstr);
    return(0);
}

struct LP_quoteinfo *LP_trades_gotconnect(void *ctx,struct LP_quoteinfo *qp,struct LP_quoteinfo *newqp,char *pairstr)
{
    double myprice,qprice,bid,ask; struct iguana_info *coin;
    *newqp = *qp;
    qp = newqp;
    if ( (coin= LP_coinfind(qp->srccoin)) == 0 )
       return(0);
    if ( (myprice= LP_trades_bobprice(&bid,&ask,qp)) == 0. )
        return(0);
    if ( (qprice= LP_trades_pricevalidate(qp,coin,myprice)) < 0. )
        return(0);
    if ( LP_reservation_check(qp->txid,qp->vout,qp->desthash) == 0 && LP_reservation_check(qp->txid2,qp->vout2,qp->desthash) == 0  )
    {
        char str[65]; printf("bob %s received CONNECT.(%s)\n",bits256_str(str,G.LP_mypub25519),qp->uuidstr+32);
        LP_connectstartbob(ctx,LP_mypubsock,qp->srccoin,qp->destcoin,qprice,qp);
        return(qp);
    }
    else
    {
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,-1,qp->uuidstr);
        printf("connect message from non-reserved (%llu)\n",(long long)qp->aliceid);
    }
    return(0);
}

struct LP_quoteinfo *LP_trades_gotconnected(void *ctx,struct LP_quoteinfo *qp,struct LP_quoteinfo *newqp,char *pairstr)
{
    char *retstr; int32_t changed; double val;
    char str[65]; printf("alice %s received CONNECTED.(%llu) mpnet.%d fill.%d gtc.%d\n",bits256_str(str,G.LP_mypub25519),(long long)qp->aliceid,qp->mpnet,qp->fill,qp->gtc);
    *newqp = *qp;
    qp = newqp;
    if ( (val= LP_trades_alicevalidate(ctx,qp)) > 0. )
    {
        //printf("CONNECTED ALICE uuid.%s\n",qp->uuidstr);
        LP_aliceid(qp->tradeid,qp->aliceid,"connected",0,0);
        if ( (retstr= LP_connectedalice(qp,pairstr)) != 0 )
            free(retstr);
        LP_mypriceset(0,&changed,qp->destcoin,qp->srccoin,0.);
        LP_alicequery_clear();
        return(qp);
    } else LP_failedmsg(qp->R.requestid,qp->R.quoteid,val,qp->uuidstr);
    //printf("LP_trades_alicevalidate error\n");
    return(0);
}

int32_t LP_trades_bestpricecheck(void *ctx,struct LP_trade *tp)
{
    double qprice; int32_t flag = 0; struct LP_quoteinfo Q; int64_t dynamictrust; char *retstr; struct LP_pubkey_info *pubp;
    Q = tp->Q;
    //printf("check bestprice %.8f vs new price %.8f\n",tp->bestprice,(double)Q.destsatoshis/Q.satoshis);
    if ( Q.satoshis != 0 && (pubp= LP_pubkeyadd(Q.srchash)) != 0 )//(qprice= LP_trades_alicevalidate(ctx,&Q)) > 0. )
    {
        qprice = (double)Q.destsatoshis / (Q.satoshis - Q.txfee);
        LP_aliceid(Q.tradeid,tp->aliceid,"reserved",0,0);
        if ( (retstr= LP_quotereceived(&Q)) != 0 )
            free(retstr);
        //LP_trades_gotreserved(ctx,&Q,&tp->Qs[LP_RESERVED]);
        dynamictrust = LP_dynamictrust(Q.othercredits,Q.srchash,LP_kmdvalue(Q.srccoin,Q.satoshis));
        if ( tp->bestprice == 0. )
            flag = 1;
        else if ( qprice < tp->bestprice && pubp->slowresponse <= tp->bestresponse*1.05 )
            flag = 1;
        else if ( qprice < tp->bestprice*1.01 && dynamictrust > tp->besttrust && pubp->slowresponse <= tp->bestresponse*1.1 )
            flag = 1;
        else if ( qprice <= tp->bestprice && pubp->unconfcredits > tp->bestunconfcredits && pubp->slowresponse <= tp->bestresponse )
            flag = 1;
        if ( flag != 0 )
        {
            tp->Qs[LP_CONNECT] = tp->Q;
            tp->bestprice = qprice;
            tp->besttrust = dynamictrust;
            tp->bestunconfcredits = pubp->unconfcredits;
            tp->bestresponse = pubp->slowresponse;
            printf("aliceid.%llu got new bestprice %.8f dynamictrust %.8f (unconf %.8f) slowresponse.%d\n",(long long)tp->aliceid,tp->bestprice,dstr(dynamictrust),dstr(tp->bestunconfcredits),tp->bestresponse);
            return(qprice);
        } //else printf("qprice %.8f dynamictrust %.8f not good enough\n",qprice,dstr(dynamictrust));
    } else printf("alice didnt validate\n");
    return(0);
}

int32_t LP_trades_canceluuid(char *uuidstr)
{
    int32_t num = 0; struct LP_trade *qtp,*tp,*tmp;
    HASH_ITER(hh,LP_trades,tp,tmp)
    {
        if ( strcmp(tp->Q.uuidstr,uuidstr) == 0 )
        {
            tp->cancelled = (uint32_t)time(NULL);
            num++;
        }
    }
    DL_FOREACH_SAFE(LP_tradesQ,qtp,tmp)
    {
        if ( strcmp(qtp->Q.uuidstr,uuidstr) == 0 )
        {
            qtp->cancelled = (uint32_t)time(NULL);
            num++;
        }
    }
    if ( num > 0 )
        fprintf(stderr,"uuid.%s %d cancelled\n",uuidstr,num);
    return(num);
}
*/
pub unsafe fn lp_trades_loop(ctx: MmArc) {
    let mut coin: *mut lp::iguana_info;
    let mut timeout: u32;
    let mut now: u64;
    let mut q: lp::LP_quoteinfo;
    let mut funcid: u32;
    let mut flag: i32;
    let mut pubp: *mut lp::LP_pubkey_info;
    thread::sleep(Duration::from_secs(5));

    loop {
        if ctx.is_stopping() { break }

        let ordermatch_ctx = unwrap!(OrdermatchContext::from_ctx(&ctx));
        let mut trades_map = unwrap!(ordermatch_ctx.lp_trades.lock());
        let mut nonz = 0;
        for (_, trade) in trades_map.iter_mut() {
            if trade.negotiationdone != 0 || trade.cancelled != 0 {
                continue;
            }
            timeout = lp::LP_AUTOTRADE_TIMEOUT;
            coin = lp::LP_coinfind(trade.Q.srccoin.as_mut_ptr());
            if coin != null_mut() && (*coin).electrum != null_mut() {
                timeout += (lp::LP_AUTOTRADE_TIMEOUT as f64 * 0.5) as u32;
            }
            coin = lp::LP_coinfind(trade.Q.destcoin.as_mut_ptr());
            if coin != null_mut() && (*coin).electrum != null_mut() {
                timeout += (lp::LP_AUTOTRADE_TIMEOUT as f64 * 0.5) as u32;
            }
            now = now_ms() / 1000;
            if now > trade.lastprocessed && trade.iambob == 0 && trade.bestprice > 0. {
                if trade.connectsent == 0 {
                    lp::LP_Alicemaxprice = trade.bestprice;
                    lp::LP_reserved(&mut trade.Qs[lp::LP_CONNECT as usize]); // send LP_CONNECT
                    (*trade).connectsent = now;
                    //printf("send LP_connect aliceid.%llu %.8f\n",(long long)tp->aliceid,tp->bestprice);
                } else if now < trade.firstprocessed + timeout as u64 && ((trade.firstprocessed  + timeout as u64 - now) % 20) == 19 {
                    //LP_Alicemaxprice = tp->bestprice;
                    //LP_reserved(ctx,LP_myipaddr,LP_mypubsock,&tp->Qs[LP_CONNECT]); // send LP_CONNECT
                    //printf("mark slow LP_connect aliceid.%llu %.8f\n",(long long)tp->aliceid,tp->bestprice);
                    pubp = lp::LP_pubkeyfind(trade.Qs[lp::LP_CONNECT as usize].srchash);
                    if !pubp.is_null() {
                        (*pubp).slowresponse += 1;
                    }
                }
            }
        }
        now = now_ms() / 1000;
        for (key, trade) in (*trades_map).clone().iter_mut() {
            timeout = lp::LP_AUTOTRADE_TIMEOUT;
            coin = lp::LP_coinfind(trade.Q.srccoin.as_mut_ptr());
            if coin != null_mut() && (*coin).electrum != null_mut() {
                timeout += (lp::LP_AUTOTRADE_TIMEOUT as f64 * 0.5) as u32;
            }
            coin = lp::LP_coinfind(trade.Q.destcoin.as_mut_ptr());
            if coin != null_mut() && (*coin).electrum != null_mut() {
                timeout += (lp::LP_AUTOTRADE_TIMEOUT as f64 * 0.5) as u32;
            }
            if now > trade.firstprocessed + timeout as u64 * 10 || trade.cancelled != 0 {
                //printf("purge swap aliceid.%llu\n",(long long)tp->aliceid);
                trades_map.remove(key);
            }
        }

        while !ordermatch_ctx.is_trade_queue_empty() {
            now = now_ms() / 1000;
            let mut qtp = unwrap!(ordermatch_ctx.pop_trade_from_queue());
            q = qtp.Q;
            funcid = qtp.funcid;
//printf("dequeue %p funcid.%d aliceid.%llu iambob.%d\n",qtp,funcid,(long long)qtp->aliceid,qtp->iambob);
            match trades_map.entry(qtp.aliceid) {
                Entry::Occupied(t) => {
                    if t.get().cancelled != 0 {
                        t.remove();
                        continue;
                    }
                },
                Entry::Vacant(t) => {
                    if now > (q.timestamp + lp::LP_AUTOTRADE_TIMEOUT * 2) as u64 || qtp.cancelled != 0 {
                        // eat expired?
                    } else {
                        if qtp.iambob != 0 && funcid == lp::LP_REQUEST { // bob maybe sends LP_RESERVED
                            let qp = lp::LP_trades_gotrequest(
                                &mut q,
                                &mut qtp.Qs[lp::LP_REQUEST as usize],
                            );
                            if qp != null_mut() {
                                qtp.Qs[lp::LP_RESERVED as usize] = q;
                            }
                        } else if qtp.iambob == 0 && funcid == lp::LP_RESERVED { // alice maybe sends LP_CONNECT
                            lp::LP_trades_bestpricecheck(
                                ctx.btc_ctx() as *mut c_void,
                                &mut qtp
                            );
                        } else if qtp.iambob == 0 && funcid == lp::LP_CONNECTED {
                            qtp.negotiationdone = now;
                            //printf("alice sets negotiationdone.%u\n",now);
                            lp::LP_trades_gotconnected(
                                ctx.btc_ctx() as *mut c_void,
                                &mut qtp.Q,
                                &mut qtp.Qs[lp::LP_CONNECTED as usize],
                                qtp.pairstr.as_mut_ptr()
                            );
                        }
                        nonz += 1;
                        qtp.firstprocessed =  now_ms() / 1000;
                        qtp.lastprocessed =  now_ms() / 1000;
                        if funcid == lp::LP_CONNECT && qtp.negotiationdone == 0 { // bob all done
                            qtp.negotiationdone = now;
                            //printf("bob sets negotiationdone.%u\n",now);
                            lp::LP_trades_gotconnect(
                                ctx.btc_ctx() as *mut c_void,
                                &mut qtp.Q,
                                &mut qtp.Qs[lp::LP_CONNECT as usize],
                            );
                        }
                        t.insert(qtp);
                    }
                    continue;
                }
            };

            let trade = unwrap!(trades_map.get_mut(&qtp.aliceid));
            (*trade).Q = qtp.Q;
            if qtp.iambob == trade.iambob && qtp.pairstr[0] != 0 {
                strcpy(trade.pairstr.as_mut_ptr(), qtp.pairstr.as_ptr());
            }
//printf("finished dequeue %p funcid.%d aliceid.%llu iambob.%d/%d done.%u\n",qtp,funcid,(long long)qtp->aliceid,qtp->iambob,tp->iambob,tp->negotiationdone);
            flag = 0;
            if trade.iambob == 0 {
                if funcid == lp::LP_RESERVED {
                    if trade.connectsent == 0 {
                        flag = lp::LP_trades_bestpricecheck(ctx.btc_ctx() as *mut c_void, trade);
                    }
                } else if funcid == lp::LP_CONNECTED && trade.negotiationdone == 0 { // alice all done  tp->connectsent != 0 &&
                    flag = 1;
                    (*trade).negotiationdone = now;
                    lp::LP_trades_gotconnected(
                        ctx.btc_ctx() as *mut c_void,
                        &mut trade.Q,
                        &mut trade.Qs[lp::LP_CONNECTED as usize],
                        trade.pairstr.as_mut_ptr()
                    );
                }
            } else {
                if funcid == lp::LP_REQUEST { // bob maybe sends LP_RESERVED
                    let qp = lp::LP_trades_gotrequest(
                        &mut q,
                        &mut trade.Qs[lp::LP_REQUEST as usize],
                    );
                    if !qp.is_null() {
                        (*trade).Qs[lp::LP_RESERVED as usize] = q;
                        flag = 1;
                    }
                } else if funcid == lp::LP_CONNECT && trade.negotiationdone == 0 { // bob all done
                    flag = 1;
                    (*trade).negotiationdone = now;
                    //printf("bob sets negotiationdone.%u\n",now);
                    lp::LP_trades_gotconnect(
                        ctx.btc_ctx() as *mut c_void,
                        &mut trade.Q,
                        &mut trade.Qs[lp::LP_CONNECT as usize],
                    );
                }
            }
            if flag != 0 {
                (*trade).lastprocessed = now_ms() / 1000;
                nonz += 1;
            }
        }
        // drop trades map before sleeping to unlock the mutex
        drop(trades_map);
        if nonz == 0 {
            thread::sleep(Duration::from_secs(1));
        }
    }
}

unsafe fn lp_trade_command_q(ctx: &MmArc, qp: *mut lp::LP_quoteinfo, pairstr: *mut c_char, funcid: u32) {
    let ordermatch_ctx = unwrap!(OrdermatchContext::from_ctx(ctx));

    let mut trade = lp::LP_trade::default();
    if funcid >= 4 {
        return;
    }
    trade.iambob = if funcid == lp::LP_REQUEST || funcid == lp::LP_CONNECT {
        1
    } else {
        0
    };
    trade.aliceid = (*qp).aliceid;
    trade.funcid = funcid;
    trade.newtime = now_ms() / 1000;
    trade.Q = *qp;
    if pairstr != null_mut() {
        strcpy(trade.pairstr.as_mut_ptr(), pairstr);
    }
    ordermatch_ctx.add_trade_to_queue(trade);
}

pub unsafe fn lp_trade_command(
    ctx: MmArc,
    json: Json,
    c_json: &CJSON,
) -> i32 {
    let q_trades: i32 = 1;
    let mut str: [libc::c_char; 65] = [0; 65];
    let mut i: i32;
    let mut num: i32 = 0;
    let dex_selector: i32 = 0;
    let aliceid: u64;
    let qprice: f64;
    let price: f64;
    let mut bid: f64 = 0.;
    let mut ask: f64 = 0.;
    let rq: u64;
    let coin: *mut lp::iguana_info;
    let mut q = lp::LP_quoteinfo::default();
    let mut q2 = lp::LP_quoteinfo::default();
    let mut counter: i32 = 0;
    let mut retval: i32 = -1i32;
    let mut proof : *mut lp::cJSON;
    let method = json["method"].as_str();
    match method {
        Some("reserved") | Some("connected") | Some("request") | Some("connect") => {
            if lp::LP_quoteparse(&mut q, c_json.0) < 0 {
                printf(
                    b"ERROR parsing.(%s)\n\x00" as *const u8 as *const libc::c_char,
                    lp::jprint(c_json.0, 0),
                );
                return 1i32;
            } else if q.satoshis < q.txfee {
                return 1i32;
            } else {
                lp::LP_requestinit(
                    &mut q.R,
                    q.srchash,
                    q.desthash,
                    q.srccoin.as_mut_ptr(),
                    q.satoshis.wrapping_sub(q.txfee),
                    q.destcoin.as_mut_ptr(),
                    q.destsatoshis.wrapping_sub(q.desttxfee),
                    q.timestamp,
                    q.quotetime,
                    dex_selector,
                    q.fill as i32,
                    q.gtc as i32,
                );
                rq = (q.R.requestid as u64) << 32i32 | q.R.quoteid as u64;
                // eat expired packets, some old timestamps floating about?
                if q.uuidstr[0usize] == 0 || q.timestamp > 0 && now_ms() / 1000 > q.timestamp.wrapping_add(30 * 20) as u64 {
                    printf(
                        b"uuid.%s aliceid.%llu is expired by %d\n\x00" as *const u8
                            as *const libc::c_char,
                        q.uuidstr.as_mut_ptr().offset(32isize),
                        q.aliceid as libc::c_longlong,
                        (now_ms() / 1000).wrapping_sub(q.timestamp.wrapping_add(60) as u64));
                    return 1i32;
                } else {
                    lp::LP_tradecommand_log(c_json.0);
                    //jdouble(argjson,"price");
                    qprice = q.destsatoshis as f64
                        / q.satoshis.wrapping_sub(q.txfee) as f64;
                    //printf("%s\n",jprint(argjson,0));
                    retval = 1i32;
                    aliceid = lp::j64bits(
                        c_json.0,
                        b"aliceid\x00" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    );
                    if method == Some("reserved") {
                        lp::LP_bob_competition(&mut counter, aliceid, qprice, 1i32);
                        //printf("%s lag %ld: aliceid.%llu price %.8f -> bestprice %.8f Alice max %.8f\n",jprint(argjson,0),Q.quotetime - (time(NULL)-20),(long long)aliceid,qprice,bestprice,LP_Alicemaxprice);
                        if lp::LP_Alicemaxprice == 0.0f64 {
                            return retval;
                        } else {
                            if (lp::LP_Alicedestpubkey.ulongs[0usize]
                                | lp::LP_Alicedestpubkey.ulongs[1usize]
                                | lp::LP_Alicedestpubkey.ulongs[2usize]
                                | lp::LP_Alicedestpubkey.ulongs[3usize]
                                != 0 as u64) as libc::c_int
                                != 0
                                {
                                    if lp::bits256_cmp(lp::LP_Alicedestpubkey, q.srchash) != 0 {
                                        printf(
                                            b"got reserved response from different node %s\n\x00"
                                                as *const u8
                                                as *const libc::c_char,
                                            lp::bits256_str(str.as_mut_ptr(), q.srchash),
                                        );
                                        return retval;
                                    } else {
                                        printf(
                                            b"got reserved response from destpubkey %s\n\x00" as *const u8
                                                as *const libc::c_char,
                                            lp::bits256_str(str.as_mut_ptr(), q.srchash),
                                        );
                                    }
                                }
                            // alice
                            if lp::bits256_cmp(lp::G.LP_mypub25519, q.desthash) == 0
                                && lp::bits256_cmp(lp::G.LP_mypub25519, q.srchash) != 0
                                && (q.vout != q.vout2 || lp::bits256_cmp(q.txid, q.txid2) != 0)
                                {
                                    if q_trades == 0 {
                                        if q.quotetime as u64 > now_ms() / 1000
                                            && lp::LP_alice_eligible(q.quotetime) > 0
                                            {
                                                lp::LP_trades_gotreserved(ctx.btc_ctx() as *mut c_void, &mut q, &mut q2);
                                                if lp::LP_quotecmp(0, &mut q, &mut lp::LP_Alicequery) == 0 {
                                                    lp::LP_reserved(
                                                        &mut q,
                                                    );
                                                }
                                            }
                                    } else {
                                        lp_trade_command_q(
                                            &ctx,
                                            &mut q,
                                            lp::jstr(
                                                c_json.0,
                                                b"pair\x00" as *const u8 as *const libc::c_char
                                                    as *mut libc::c_char,
                                            ),
                                            1,
                                        );
                                    }
                                }
                        }
                    } else if method == Some("connected") {
                        lp::LP_bob_competition(&mut counter, aliceid, qprice, 1000);
                        // alice
                        if lp::bits256_cmp(lp::G.LP_mypub25519, q.desthash) == 0
                            && lp::bits256_cmp(lp::G.LP_mypub25519, q.srchash) != 0
                            {
                                static mut RQS: [u64; 1024] = [0; 1024];
                                i = 0;
                                while (i as u64)
                                    < (::std::mem::size_of::<[u64; 1024]>() as u64)
                                    .wrapping_div(::std::mem::size_of::<u64>() as u64)
                                    {
                                        if rq == RQS[i as usize] {
                                            return retval;
                                        } else {
                                            i += 1
                                        }
                                    }
                                i = 0;
                                while (i as u64)
                                    < (::std::mem::size_of::<[u64; 1024]>() as u64)
                                    .wrapping_div(::std::mem::size_of::<u64>() as u64)
                                    {
                                        if RQS[i as usize] == 0 as u64 {
                                            break;
                                        }
                                        i += 1
                                    }
                                if i as u64
                                    == (::std::mem::size_of::<[u64; 1024]>() as u64)
                                    .wrapping_div(::std::mem::size_of::<u64>() as u64)
                                    {
                                        i = (rand() as u64).wrapping_rem(
                                            (::std::mem::size_of::<[u64; 1024]>() as u64)
                                                .wrapping_div(
                                                    ::std::mem::size_of::<u64>() as u64
                                                ),
                                        ) as i32
                                    }
                                RQS[i as usize] = rq;
                                printf(
                                    b"CONNECTED.(%s)\n\x00" as *const u8 as *const libc::c_char,
                                    lp::jprint(c_json.0, 0),
                                );
                                proof = lp::jarray(
                                    &mut num,
                                    c_json.0,
                                    b"proof\x00" as *const u8 as *const libc::c_char as *mut libc::c_char,
                                );
                                if !proof.is_null() && num > 0 {
                                    q.othercredits = lp::LP_instantdex_proofcheck(
                                        q.srccoin.as_mut_ptr(),
                                        q.coinaddr.as_mut_ptr(),
                                        proof,
                                        num,
                                    )
                                }
                                if q_trades == 0 {
                                    lp::LP_trades_gotconnected(
                                        ctx.btc_ctx() as *mut c_void,
                                        &mut q,
                                        &mut q2,
                                        lp::jstr(
                                            c_json.0,
                                            b"pair\x00" as *const u8 as *const libc::c_char
                                                as *mut libc::c_char,
                                        ),
                                    );
                                } else {
                                    lp_trade_command_q(
                                        &ctx,
                                        &mut q,
                                        lp::jstr(
                                            c_json.0,
                                            b"pair\x00" as *const u8 as *const libc::c_char
                                                as *mut libc::c_char,
                                        ),
                                        3,
                                    );
                                }
                            }
                    }
                    // bob
                    if method == Some("request") || method == Some("connect") {
                        price = lp::LP_myprice(
                            1i32,
                            &mut bid,
                            &mut ask,
                            q.srccoin.as_mut_ptr(),
                            q.destcoin.as_mut_ptr(),
                        )
                    } else {
                        price = lp::LP_myprice(
                            0,
                            &mut bid,
                            &mut ask,
                            q.srccoin.as_mut_ptr(),
                            q.destcoin.as_mut_ptr(),
                        )
                    }
                    coin = lp::LP_coinfind(q.srccoin.as_mut_ptr());
                    if coin.is_null() || (*coin).inactive != 0 as libc::c_uint {
                        //printf("%s is not active\n",Q.srccoin);
                        return retval;
                    } else if price <= 1e-15f64 || ask <= 1e-15f64 {
                        //printf("this node has no price for %s/%s\n",Q.srccoin,Q.destcoin);
                        return retval;
                    } else {
                        // bob
                        if method == Some("request") {
                            //if ( LP_Alicemaxprice != 0. )
                            //    return(retval);
                            if q.destvout != q.feevout || lp::bits256_cmp(q.desttxid, q.feetxid) != 0 {
                                lp::LP_bob_competition(&mut counter, aliceid, qprice, -1i32);
                                //printf("bestprice %.8f\n",bestprice);
                                //|| (bits256_cmp(Q.srchash,G.LP_mypub25519) == 0 && bits256_cmp(G.LP_mypub25519,Q.desthash) != 0) )
                                if q_trades == 0 {
                                    lp::LP_trades_gotrequest(
                                        &mut q,
                                        &mut q2,
                                    );
                                } else {
                                    lp_trade_command_q(
                                        &ctx,
                                        &mut q,
                                        lp::jstr(
                                            c_json.0,
                                            b"pair\x00" as *const u8 as *const libc::c_char
                                                as *mut libc::c_char,
                                        ),
                                        0,
                                    );
                                }
                            }
                        } else if method == Some("connect") {
                                lp::LP_bob_competition(&mut counter, aliceid, qprice, 1000);
                                // bob
                                if lp::bits256_cmp(lp::G.LP_mypub25519, q.srchash) == 0
                                    && lp::bits256_cmp(lp::G.LP_mypub25519, q.desthash) != 0
                                    {
                                        static mut RQS_0: [u64; 1024] = [0; 1024];
                                        i = 0;
                                        while (i as u64)
                                            < (::std::mem::size_of::<[u64; 1024]>() as u64)
                                            .wrapping_div(::std::mem::size_of::<u64>() as u64)
                                            {
                                                if rq == RQS_0[i as usize] {
                                                    return retval;
                                                } else {
                                                    i += 1
                                                }
                                            }
                                        i = 0;
                                        while (i as u64)
                                            < (::std::mem::size_of::<[u64; 1024]>() as u64)
                                            .wrapping_div(::std::mem::size_of::<u64>() as u64)
                                            {
                                                if RQS_0[i as usize] == 0 as u64 {
                                                    break;
                                                }
                                                i += 1
                                            }
                                        if i as u64
                                            == (::std::mem::size_of::<[u64; 1024]>() as u64)
                                            .wrapping_div(::std::mem::size_of::<u64>() as u64)
                                            {
                                                i = (rand() as u64).wrapping_rem(
                                                    (::std::mem::size_of::<[u64; 1024]>() as u64)
                                                        .wrapping_div(
                                                            ::std::mem::size_of::<u64>() as u64
                                                        ),
                                                ) as i32
                                            }
                                        RQS_0[i as usize] = rq;
                                        printf(
                                            b"CONNECT.(%s)\n\x00" as *const u8 as *const libc::c_char,
                                            lp::jprint(c_json.0, 0),
                                        );
                                        proof = lp::jarray(
                                            &mut num,
                                            c_json.0,
                                            b"proof\x00" as *const u8 as *const libc::c_char
                                                as *mut libc::c_char,
                                        );
                                        if !proof.is_null() && num > 0 {
                                            q.othercredits = lp::LP_instantdex_proofcheck(
                                                q.destcoin.as_mut_ptr(),
                                                q.destaddr.as_mut_ptr(),
                                                proof,
                                                num,
                                            )
                                        }
                                        if q_trades == 0 {
                                            lp::LP_trades_gotconnect(
                                                ctx.btc_ctx() as *mut c_void,
                                                &mut q,
                                                &mut q2,
                                            );
                                        } else {
                                            lp_trade_command_q(
                                                &ctx,
                                                &mut q,
                                                lp::jstr(
                                                    c_json.0,
                                                    b"pair\x00" as *const u8 as *const libc::c_char
                                                        as *mut libc::c_char,
                                                ),
                                                2,
                                            );
                                        }
                                    }
                            }
                        return retval;
                    }
                }
            }
        },
        _ => return retval
    };
}

fn zero_f() -> f64 { 0. }

#[derive(Deserialize, Debug)]
pub struct AutoBuyInput {
    base: String,
    rel: String,
    price: f64,
    #[serde(rename="relvolume")]
    #[serde(default = "zero_f")]
    rel_volume: f64,
    #[serde(rename="basevolume")]
    #[serde(default = "zero_f")]
    base_volume: f64,
    #[serde(default = "zero_f")]
    fomo: f64,
    #[serde(default = "zero_f")]
    dump: f64,
    timeout: Option<u32>,
    duration: Option<u32>,
    // TODO: remove this field on API refactoring, method should be separated from params
    method: String,
    fill: Option<u32>,
    gtc: Option<u32>,
    gui: Option<String>,
    #[serde(rename="destpubkey")]
    dest_pub_key: Option<String>
}

pub fn lp_auto_buy(input: AutoBuyInput) -> Result<String, String> {
    if input.price < SMALLVAL {
        return ERR!("Price is too low, minimum is {}", SMALLVAL);
    }

    let mut fomo = 0;
    let (base, rel, mut volume, mut price) = match Some(input.method.as_ref()) {
        Some("buy") => {
            let volume = if input.fomo > 0. {
                fomo = 1;
                input.fomo
            } else {
                input.rel_volume
            };
            if volume <= 0. {
                return ERR!("Volume must be greater than 0");
            }
            (find_coin(Some(&input.base)), find_coin(Some(&input.rel)), volume, input.price)
        },
        Some("sell") => {
            let volume = if input.dump > 0. {
                fomo = 1;
                input.dump
            } else {
                input.base_volume
            };
            if volume <= 0. {
                return ERR!("Volume must be greater than 0");
            }
            (find_coin(Some(&input.rel)), find_coin(Some(&input.base)), volume, 1. / input.price)
        },
        _ => return ERR!("Auto buy must be called only from buy/sell RPC methods")
    };
    if base.is_none() {
        return ERR!("Base coin is not found or inactive");
    }
    if rel.is_none() {
        return ERR!("Rel coin is not found or inactive");
    }

    let mut timeout = input.timeout.unwrap_or(unsafe { lp::LP_AUTOTRADE_TIMEOUT });
    let mut num = 0;
    let num_ptr = &mut num as *mut i32;

    unsafe {
        let base_coin = base.unwrap().0;
        let rel_coin = rel.unwrap().0;
        if (*base_coin).electrum != null_mut() && (*rel_coin).electrum != null_mut() {
            if timeout < 2 * lp::LP_AUTOTRADE_TIMEOUT {
                timeout = 2 * lp::LP_AUTOTRADE_TIMEOUT;
            }
        } else if (*base_coin).electrum != null_mut() || (*rel_coin).electrum != null_mut() {
            if timeout < (1.5 * lp::LP_AUTOTRADE_TIMEOUT as f32) as u32 {
                timeout = (1.5 * lp::LP_AUTOTRADE_TIMEOUT as f32) as u32;
            }
        }

        if now_ms() / 1000 < lp::Alice_expiration as u64 {
            return ERR!("Only 1 pending request at a time, wait {}",
                            lp::Alice_expiration as u64 - now_ms() / 1000);
        } else {
            lp::LP_alicequery_clear();
        }

        if (*rel_coin).etomic[0] != 0 {
            let etomic = find_coin(Some("ETOMIC"));
            if etomic.is_none() {
                return ERR!("ETOMIC is not found or inactive. It must be enabled for ETH/ERC20!");
            }
            let etomic_coin = etomic.unwrap().0;
            lp::LP_address_utxo_reset(num_ptr, etomic_coin);
        } else {
            lp::LP_address_utxo_reset(num_ptr, rel_coin);
            if num <= 1 {
                if now_ms() / 1000 > ((*rel_coin).lastautosplit + 300).into() {
                    (*rel_coin).lastautosplit = (now_ms() / 1000) as u32;
                    let auto_split = lp::LP_autosplit(rel_coin);
                    let auto_split_str = try_s!(c_char_to_string(auto_split));
                    free_c_ptr(auto_split as *mut c_void);
                    return Ok(auto_split_str);
                }
                return ERR!("not enough utxo, please make more deposits");
            }
        }
        let mut tx_fee : u64 = 0;
        let mut dest_tx_fee : u64 = 0;
        let base_str = try_s!(CString::new(input.base.clone()));
        let rel_str = try_s!(CString::new(input.rel.clone()));

        lp::LP_txfees(
            &mut tx_fee as *mut u64,
            &mut dest_tx_fee as *mut u64,
            base_str.as_ptr() as *mut c_char,
            rel_str.as_ptr() as *mut c_char,
        );
        if tx_fee != 0 && tx_fee < 10000 {
            tx_fee = 10000;
        }
        if dest_tx_fee != 0 && dest_tx_fee < 10000 {
            dest_tx_fee = 10000;
        }

        if fomo > 0 {
            let mut median : u64 = 0;
            let mut min_utxo : u64 = 0;
            let mut max_utxo : u64 = 0;
            lp::LP_address_minmax(
                0,
                &mut median as *mut u64,
                &mut min_utxo as *mut u64,
                &mut max_utxo as *mut u64,
                rel_coin,
                (*rel_coin).smartaddr.as_ptr() as *mut i8,
            );
            if max_utxo > 0 {
                volume = volume.min(sat_to_f(max_utxo) - sat_to_f(dest_tx_fee) * 3.);
                price = lp::LP_fomoprice(
                    base_str.as_ptr() as *mut c_char,
                    rel_str.as_ptr() as *mut c_char,
                    &mut volume as *mut f64
                );
                if price == 0. {
                    return ERR!("no orderbook entry found to handle request");
                }
            } else {
                return ERR!("No utxo available for fomo buy/sell");
            }
        }
        if price <= 0. {
            return ERR!("Resulting price is <= 0");
        }
        if volume <= 0. {
            return ERR!("Resulting volume is <= 0");
        }
        if lp::LP_priceinfofind(base_str.as_ptr() as *mut c_char) == null_mut() {
            return ERR!("No price info found for base coin {}", input.base);
        }
        if lp::LP_priceinfofind(rel_str.as_ptr() as *mut c_char) == null_mut() {
            return ERR!("No price info found for rel coin {}", input.rel);
        }

        if input.rel == "BTC" {
            price *= 1.01;
        } else {
            price *= 1.001;
        }

        let mut dest_satoshis = (SATOSHIS as f64 * volume) as u64 + 2 * dest_tx_fee;
        let mut a_utxo: *mut lp::LP_utxoinfo = null_mut();
        let mut a = lp::LP_utxoinfo::default();
        let mut b = lp::LP_utxoinfo::default();
        let utxos: [*mut lp::LP_address_utxo; 4096] = [null_mut(); 4096];
        let fill_flag = input.fill.unwrap_or(0);
        for i in 0..=100 {
            if i == 100 {
                return ERR!("cant find a deposit that is close enough in size. make another deposit that is just a bit larger than what you want to trade");
            }
            a_utxo = lp_address_myutxopair(
                &mut a as *mut lp::LP_utxoinfo,
                0,
                utxos.as_ptr() as *mut *mut lp::LP_address_utxo,
                4096,
                rel_coin,
                (*rel_coin).smartaddr.as_ptr() as *mut i8,
                tx_fee,
                sat_to_f(dest_satoshis),
                price,
                dest_tx_fee
            );
            if a_utxo != null_mut() { break }
            if fill_flag != 0 {
                return ERR!("cant find a deposit that is big enough in size. make another deposit that is just a bit larger than what you want to trade");
            }
            dest_satoshis = (dest_satoshis as f64 * 0.98) as u64;
            if dest_satoshis < dest_tx_fee * 10 { break }
        }

        if dest_satoshis < dest_tx_fee * 10 {
            return ERR!("cant find a deposit that is close enough in size. make another deposit that is just a bit larger than what you want to trade");
        }

        if dest_satoshis - dest_tx_fee < (*a_utxo).swap_satoshis as u64 {
            dest_satoshis -= dest_tx_fee;
            (*a_utxo).swap_satoshis = dest_satoshis as i64;
        } else if (*a_utxo).swap_satoshis as u64 - dest_tx_fee < dest_satoshis && (*rel_coin).etomic[0] == 0 {
            (*a_utxo).swap_satoshis -= dest_tx_fee as i64;
            dest_satoshis = (*a_utxo).swap_satoshis as u64;
        }

        if (*rel_coin).etomic[0] == 0 &&
            (dest_satoshis < ((*a_utxo).payment.value / 1000) || (*a_utxo).payment.value < dest_tx_fee * 10) {
            return ERR!("cant find a deposit that is close enough in size. make another deposit that is a bit larger than what you want to trade");
        }
        let best_satoshis = (1.001 * lp_base_satoshis(sat_to_f(dest_satoshis), price, tx_fee, dest_tx_fee) as f64) as u64;
        strcpy(b.coin.as_ptr() as *mut c_char, base_str.as_ptr());
        let mut q = lp::LP_quoteinfo::default();
        if lp::LP_quoteinfoinit(
            &mut q as *mut lp::LP_quoteinfo,
            &mut b as *mut lp::LP_utxoinfo,
            rel_str.as_ptr() as *mut c_char,
            price,
            best_satoshis,
            dest_satoshis,
        ) < 0 {
            return ERR!("cant set ordermatch quote");
        }
        if lp::LP_quotedestinfo(
            &mut q as *mut lp::LP_quoteinfo,
            (*a_utxo).payment.txid,
            (*a_utxo).payment.vout,
            (*a_utxo).fee.txid,
            (*a_utxo).fee.vout,
            lp::G.LP_mypub25519,
            (*a_utxo).coinaddr.as_ptr() as *mut c_char,
        ) < 0 {
            return ERR!("cant set ordermatch quote info");
        }
        if (*rel_coin).etomic[0] != 0 || (*base_coin).etomic[0] != 0 {
            if (*rel_coin).etomic[0] != 0 {
                strcpy(q.etomicdest.as_ptr() as *mut c_char, (*rel_coin).smartaddr.as_ptr());
            } else if (*base_coin).etomic[0] != 0 {
                strcpy(q.etomicdest.as_ptr() as *mut c_char, (*base_coin).smartaddr.as_ptr());
            }
        }
        let mut changed : i32 = 0;
        q.mpnet = lp::G.mpnet;
        q.fill = fill_flag;
        q.gtc = input.gtc.unwrap_or(0);
        lp::LP_mypriceset(0,
                          &mut changed as *mut i32,
                          rel_str.as_ptr() as *mut c_char,
                          base_str.as_ptr() as *mut c_char,
                          1. / price,
        );
        lp::LP_mypriceset(0,
                          &mut changed as *mut i32,
                          base_str.as_ptr() as *mut c_char,
                          rel_str.as_ptr() as *mut c_char,
                          0.,
        );
        let uuid_str: [c_char; 100] = [0; 100];
        lp::gen_quote_uuid(uuid_str.as_ptr() as *mut c_char, base_str.as_ptr() as *mut c_char, rel_str.as_ptr() as *mut c_char);
        let dest_pub_key = lp::bits256::default();
        if input.dest_pub_key.is_some() {
            let pub_key_str = try_s!(CString::new(input.dest_pub_key.unwrap()));
            lp::decode_hex(dest_pub_key.bytes.as_ptr() as *mut u8, 32, pub_key_str.as_ptr() as *mut c_char);
        }
        Ok(try_s!(lp_trade(
            &mut q as *mut lp::LP_quoteinfo,
            price,
            timeout as i32,
            0,
            dest_pub_key,
            uuid_str.as_ptr() as *mut c_char
        )))
    }
}
