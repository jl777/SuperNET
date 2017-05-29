
/******************************************************************************
 * Copyright © 2014-2017 The SuperNET Developers.                             *
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
//  LP_remember.c
//  marketmaker
//

/*void basilisk_swaps_init(struct supernet_info *myinfo)
{
    char fname[512]; uint32_t iter,swapcompleted,requestid,quoteid,optionduration,statebits; FILE *fp; bits256 privkey;struct basilisk_request R; struct basilisk_swapmessage M; struct basilisk_swap *swap = 0;
    sprintf(fname,"%s/SWAPS/list",GLOBAL_DBDIR), OS_compatible_path(fname);
    if ( (myinfo->swapsfp= fopen(fname,"rb+")) != 0 )
    {
        while ( fread(&requestid,1,sizeof(requestid),myinfo->swapsfp) == sizeof(requestid) && fread(&quoteid,1,sizeof(quoteid),myinfo->swapsfp) == sizeof(quoteid) )
        {
            sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
            printf("%s\n",fname);
            if ( (fp= fopen(fname,"rb+")) != 0 ) // check to see if completed
            {
                memset(&M,0,sizeof(M));
                swapcompleted = 1;
                for (iter=0; iter<2; iter++)
                {
                    if ( fread(privkey.bytes,1,sizeof(privkey),fp) == sizeof(privkey) &&
                        fread(&R,1,sizeof(R),fp) == sizeof(R) &&
                        fread(&statebits,1,sizeof(statebits),fp) == sizeof(statebits) &&
                        fread(&optionduration,1,sizeof(optionduration),fp) == sizeof(optionduration) )
                    {
                        while ( 0 && fread(&M,1,sizeof(M),fp) == sizeof(M) )
                        {
                            M.data = 0;
                            //printf("entry iter.%d crc32.%x datalen.%d\n",iter,M.crc32,M.datalen);
                            if ( M.datalen < 100000 )
                            {
                                M.data = malloc(M.datalen);
                                if ( fread(M.data,1,M.datalen,fp) == M.datalen )
                                {
                                    if ( calc_crc32(0,M.data,M.datalen) == M.crc32 )
                                    {
                                        if ( iter == 1 )
                                        {
                                            if ( swap == 0 )
                                            {
                                                swap = basilisk_thread_start(privkey,&R,statebits,optionduration,1);
                                                swap->I.choosei = swap->I.otherchoosei = -1;
                                            }
                                            if ( swap != 0 )
                                                basilisk_swapgotdata(swap,M.crc32,M.srchash,M.desthash,M.quoteid,M.msgbits,M.data,M.datalen,1);
                                        }
                                    } else printf("crc mismatch %x vs %x\n",calc_crc32(0,M.data,M.datalen),M.crc32);
                                } else printf("error reading M.datalen %d\n",M.datalen);
                                free(M.data), M.data = 0;
                            }
                        }
                    }
                    if ( swapcompleted != 0 )
                        break;
                    rewind(fp);
                }
            }
        }
    } else myinfo->swapsfp = fopen(fname,"wb+");
}*/

FILE *basilisk_swap_save(struct basilisk_swap *swap,bits256 privkey,struct basilisk_request *rp,uint32_t statebits,int32_t optionduration,int32_t reinit)
{
    FILE *fp=0; /*char fname[512];
                 sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,rp->requestid,rp->quoteid), OS_compatible_path(fname);
                 if ( (fp= fopen(fname,"rb+")) == 0 )
                 {
                 if ( (fp= fopen(fname,"wb+")) != 0 )
                 {
                 fwrite(privkey.bytes,1,sizeof(privkey),fp);
                 fwrite(rp,1,sizeof(*rp),fp);
                 fwrite(&statebits,1,sizeof(statebits),fp);
                 fwrite(&optionduration,1,sizeof(optionduration),fp);
                 fflush(fp);
                 }
                 }
                 else if ( reinit != 0 )
                 {
                 }*/
    return(fp);
}

int32_t basilisk_swap_load(uint32_t requestid,uint32_t quoteid,bits256 *privkeyp,struct basilisk_request *rp,uint32_t *statebitsp,int32_t *optiondurationp)
{
    FILE *fp=0; char fname[512]; int32_t retval = -1;
    sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"rb+")) != 0 )
    {
        if ( fread(privkeyp,1,sizeof(*privkeyp),fp) == sizeof(*privkeyp) &&
            fread(rp,1,sizeof(*rp),fp) == sizeof(*rp) &&
            fread(statebitsp,1,sizeof(*statebitsp),fp) == sizeof(*statebitsp) &&
            fread(optiondurationp,1,sizeof(*optiondurationp),fp) == sizeof(*optiondurationp) )
            retval = 0;
        fclose(fp);
    }
    return(retval);
}

void basilisk_swap_saveupdate(struct basilisk_swap *swap)
{
    FILE *fp; char fname[512];
    sprintf(fname,"%s/SWAPS/%u-%u.swap",GLOBAL_DBDIR,swap->I.req.requestid,swap->I.req.quoteid), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"wb")) != 0 )
    {
        fwrite(&swap->I,1,sizeof(swap->I),fp);
        /*fwrite(&swap->bobdeposit,1,sizeof(swap->bobdeposit),fp);
         fwrite(&swap->bobpayment,1,sizeof(swap->bobpayment),fp);
         fwrite(&swap->alicepayment,1,sizeof(swap->alicepayment),fp);
         fwrite(&swap->myfee,1,sizeof(swap->myfee),fp);
         fwrite(&swap->otherfee,1,sizeof(swap->otherfee),fp);
         fwrite(&swap->aliceclaim,1,sizeof(swap->aliceclaim),fp);
         fwrite(&swap->alicespend,1,sizeof(swap->alicespend),fp);
         fwrite(&swap->bobreclaim,1,sizeof(swap->bobreclaim),fp);
         fwrite(&swap->bobspend,1,sizeof(swap->bobspend),fp);
         fwrite(&swap->bobrefund,1,sizeof(swap->bobrefund),fp);
         fwrite(&swap->alicereclaim,1,sizeof(swap->alicereclaim),fp);*/
        fwrite(swap->privkeys,1,sizeof(swap->privkeys),fp);
        fwrite(swap->otherdeck,1,sizeof(swap->otherdeck),fp);
        fwrite(swap->deck,1,sizeof(swap->deck),fp);
        fclose(fp);
    }
}

/*int32_t basilisk_swap_loadtx(struct basilisk_rawtx *rawtx,FILE *fp,char *bobcoinstr,char *alicecoinstr)
{
    if ( fread(rawtx,1,sizeof(*rawtx),fp) == sizeof(*rawtx) )
    {
        rawtx->coin = 0;
        rawtx->vins = 0;
        if ( strcmp(rawtx->I.coinstr,bobcoinstr) == 0 || strcmp(rawtx->I.coinstr,alicecoinstr) == 0 )
        {
            rawtx->coin = LP_coinfind(rawtx->I.coinstr);
            if ( rawtx->vinstr[0] != 0 )
                rawtx->vins = cJSON_Parse(rawtx->vinstr);
            printf("loaded.%s len.%d\n",rawtx->name,rawtx->I.datalen);
            return(0);
        }
    }
    return(-1);
}*/

void basilisk_dontforget_userdata(char *userdataname,FILE *fp,uint8_t *script,int32_t scriptlen)
{
    int32_t i; char scriptstr[513];
    if ( scriptlen != 0 )
    {
        for (i=0; i<scriptlen; i++)
            sprintf(&scriptstr[i << 1],"%02x",script[i]);
        scriptstr[i << 1] = 0;
        fprintf(fp,"\",\"%s\":\"%s\"",userdataname,scriptstr);
    }
}

void basilisk_dontforget(struct basilisk_swap *swap,struct basilisk_rawtx *rawtx,int32_t locktime,bits256 triggertxid)
{
    char zeroes[32],fname[512],str[65],coinaddr[64],secretAmstr[41],secretAm256str[65],secretBnstr[41],secretBn256str[65]; FILE *fp; int32_t i,len; uint8_t redeemscript[256],script[256];
    sprintf(fname,"%s/SWAPS/%u-%u.%s",GLOBAL_DBDIR,swap->I.req.requestid,swap->I.req.quoteid,rawtx->name), OS_compatible_path(fname);
    coinaddr[0] = secretAmstr[0] = secretAm256str[0] = secretBnstr[0] = secretBn256str[0] = 0;
    memset(zeroes,0,sizeof(zeroes));
    if ( rawtx != 0 && (fp= fopen(fname,"wb")) != 0 )
    {
        fprintf(fp,"{\"name\":\"%s\",\"coin\":\"%s\"",rawtx->name,rawtx->coin->symbol);
        if ( rawtx->I.datalen > 0 )
        {
            fprintf(fp,",\"tx\":\"");
            for (i=0; i<rawtx->I.datalen; i++)
                fprintf(fp,"%02x",rawtx->txbytes[i]);
            fprintf(fp,"\",\"txid\":\"%s\"",bits256_str(str,bits256_doublesha256(0,rawtx->txbytes,rawtx->I.datalen)));
            if ( rawtx == &swap->bobdeposit || rawtx == &swap->bobpayment )
            {
                basilisk_swap_coinaddr(swap,&swap->bobcoin,coinaddr,rawtx->txbytes,rawtx->I.datalen);
                if ( coinaddr[0] != 0 )
                {
                    LP_importaddress(swap->bobcoin.symbol,coinaddr);
                    if ( rawtx == &swap->bobdeposit )
                        safecopy(swap->Bdeposit,coinaddr,sizeof(swap->Bdeposit));
                    else safecopy(swap->Bpayment,coinaddr,sizeof(swap->Bpayment));
                }
            }
        }
        if ( swap->Bdeposit[0] != 0 )
            fprintf(fp,",\"%s\":\"%s\"","Bdeposit",swap->Bdeposit);
        if ( swap->Bpayment[0] != 0 )
            fprintf(fp,",\"%s\":\"%s\"","Bpayment",swap->Bpayment);
        fprintf(fp,",\"expiration\":%u",swap->I.expiration);
        fprintf(fp,",\"iambob\":%d",swap->I.iambob);
        fprintf(fp,",\"bobcoin\":\"%s\"",swap->bobcoin.symbol);
        fprintf(fp,",\"alicecoin\":\"%s\"",swap->alicecoin.symbol);
        fprintf(fp,",\"lock\":%u",locktime);
        fprintf(fp,",\"amount\":%.8f",dstr(rawtx->I.amount));
        if ( bits256_nonz(triggertxid) != 0 )
            fprintf(fp,",\"trigger\":\"%s\"",bits256_str(str,triggertxid));
        if ( bits256_nonz(swap->I.pubAm) != 0 && bits256_nonz(swap->I.pubBn) != 0 )
        {
            basilisk_alicescript(redeemscript,&len,script,0,coinaddr,swap->alicecoin.p2shtype,swap->I.pubAm,swap->I.pubBn);
            LP_importaddress(swap->alicecoin.symbol,coinaddr);
            fprintf(fp,",\"Apayment\":\"%s\"",coinaddr);
        }
        /*basilisk_dontforget_userdata("Aclaim",fp,swap->I.userdata_aliceclaim,swap->I.userdata_aliceclaimlen);
         basilisk_dontforget_userdata("Areclaim",fp,swap->I.userdata_alicereclaim,swap->I.userdata_alicereclaimlen);
         basilisk_dontforget_userdata("Aspend",fp,swap->I.userdata_alicespend,swap->I.userdata_alicespendlen);
         basilisk_dontforget_userdata("Bspend",fp,swap->I.userdata_bobspend,swap->I.userdata_bobspendlen);
         basilisk_dontforget_userdata("Breclaim",fp,swap->I.userdata_bobreclaim,swap->I.userdata_bobreclaimlen);
         basilisk_dontforget_userdata("Brefund",fp,swap->I.userdata_bobrefund,swap->I.userdata_bobrefundlen);*/
        fprintf(fp,"}\n");
        fclose(fp);
    }
    sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,swap->I.req.requestid,swap->I.req.quoteid), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"wb")) != 0 )
    {
        fprintf(fp,"{\"src\":\"%s\",\"srcamount\":%.8f,\"dest\":\"%s\",\"destamount\":%.8f,\"requestid\":%u,\"quoteid\":%u,\"iambob\":%d,\"state\":%u,\"otherstate\":%u,\"expiration\":%u,\"dlocktime\":%u,\"plocktime\":%u",swap->I.req.src,dstr(swap->I.req.srcamount),swap->I.req.dest,dstr(swap->I.req.destamount),swap->I.req.requestid,swap->I.req.quoteid,swap->I.iambob,swap->I.statebits,swap->I.otherstatebits,swap->I.expiration,swap->bobdeposit.I.locktime,swap->bobpayment.I.locktime);
        if ( memcmp(zeroes,swap->I.secretAm,20) != 0 )
        {
            init_hexbytes_noT(secretAmstr,swap->I.secretAm,20);
            fprintf(fp,",\"secretAm\":\"%s\"",secretAmstr);
        }
        if ( memcmp(zeroes,swap->I.secretAm256,32) != 0 )
        {
            init_hexbytes_noT(secretAm256str,swap->I.secretAm256,32);
            fprintf(fp,",\"secretAm256\":\"%s\"",secretAm256str);
        }
        if ( memcmp(zeroes,swap->I.secretBn,20) != 0 )
        {
            init_hexbytes_noT(secretBnstr,swap->I.secretBn,20);
            fprintf(fp,",\"secretBn\":\"%s\"",secretBnstr);
        }
        if ( memcmp(zeroes,swap->I.secretBn256,32) != 0 )
        {
            init_hexbytes_noT(secretBn256str,swap->I.secretBn256,32);
            fprintf(fp,",\"secretBn256\":\"%s\"",secretBn256str);
        }
        for (i=0; i<2; i++)
            if ( bits256_nonz(swap->I.myprivs[i]) != 0 )
                fprintf(fp,",\"myprivs%d\":\"%s\"",i,bits256_str(str,swap->I.myprivs[i]));
        if ( bits256_nonz(swap->I.privAm) != 0 )
            fprintf(fp,",\"privAm\":\"%s\"",bits256_str(str,swap->I.privAm));
        if ( bits256_nonz(swap->I.privBn) != 0 )
            fprintf(fp,",\"privBn\":\"%s\"",bits256_str(str,swap->I.privBn));
        if ( bits256_nonz(swap->I.pubA0) != 0 )
            fprintf(fp,",\"pubA0\":\"%s\"",bits256_str(str,swap->I.pubA0));
        if ( bits256_nonz(swap->I.pubB0) != 0 )
            fprintf(fp,",\"pubB0\":\"%s\"",bits256_str(str,swap->I.pubB0));
        if ( bits256_nonz(swap->I.pubB1) != 0 )
            fprintf(fp,",\"pubB1\":\"%s\"",bits256_str(str,swap->I.pubB1));
        if ( bits256_nonz(swap->bobdeposit.I.actualtxid) != 0 )
            fprintf(fp,",\"Bdeposit\":\"%s\"",bits256_str(str,swap->bobdeposit.I.actualtxid));
        if ( bits256_nonz(swap->bobrefund.I.actualtxid) != 0 )
            fprintf(fp,",\"Brefund\":\"%s\"",bits256_str(str,swap->bobrefund.I.actualtxid));
        if ( bits256_nonz(swap->aliceclaim.I.actualtxid) != 0 )
            fprintf(fp,",\"Aclaim\":\"%s\"",bits256_str(str,swap->aliceclaim.I.actualtxid));
        
        if ( bits256_nonz(swap->bobpayment.I.actualtxid) != 0 )
            fprintf(fp,",\"Bpayment\":\"%s\"",bits256_str(str,swap->bobpayment.I.actualtxid));
        if ( bits256_nonz(swap->alicespend.I.actualtxid) != 0 )
            fprintf(fp,",\"Aspend\":\"%s\"",bits256_str(str,swap->alicespend.I.actualtxid));
        if ( bits256_nonz(swap->bobreclaim.I.actualtxid) != 0 )
            fprintf(fp,",\"Breclaim\":\"%s\"",bits256_str(str,swap->bobreclaim.I.actualtxid));
        
        if ( bits256_nonz(swap->alicepayment.I.actualtxid) != 0 )
            fprintf(fp,",\"Apayment\":\"%s\"",bits256_str(str,swap->alicepayment.I.actualtxid));
        if ( bits256_nonz(swap->bobspend.I.actualtxid) != 0 )
            fprintf(fp,",\"Bspend\":\"%s\"",bits256_str(str,swap->bobspend.I.actualtxid));
        if ( bits256_nonz(swap->alicereclaim.I.actualtxid) != 0 )
            fprintf(fp,",\"Areclaim\":\"%s\"",bits256_str(str,swap->alicereclaim.I.actualtxid));
        
        if ( bits256_nonz(swap->otherfee.I.actualtxid) != 0 )
            fprintf(fp,",\"otherfee\":\"%s\"",bits256_str(str,swap->otherfee.I.actualtxid));
        if ( bits256_nonz(swap->myfee.I.actualtxid) != 0 )
            fprintf(fp,",\"myfee\":\"%s\"",bits256_str(str,swap->myfee.I.actualtxid));
        fprintf(fp,",\"dest33\":\"");
        for (i=0; i<33; i++)
            fprintf(fp,"%02x",swap->persistent_pubkey33[i]);
        fprintf(fp,"\"}\n");
        fclose(fp);
    }
}

void basilisk_dontforget_update(struct basilisk_swap *swap,struct basilisk_rawtx *rawtx)
{
    bits256 triggertxid;
    memset(triggertxid.bytes,0,sizeof(triggertxid));
    if ( rawtx == 0 )
    {
        basilisk_dontforget(swap,0,0,triggertxid);
        return;
    }
    if ( rawtx == &swap->myfee )
        basilisk_dontforget(swap,&swap->myfee,0,triggertxid);
    else if ( rawtx == &swap->otherfee )
        basilisk_dontforget(swap,&swap->otherfee,0,triggertxid);
    else if ( rawtx == &swap->bobdeposit )
    {
        basilisk_dontforget(swap,&swap->bobdeposit,0,triggertxid);
        basilisk_dontforget(swap,&swap->bobrefund,swap->bobdeposit.I.locktime,triggertxid);
    }
    else if ( rawtx == &swap->bobrefund )
        basilisk_dontforget(swap,&swap->bobrefund,swap->bobdeposit.I.locktime,triggertxid);
    else if ( rawtx == &swap->aliceclaim )
    {
        basilisk_dontforget(swap,&swap->bobrefund,0,triggertxid);
        basilisk_dontforget(swap,&swap->aliceclaim,0,swap->bobrefund.I.actualtxid);
    }
    else if ( rawtx == &swap->alicepayment )
    {
        basilisk_dontforget(swap,&swap->alicepayment,0,swap->bobdeposit.I.actualtxid);
    }
    else if ( rawtx == &swap->bobspend )
    {
        basilisk_dontforget(swap,&swap->alicepayment,0,swap->bobdeposit.I.actualtxid);
        basilisk_dontforget(swap,&swap->bobspend,0,swap->alicepayment.I.actualtxid);
    }
    else if ( rawtx == &swap->alicereclaim )
    {
        basilisk_dontforget(swap,&swap->alicepayment,0,swap->bobdeposit.I.actualtxid);
        basilisk_dontforget(swap,&swap->alicereclaim,0,swap->bobrefund.I.actualtxid);
    }
    else if ( rawtx == &swap->bobpayment )
    {
        basilisk_dontforget(swap,&swap->bobpayment,0,triggertxid);
        basilisk_dontforget(swap,&swap->bobreclaim,swap->bobpayment.I.locktime,triggertxid);
    }
    else if ( rawtx == &swap->alicespend )
    {
        basilisk_dontforget(swap,&swap->bobpayment,0,triggertxid);
        basilisk_dontforget(swap,&swap->alicespend,0,triggertxid);
    }
    else if ( rawtx == &swap->bobreclaim )
        basilisk_dontforget(swap,&swap->bobreclaim,swap->bobpayment.I.locktime,triggertxid);
}



bits256 basilisk_swap_privbob_extract(char *symbol,bits256 spendtxid,int32_t vini,int32_t revflag)
{
    bits256 privkey; int32_t i,scriptlen,siglen; uint8_t script[1024]; // from Bob refund of Bob deposit
    memset(&privkey,0,sizeof(privkey));
    if ( (scriptlen= basilisk_swap_getsigscript(symbol,script,(int32_t)sizeof(script),spendtxid,vini)) > 0 )
    {
        siglen = script[0];
        for (i=0; i<32; i++)
        {
            if ( revflag != 0 )
                privkey.bytes[31 - i] = script[siglen+2+i];
            else privkey.bytes[i] = script[siglen+2+i];
        }
        char str[65]; printf("extracted privbob.(%s)\n",bits256_str(str,privkey));
    }
    return(privkey);
}

bits256 basilisk_swap_privBn_extract(bits256 *bobrefundp,char *bobcoin,bits256 bobdeposit,bits256 privBn)
{
    char destaddr[64];
    if ( bits256_nonz(privBn) == 0 )
    {
        if ( bits256_nonz(bobdeposit) != 0 )
            *bobrefundp = LP_swap_spendtxid(bobcoin,destaddr,bobdeposit,0);
        if ( bits256_nonz(*bobrefundp) != 0 )
            privBn = basilisk_swap_privbob_extract(bobcoin,*bobrefundp,0,0);
    }
    return(privBn);
}

bits256 basilisk_swap_spendupdate(char *symbol,int32_t *sentflags,bits256 *txids,int32_t utxoind,int32_t alicespent,int32_t bobspent,int32_t vout,char *aliceaddr,char *bobaddr)
{
    bits256 spendtxid,txid; char destaddr[64];
    txid = txids[utxoind];
    memset(&spendtxid,0,sizeof(spendtxid));
    /*if ( aliceaddr != 0 )
     printf("aliceaddr.(%s)\n",aliceaddr);
     if ( bobaddr != 0 )
     printf("bobaddr.(%s)\n",bobaddr);*/
    if ( bits256_nonz(txid) != 0 )
    {
        //char str[65];
        spendtxid = LP_swap_spendtxid(symbol,destaddr,txid,vout);
        if ( bits256_nonz(spendtxid) != 0 )
        {
            sentflags[utxoind] = 1;
            if ( aliceaddr != 0 && strcmp(destaddr,aliceaddr) == 0 )
            {
                //printf("ALICE spent.(%s) -> %s\n",bits256_str(str,txid),destaddr);
                sentflags[alicespent] = 1;
                txids[alicespent] = spendtxid;
            }
            else if ( bobaddr != 0 && strcmp(destaddr,bobaddr) == 0 )
            {
                //printf("BOB spent.(%s) -> %s\n",bits256_str(str,txid),destaddr);
                sentflags[bobspent] = 1;
                txids[bobspent] = spendtxid;
            }
            else
            {
                //printf("OTHER dest spent.(%s) -> %s\n",bits256_str(str,txid),destaddr);
                if ( aliceaddr != 0 )
                {
                    sentflags[bobspent] = 1;
                    txids[bobspent] = spendtxid;
                }
                else if ( bobaddr != 0 )
                {
                    sentflags[alicespent] = 1;
                    txids[alicespent] = spendtxid;
                }
            }
        }
    } else printf("utxoind.%d null txid\n",utxoind);
    return(spendtxid);
}

#define BASILISK_ALICESPEND 0
#define BASILISK_BOBSPEND 1
#define BASILISK_BOBPAYMENT 2
#define BASILISK_ALICEPAYMENT 3
#define BASILISK_BOBDEPOSIT 4
#define BASILISK_OTHERFEE 5
#define BASILISK_MYFEE 6
#define BASILISK_BOBREFUND 7
#define BASILISK_BOBRECLAIM 8
#define BASILISK_ALICERECLAIM 9
#define BASILISK_ALICECLAIM 10
//0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0
char *txnames[] = { "alicespend", "bobspend", "bobpayment", "alicepayment", "bobdeposit", "otherfee", "myfee", "bobrefund", "bobreclaim", "alicereclaim", "aliceclaim" };

int32_t basilisk_isbobcoin(int32_t iambob,int32_t ind)
{
    switch ( ind  )
    {
        case BASILISK_MYFEE: return(iambob); break;
        case BASILISK_OTHERFEE: return(!iambob); break;
        case BASILISK_BOBSPEND:
        case BASILISK_ALICEPAYMENT:
        case BASILISK_ALICERECLAIM:
        case BASILISK_ALICECLAIM: return(0);
            break;
        case BASILISK_BOBDEPOSIT:
        case BASILISK_ALICESPEND:
        case BASILISK_BOBPAYMENT:
        case BASILISK_BOBREFUND:
        case BASILISK_BOBRECLAIM: return(1);
            break;
        default: return(-1); break;
    }
}

// add blocktrail presence requirement for BTC
int32_t basilisk_swap_isfinished(int32_t iambob,bits256 *txids,int32_t *sentflags,bits256 paymentspent,bits256 Apaymentspent,bits256 depositspent)
{
    int32_t i,n = 0;
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
        if ( i != BASILISK_OTHERFEE && i != BASILISK_MYFEE && sentflags[i] != 0 )
            n++;
    if ( n == 0 )
    {
        printf("if nothing sent, it is finished\n");
        return(1);
    }
    if ( iambob != 0 )
    {
        if ( bits256_nonz(txids[BASILISK_BOBDEPOSIT]) == 0 && sentflags[BASILISK_BOBDEPOSIT] == 0 )
            return(1);
        else if ( bits256_nonz(txids[BASILISK_BOBPAYMENT]) == 0 && sentflags[BASILISK_BOBPAYMENT] == 0 )
        {
            if ( bits256_nonz(depositspent) != 0 )
                return(1);
        }
        else if ( bits256_nonz(paymentspent) != 0 )
            return(1);
    }
    else
    {
        if ( bits256_nonz(txids[BASILISK_ALICEPAYMENT]) == 0 && sentflags[BASILISK_ALICEPAYMENT] == 0 )
            return(1);
        else
        {
            if ( sentflags[BASILISK_ALICERECLAIM] != 0 || sentflags[BASILISK_ALICESPEND] != 0 )
                return(1);
            else if ( sentflags[BASILISK_BOBSPEND] != 0 ) // without ALICECLAIM this is loss due to inactivity
                return(1);
        }
    }
    return(0);
}

cJSON *basilisk_remember(int64_t *KMDtotals,int64_t *BTCtotals,uint32_t requestid,uint32_t quoteid)
{
    static void *ctx;
    FILE *fp; int32_t sentflags[sizeof(txnames)/sizeof(*txnames)],i,n,j,len,needflag,secretstart,redeemlen,addflag,origfinishedflag = 0,finishedflag = 0,iambob = -1; int64_t srcamount,destamount=0,value,values[sizeof(txnames)/sizeof(*txnames)]; uint8_t secretAm[20],secretAm256[32],secretBn[20],secretBn256[32],pubkey33[33],redeemscript[1024],userdata[1024]; uint32_t plocktime,dlocktime,expiration=0,r,q,state,otherstate; char *secretstr,*srcstr,*deststr,str[65],src[64],dest[64],fname[512],*fstr,*dest33,*symbol,*txname,*Adest,*Bdest,*AAdest,*ABdest,destaddr[64],Adestaddr[64],alicecoin[64],bobcoin[64],*txbytes[sizeof(txnames)/sizeof(*txnames)]; long fsize; cJSON *txobj,*item,*sentobj,*array; bits256 checktxid,txid,pubA0,pubB0,pubB1,privAm,privBn,paymentspent,Apaymentspent,depositspent,zero,privkey,rev,myprivs[2],txids[sizeof(txnames)/sizeof(*txnames)],signedtxid; struct iguana_info *bob=0,*alice=0; uint64_t txfee = 10000;
    if ( ctx == 0 )
        ctx = bitcoin_ctx();
    memset(values,0,sizeof(values));
    memset(txids,0,sizeof(txids));
    memset(secretAm,0,sizeof(secretAm));
    memset(secretAm256,0,sizeof(secretAm256));
    memset(secretBn,0,sizeof(secretBn));
    memset(secretBn256,0,sizeof(secretBn256));
    memset(pubkey33,0,sizeof(pubkey33));
    memset(txbytes,0,sizeof(txbytes));
    memset(sentflags,0,sizeof(sentflags));
    memset(myprivs,0,sizeof(myprivs));
    Apaymentspent = paymentspent = depositspent = rev = zero = pubA0 = pubB0 = pubB1 = privAm = privBn = myprivs[0];
    plocktime = dlocktime = 0;
    src[0] = dest[0] = bobcoin[0] = alicecoin[0] = 0;
    sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
    if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
    {
        if ( (item= cJSON_Parse(fstr)) != 0 )
        {
            iambob = jint(item,"iambob");
            if ( (secretstr= jstr(item,"secretAm")) != 0 && strlen(secretstr) == 40 )
                decode_hex(secretAm,20,secretstr);
            if ( (secretstr= jstr(item,"secretAm256")) != 0 && strlen(secretstr) == 64 )
                decode_hex(secretAm256,32,secretstr);
            if ( (secretstr= jstr(item,"secretBn")) != 0 && strlen(secretstr) == 40 )
                decode_hex(secretBn,20,secretstr);
            if ( (secretstr= jstr(item,"secretBn256")) != 0 && strlen(secretstr) == 64 )
                decode_hex(secretBn256,32,secretstr);
            if ( (srcstr= jstr(item,"src")) != 0 )
                safecopy(src,srcstr,sizeof(src));
            if ( (deststr= jstr(item,"dest")) != 0 )
                safecopy(dest,deststr,sizeof(dest));
            if ( (dest33= jstr(item,"dest33")) != 0 && strlen(dest33) == 66 )
            {
                decode_hex(pubkey33,33,dest33);
                //for (i=0; i<33; i++)
                //    printf("%02x",pubkey33[i]);
                //printf(" <- %s dest33\n",dest33);
            }
            plocktime = juint(item,"plocktime");
            dlocktime = juint(item,"dlocktime");
            r = juint(item,"requestid");
            q = juint(item,"quoteid");
            pubA0 = jbits256(item,"pubA0");
            pubB0 = jbits256(item,"pubB0");
            pubB1 = jbits256(item,"pubB1");
            privkey = jbits256(item,"myprivs0");
            if ( bits256_nonz(privkey) != 0 )
                myprivs[0] = privkey;
            privkey = jbits256(item,"myprivs1");
            if ( bits256_nonz(privkey) != 0 )
                myprivs[1] = privkey;
            privkey = jbits256(item,"privAm");
            if ( bits256_nonz(privkey) != 0 )
            {
                privAm = privkey;
                //printf("set privAm <- %s\n",bits256_str(str,privAm));
            }
            privkey = jbits256(item,"privBn");
            if ( bits256_nonz(privkey) != 0 )
            {
                privBn = privkey;
                //printf("set privBn <- %s\n",bits256_str(str,privBn));
            }
            expiration = juint(item,"expiration");
            state = jint(item,"state");
            otherstate = jint(item,"otherstate");
            srcamount = SATOSHIDEN * jdouble(item,"srcamount");
            destamount = SATOSHIDEN * jdouble(item,"destamount");
            txids[BASILISK_BOBDEPOSIT] = jbits256(item,"Bdeposit");
            txids[BASILISK_BOBREFUND] = jbits256(item,"Brefund");
            txids[BASILISK_ALICECLAIM] = jbits256(item,"Aclaim");
            txids[BASILISK_BOBPAYMENT] = jbits256(item,"Bpayment");
            txids[BASILISK_ALICESPEND] = jbits256(item,"Aspend");
            txids[BASILISK_BOBRECLAIM] = jbits256(item,"Breclaim");
            txids[BASILISK_ALICEPAYMENT] = jbits256(item,"Apayment");
            txids[BASILISK_BOBSPEND] = jbits256(item,"Bspend");
            txids[BASILISK_ALICERECLAIM] = jbits256(item,"Areclaim");
            txids[BASILISK_MYFEE] = jbits256(item,"myfee");
            txids[BASILISK_OTHERFEE] = jbits256(item,"otherfee");
            free_json(item);
        }
        free(fstr);
    }
    sprintf(fname,"%s/SWAPS/%u-%u.finished",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
    if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
    {
        //printf("%s -> (%s)\n",fname,fstr);
        if ( (txobj= cJSON_Parse(fstr)) != 0 )
        {
            paymentspent = jbits256(txobj,"paymentspent");
            Apaymentspent = jbits256(txobj,"Apaymentspent");
            depositspent = jbits256(txobj,"depositspent");
            if ( (array= jarray(&n,txobj,"values")) != 0 )
                for (i=0; i<n&&i<sizeof(txnames)/sizeof(*txnames); i++)
                    values[i] = SATOSHIDEN * jdouble(jitem(array,i),0);
            if ( (array= jarray(&n,txobj,"sentflags")) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (txname= jstri(array,i)) != 0 )
                    {
                        for (j=0; j<sizeof(txnames)/sizeof(*txnames); j++)
                            if ( strcmp(txname,txnames[j]) == 0 )
                            {
                                sentflags[j] = 1;
                                //printf("finished.%s\n",txnames[j]);
                                break;
                            }
                    }
                }
            }
        }
        origfinishedflag = finishedflag = 1;
        free(fstr);
    }
    if ( iambob < 0 )
        return(0);
    item = cJSON_CreateObject();
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
    {
        needflag = addflag = 0;
        sprintf(fname,"%s/SWAPS/%u-%u.%s",GLOBAL_DBDIR,requestid,quoteid,txnames[i]), OS_compatible_path(fname);
        if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
        {
            if ( finishedflag == 0 )
                printf("%s\n",fname);
            //printf("%s -> (%s)\n",fname,fstr);
            if ( (txobj= cJSON_Parse(fstr)) != 0 )
            {
                //printf("TXOBJ.(%s)\n",jprint(txobj,0));
                iambob = jint(txobj,"iambob");
                txid = jbits256(txobj,"txid");
                if ( bits256_nonz(txid) == 0 )
                    continue;
                txids[i] = txid;
                if ( jobj(txobj,"tx") != 0 )
                {
                    txbytes[i] = clonestr(jstr(txobj,"tx"));
                    //printf("[%s] TX.(%s)\n",txnames[i],txbytes[i]);
                }
                if ( (value= jdouble(txobj,"amount") * SATOSHIDEN) == 0 )
                    value = jdouble(txobj,"value") * SATOSHIDEN;
                values[i] = value;
                if ( (symbol= jstr(txobj,"coin")) != 0 )
                {
                    if ( i == BASILISK_ALICESPEND || i == BASILISK_BOBPAYMENT || i == BASILISK_BOBDEPOSIT || i == BASILISK_BOBREFUND || i == BASILISK_BOBRECLAIM || i == BASILISK_ALICECLAIM )
                        safecopy(bobcoin,symbol,sizeof(bobcoin));
                    else if ( i == BASILISK_BOBSPEND || i == BASILISK_ALICEPAYMENT || i == BASILISK_ALICERECLAIM )
                        safecopy(alicecoin,symbol,sizeof(alicecoin));
                    if ( finishedflag == 0 )
                    {
                        if ( (sentobj= LP_gettx(symbol,txid)) == 0 )
                        {
                            //printf("%s %s ready to broadcast\n",symbol,bits256_str(str2,txid));
                        }
                        else
                        {
                            checktxid = jbits256(sentobj,"txid");
                            if ( bits256_nonz(checktxid) == 0 )
                                checktxid = jbits256(sentobj,"hash");
                            if ( bits256_cmp(checktxid,txid) == 0 )
                            {
                                //printf(">>>>>> %s txid %s\n",jprint(sentobj,0),bits256_str(str,txid));
                                sentflags[i] = 1;
                            }
                            free_json(sentobj);
                        }
                        printf("%s %s %.8f\n",txnames[i],bits256_str(str,txid),dstr(value));
                    }
                }
            } //else printf("no symbol\n");
            free(fstr);
        } else if ( finishedflag == 0 )
            printf("%s not finished\n",fname);
    }
    //printf("iambob.%d src.%s dest.%s bob.%s alice.%s pubA0.(%s)\n",iambob,src,dest,bobcoin,alicecoin,bits256_str(str,pubA0));
    Adestaddr[0] = destaddr[0] = 0;
    Adest = Bdest = AAdest = ABdest = 0;
    if ( bobcoin[0] == 0 || alicecoin[0] == 0 )
        return(0);
    //printf("privAm.(%s) %p/%p\n",bits256_str(str,privAm),Adest,AAdest);
    //printf("privBn.(%s) %p/%p\n",bits256_str(str,privBn),Bdest,ABdest);
    if ( finishedflag == 0 && bobcoin[0] != 0 && alicecoin[0] != 0 )
    {
        if ( iambob == 0 )
        {
            if ( (alice= LP_coinfind(alicecoin)) != 0 )
            {
                bitcoin_address(Adestaddr,alice->pubtype,pubkey33,33);
                AAdest = Adestaddr;
            }
            if ( (bob= LP_coinfind(bobcoin)) != 0 )
            {
                bitcoin_address(destaddr,bob->pubtype,pubkey33,33);
                Adest = destaddr;
            }
        }
        else
        {
            if ( (bob= LP_coinfind(bobcoin)) != 0 )
            {
                bitcoin_address(destaddr,bob->pubtype,pubkey33,33);
                Bdest = destaddr;
            }
            if ( (alice= LP_coinfind(alicecoin)) != 0 )
            {
                bitcoin_address(Adestaddr,alice->pubtype,pubkey33,33);
                ABdest = Adestaddr;
            }
        }
        if ( sentflags[BASILISK_ALICEPAYMENT] == 0 && bits256_nonz(txids[BASILISK_ALICEPAYMENT]) != 0 )
        {
            printf("txbytes.%p Apayment.%s\n",txbytes[BASILISK_ALICEPAYMENT],bits256_str(str,txids[BASILISK_ALICEPAYMENT]));
            if ( txbytes[BASILISK_ALICEPAYMENT] != 0 )
                sentflags[BASILISK_ALICEPAYMENT] = 1;
            else if ( (sentobj= LP_gettx(alicecoin,txids[BASILISK_ALICEPAYMENT])) != 0 )
            {
                sentflags[BASILISK_ALICEPAYMENT] = 1;
                free_json(sentobj);
            }
        }
        paymentspent = basilisk_swap_spendupdate(bobcoin,sentflags,txids,BASILISK_BOBPAYMENT,BASILISK_ALICESPEND,BASILISK_BOBRECLAIM,0,Adest,Bdest);
        Apaymentspent = basilisk_swap_spendupdate(alicecoin,sentflags,txids,BASILISK_ALICEPAYMENT,BASILISK_ALICERECLAIM,BASILISK_BOBSPEND,0,AAdest,ABdest);
        depositspent = basilisk_swap_spendupdate(bobcoin,sentflags,txids,BASILISK_BOBDEPOSIT,BASILISK_ALICECLAIM,BASILISK_BOBREFUND,0,Adest,Bdest);
        finishedflag = basilisk_swap_isfinished(iambob,txids,sentflags,paymentspent,Apaymentspent,depositspent);
        if ( iambob == 0 )
        {
            if ( sentflags[BASILISK_ALICESPEND] == 0 )
            {
                if ( sentflags[BASILISK_BOBPAYMENT] != 0 && bits256_nonz(paymentspent) == 0 )
                {
                    //if ( txbytes[BASILISK_ALICESPEND] == 0 )
                    {
                        if ( bits256_nonz(txids[BASILISK_BOBPAYMENT]) != 0 )
                        {
                            // alicespend
                            for (j=0; j<32; j++)
                                rev.bytes[j] = privAm.bytes[31 - j];
                            revcalc_rmd160_sha256(secretAm,rev);//privAm);
                            vcalc_sha256(0,secretAm256,rev.bytes,sizeof(rev));
                            redeemlen = basilisk_swap_bobredeemscript(0,&secretstart,redeemscript,plocktime,pubA0,pubB0,pubB1,rev,privBn,secretAm,secretAm256,secretBn,secretBn256);
                            len = basilisk_swapuserdata(userdata,rev,0,myprivs[0],redeemscript,redeemlen);
                            printf("alicespend len.%d redeemlen.%d\n",len,redeemlen);
                            if ( (txbytes[BASILISK_ALICESPEND]= basilisk_swap_bobtxspend(&signedtxid,txfee,"alicespend",bobcoin,bob->pubtype,bob->p2shtype,bob->isPoS,bob->wiftype,ctx,myprivs[0],0,redeemscript,redeemlen,userdata,len,txids[BASILISK_BOBPAYMENT],0,pubkey33,1,expiration,&values[BASILISK_ALICESPEND])) != 0 )
                                printf("alicespend.(%s)\n",txbytes[BASILISK_ALICESPEND]);
                        }
                    }
                    if ( txbytes[BASILISK_ALICESPEND] != 0 )
                    {
                        txids[BASILISK_ALICESPEND] = LP_broadcast("alicespend",bobcoin,txbytes[BASILISK_ALICESPEND]);
                        if ( bits256_nonz(txids[BASILISK_ALICESPEND]) != 0 ) // tested
                        {
                            sentflags[BASILISK_ALICESPEND] = 1;
                            paymentspent = txids[BASILISK_ALICESPEND];
                        }
                    }
                }
            }
            if ( sentflags[BASILISK_ALICECLAIM] == 0 && sentflags[BASILISK_BOBDEPOSIT] != 0 && bits256_nonz(txids[BASILISK_BOBDEPOSIT]) != 0 && bits256_nonz(depositspent) == 0 )
            {
                if ( time(NULL) > expiration )
                {
                    //if ( txbytes[BASILISK_ALICECLAIM] == 0 )
                    {
                        redeemlen = basilisk_swap_bobredeemscript(1,&secretstart,redeemscript,dlocktime,pubA0,pubB0,pubB1,privAm,zero,secretAm,secretAm256,secretBn,secretBn256);
                        if ( redeemlen > 0 )
                        {
                            len = basilisk_swapuserdata(userdata,zero,1,myprivs[0],redeemscript,redeemlen);
                            if ( (txbytes[BASILISK_ALICECLAIM]= basilisk_swap_bobtxspend(&signedtxid,txfee,"aliceclaim",bobcoin,bob->pubtype,bob->p2shtype,bob->isPoS,bob->wiftype,ctx,myprivs[0],0,redeemscript,redeemlen,userdata,len,txids[BASILISK_BOBDEPOSIT],0,pubkey33,0,expiration,&values[BASILISK_ALICECLAIM])) != 0 )
                                printf("privBn.(%s) aliceclaim.(%s)\n",bits256_str(str,privBn),txbytes[BASILISK_ALICECLAIM]);
                        }
                    }
                    if ( txbytes[BASILISK_ALICECLAIM] != 0 )
                    {
                        txids[BASILISK_ALICECLAIM] = LP_broadcast("aliceclaim",bobcoin,txbytes[BASILISK_ALICECLAIM]);
                        if ( bits256_nonz(txids[BASILISK_ALICECLAIM]) != 0 ) // tested
                        {
                            sentflags[BASILISK_ALICECLAIM] = 1;
                            depositspent = txids[BASILISK_ALICECLAIM];
                        }
                    }
                } else printf("now %u before expiration %u\n",(uint32_t)time(NULL),expiration);
            }
            if ( sentflags[BASILISK_ALICEPAYMENT] != 0 && bits256_nonz(Apaymentspent) == 0 && sentflags[BASILISK_ALICECLAIM] == 0 )
            {
                //if ( txbytes[BASILISK_ALICERECLAIM] == 0 )
                {
                    privBn = basilisk_swap_privBn_extract(&txids[BASILISK_BOBREFUND],bobcoin,txids[BASILISK_BOBDEPOSIT],privBn);
                    if ( bits256_nonz(txids[BASILISK_ALICEPAYMENT]) != 0 && bits256_nonz(privAm) != 0 && bits256_nonz(privBn) != 0 )
                    {
                        if ( (txbytes[BASILISK_ALICERECLAIM]= basilisk_swap_Aspend("alicereclaim",alicecoin,alice->pubtype,alice->p2shtype,alice->isPoS,alice->wiftype,ctx,privAm,privBn,txids[BASILISK_ALICEPAYMENT],0,pubkey33,expiration,&values[BASILISK_ALICERECLAIM])) != 0 )
                            printf("privBn.(%s) alicereclaim.(%s)\n",bits256_str(str,privBn),txbytes[BASILISK_ALICERECLAIM]);
                    }
                }
                if ( txbytes[BASILISK_ALICERECLAIM] != 0 )
                {
                    txids[BASILISK_ALICERECLAIM] = LP_broadcast("alicereclaim",alicecoin,txbytes[BASILISK_ALICERECLAIM]);
                    if ( bits256_nonz(txids[BASILISK_ALICERECLAIM]) != 0 ) // tested
                    {
                        sentflags[BASILISK_ALICERECLAIM] = 1;
                        Apaymentspent = txids[BASILISK_ALICERECLAIM];
                    }
                }
            }
        }
        else if ( iambob == 1 )
        {
            if ( sentflags[BASILISK_BOBSPEND] == 0 && bits256_nonz(Apaymentspent) == 0 )
            {
                printf("try to bobspend aspend.%s have privAm.%d\n",bits256_str(str,txids[BASILISK_ALICESPEND]),bits256_nonz(privAm));
                if ( bits256_nonz(txids[BASILISK_ALICESPEND]) != 0 || bits256_nonz(privAm) != 0 )
                {
                    //if ( txbytes[BASILISK_BOBSPEND] == 0 )
                    {
                        if ( bits256_nonz(privAm) == 0 )
                        {
                            privAm = basilisk_swap_privbob_extract(bobcoin,txids[BASILISK_ALICESPEND],0,1);
                        }
                        if ( bits256_nonz(privAm) != 0 && bits256_nonz(privBn) != 0 )
                        {
                            if ( (txbytes[BASILISK_BOBSPEND]= basilisk_swap_Aspend("bobspend",alicecoin,alice->pubtype,alice->p2shtype,alice->isPoS,alice->wiftype,ctx,privAm,privBn,txids[BASILISK_ALICEPAYMENT],0,pubkey33,expiration,&values[BASILISK_BOBSPEND])) != 0 )
                                printf("bobspend.(%s)\n",txbytes[BASILISK_BOBSPEND]);
                        }
                    }
                    if ( txbytes[BASILISK_BOBSPEND] != 0 )
                    {
                        txids[BASILISK_BOBSPEND] = LP_broadcast("bobspend",alicecoin,txbytes[BASILISK_BOBSPEND]);
                        if ( bits256_nonz(txids[BASILISK_BOBSPEND]) != 0 ) // tested
                        {
                            sentflags[BASILISK_BOBSPEND] = 1;
                            Apaymentspent = txids[BASILISK_BOBSPEND];
                        }
                    }
                }
            }
            if ( sentflags[BASILISK_BOBRECLAIM] == 0 && sentflags[BASILISK_BOBPAYMENT] != 0 && bits256_nonz(txids[BASILISK_BOBPAYMENT]) != 0 && time(NULL) > expiration && bits256_nonz(paymentspent) == 0 )
            {
                //if ( txbytes[BASILISK_BOBRECLAIM] == 0 )
                {
                    // bobreclaim
                    redeemlen = basilisk_swap_bobredeemscript(0,&secretstart,redeemscript,plocktime,pubA0,pubB0,pubB1,zero,privBn,secretAm,secretAm256,secretBn,secretBn256);
                    if ( redeemlen > 0 )
                    {
                        len = basilisk_swapuserdata(userdata,zero,1,myprivs[1],redeemscript,redeemlen);
                        if ( (txbytes[BASILISK_BOBRECLAIM]= basilisk_swap_bobtxspend(&signedtxid,txfee,"bobrefund",bobcoin,bob->pubtype,bob->p2shtype,bob->isPoS,bob->wiftype,ctx,myprivs[1],0,redeemscript,redeemlen,userdata,len,txids[BASILISK_BOBPAYMENT],0,pubkey33,0,expiration,&values[BASILISK_BOBRECLAIM])) != 0 )
                        {
                            int32_t z;
                            for (z=0; z<20; z++)
                                printf("%02x",secretAm[z]);
                            printf(" secretAm, myprivs[1].(%s) bobreclaim.(%s)\n",bits256_str(str,myprivs[1]),txbytes[BASILISK_BOBRECLAIM]);
                        }
                    }
                }
                if ( txbytes[BASILISK_BOBRECLAIM] != 0 )
                {
                    txids[BASILISK_BOBRECLAIM] = LP_broadcast("bobreclaim",bobcoin,txbytes[BASILISK_BOBRECLAIM]);
                    if ( bits256_nonz(txids[BASILISK_BOBRECLAIM]) != 0 ) // tested
                    {
                        sentflags[BASILISK_BOBRECLAIM] = 1;
                        paymentspent = txids[BASILISK_BOBRECLAIM];
                    }
                }
            }
            if ( sentflags[BASILISK_BOBREFUND] == 0 && sentflags[BASILISK_BOBDEPOSIT] != 0 && bits256_nonz(txids[BASILISK_BOBDEPOSIT]) != 0 && bits256_nonz(depositspent) == 0 )
            {
                if ( bits256_nonz(paymentspent) != 0 || time(NULL) > expiration )
                {
                    printf("do the refund!\n");
                    //if ( txbytes[BASILISK_BOBREFUND] == 0 )
                    {
                        revcalc_rmd160_sha256(secretBn,privBn);
                        vcalc_sha256(0,secretBn256,privBn.bytes,sizeof(privBn));
                        redeemlen = basilisk_swap_bobredeemscript(1,&secretstart,redeemscript,dlocktime,pubA0,pubB0,pubB1,privAm,privBn,secretAm,secretAm256,secretBn,secretBn256);
                        len = basilisk_swapuserdata(userdata,privBn,0,myprivs[0],redeemscript,redeemlen);
                        if ( (txbytes[BASILISK_BOBREFUND]= basilisk_swap_bobtxspend(&signedtxid,txfee,"bobrefund",bobcoin,bob->pubtype,bob->p2shtype,bob->isPoS,bob->wiftype,ctx,myprivs[0],0,redeemscript,redeemlen,userdata,len,txids[BASILISK_BOBDEPOSIT],0,pubkey33,1,expiration,&values[BASILISK_BOBREFUND])) != 0 )
                            printf("pubB1.(%s) bobrefund.(%s)\n",bits256_str(str,pubB1),txbytes[BASILISK_BOBREFUND]);
                    }
                    if ( txbytes[BASILISK_BOBREFUND] != 0 )
                    {
                        txids[BASILISK_BOBREFUND] = LP_broadcast("bobrefund",bobcoin,txbytes[BASILISK_BOBREFUND]);
                        if ( bits256_nonz(txids[BASILISK_BOBREFUND]) != 0 ) // tested
                        {
                            sentflags[BASILISK_BOBREFUND] = 1;
                            depositspent = txids[BASILISK_BOBREFUND];
                        }
                    }
                } else printf("time %u vs expiration %u\n",(uint32_t)time(NULL),expiration);
            }
        }
    }
    //printf("finish.%d iambob.%d REFUND %d %d %d %d\n",finishedflag,iambob,sentflags[BASILISK_BOBREFUND] == 0,sentflags[BASILISK_BOBDEPOSIT] != 0,bits256_nonz(txids[BASILISK_BOBDEPOSIT]) != 0,bits256_nonz(depositspent) == 0);
    if ( sentflags[BASILISK_ALICESPEND] != 0 || sentflags[BASILISK_BOBRECLAIM] != 0 )
        sentflags[BASILISK_BOBPAYMENT] = 1;
    if ( sentflags[BASILISK_ALICERECLAIM] != 0 || sentflags[BASILISK_BOBSPEND] != 0 )
        sentflags[BASILISK_ALICEPAYMENT] = 1;
    if ( sentflags[BASILISK_ALICECLAIM] != 0 || sentflags[BASILISK_BOBREFUND] != 0 )
        sentflags[BASILISK_BOBDEPOSIT] = 1;
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
        if ( bits256_nonz(txids[i]) != 0 && values[i] == 0 )
            values[i] = basilisk_txvalue(basilisk_isbobcoin(iambob,i) ? bobcoin : alicecoin,txids[i],0);
    if ( origfinishedflag == 0 )
    {
        printf("iambob.%d Apaymentspent.(%s) alice.%d bob.%d %s %.8f\n",iambob,bits256_str(str,Apaymentspent),sentflags[BASILISK_ALICERECLAIM],sentflags[BASILISK_BOBSPEND],alicecoin,dstr(values[BASILISK_ALICEPAYMENT]));
        printf("paymentspent.(%s) alice.%d bob.%d %s %.8f\n",bits256_str(str,paymentspent),sentflags[BASILISK_ALICESPEND],sentflags[BASILISK_BOBRECLAIM],bobcoin,dstr(values[BASILISK_BOBPAYMENT]));
        printf("depositspent.(%s) alice.%d bob.%d %s %.8f\n",bits256_str(str,depositspent),sentflags[BASILISK_ALICECLAIM],sentflags[BASILISK_BOBREFUND],bobcoin,dstr(values[BASILISK_BOBDEPOSIT]));
    }
    values[BASILISK_OTHERFEE] = 0;
    if ( iambob == 0 )
    {
        if ( strcmp(alicecoin,"BTC") == 0 )
        {
            BTCtotals[BASILISK_ALICEPAYMENT] -= values[BASILISK_ALICEPAYMENT] * sentflags[BASILISK_ALICEPAYMENT];
            BTCtotals[BASILISK_ALICERECLAIM] += values[BASILISK_ALICEPAYMENT] * sentflags[BASILISK_ALICERECLAIM];
            BTCtotals[BASILISK_MYFEE] -= values[BASILISK_MYFEE] * sentflags[BASILISK_MYFEE];
        }
        else if ( strcmp(alicecoin,"KMD") == 0 )
        {
            KMDtotals[BASILISK_ALICEPAYMENT] -= values[BASILISK_ALICEPAYMENT] * sentflags[BASILISK_ALICEPAYMENT];
            KMDtotals[BASILISK_ALICERECLAIM] += values[BASILISK_ALICEPAYMENT] * sentflags[BASILISK_ALICERECLAIM];
            KMDtotals[BASILISK_MYFEE] -= values[BASILISK_MYFEE] * sentflags[BASILISK_MYFEE];
        }
        if ( strcmp(bobcoin,"KMD") == 0 )
        {
            KMDtotals[BASILISK_ALICESPEND] += values[BASILISK_BOBPAYMENT] * sentflags[BASILISK_ALICESPEND];
            KMDtotals[BASILISK_ALICECLAIM] += values[BASILISK_BOBDEPOSIT] * sentflags[BASILISK_ALICECLAIM];
        }
        else if ( strcmp(bobcoin,"BTC") == 0 )
        {
            BTCtotals[BASILISK_ALICESPEND] += values[BASILISK_BOBPAYMENT] * sentflags[BASILISK_ALICESPEND];
            BTCtotals[BASILISK_ALICECLAIM] += values[BASILISK_BOBDEPOSIT] * sentflags[BASILISK_ALICECLAIM];
        }
    }
    else
    {
        if ( strcmp(bobcoin,"BTC") == 0 )
        {
            BTCtotals[BASILISK_BOBPAYMENT] -= values[BASILISK_BOBPAYMENT] * sentflags[BASILISK_BOBPAYMENT];
            BTCtotals[BASILISK_BOBDEPOSIT] -= values[BASILISK_BOBDEPOSIT] * sentflags[BASILISK_BOBDEPOSIT];
            BTCtotals[BASILISK_BOBREFUND] += values[BASILISK_BOBREFUND] * sentflags[BASILISK_BOBREFUND];
            BTCtotals[BASILISK_BOBRECLAIM] += values[BASILISK_BOBRECLAIM] * sentflags[BASILISK_BOBRECLAIM];
            BTCtotals[BASILISK_MYFEE] -= values[BASILISK_MYFEE] * sentflags[BASILISK_MYFEE];
        }
        else if ( strcmp(bobcoin,"KMD") == 0 )
        {
            KMDtotals[BASILISK_BOBPAYMENT] -= values[BASILISK_BOBPAYMENT] * sentflags[BASILISK_BOBPAYMENT];
            KMDtotals[BASILISK_BOBDEPOSIT] -= values[BASILISK_BOBDEPOSIT] * sentflags[BASILISK_BOBDEPOSIT];
            KMDtotals[BASILISK_BOBREFUND] += values[BASILISK_BOBDEPOSIT] * sentflags[BASILISK_BOBREFUND];
            KMDtotals[BASILISK_BOBRECLAIM] += values[BASILISK_BOBPAYMENT] * sentflags[BASILISK_BOBRECLAIM];
            KMDtotals[BASILISK_MYFEE] -= values[BASILISK_MYFEE] * sentflags[BASILISK_MYFEE];
        }
        if ( strcmp(alicecoin,"KMD") == 0 )
        {
            KMDtotals[BASILISK_BOBSPEND] += values[BASILISK_BOBSPEND] * sentflags[BASILISK_BOBSPEND];
        }
        else if ( strcmp(alicecoin,"BTC") == 0 )
        {
            BTCtotals[BASILISK_BOBSPEND] += values[BASILISK_ALICEPAYMENT] * sentflags[BASILISK_BOBSPEND];
        }
    }
    finishedflag = basilisk_swap_isfinished(iambob,txids,sentflags,paymentspent,Apaymentspent,depositspent);
    jaddnum(item,"requestid",requestid);
    jaddnum(item,"quoteid",quoteid);
    jadd(item,"txs",array);
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
    {
        if ( sentflags[i] != 0 )
            jaddistr(array,txnames[i]);
        if ( txbytes[i] != 0 )
            free(txbytes[i]);
    }
    jadd(item,"sentflags",array);
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
        jaddinum(array,dstr(values[i]));
    jadd(item,"values",array);
    jaddstr(item,"result","success");
    if ( finishedflag != 0 )
        jaddstr(item,"status","finished");
    else jaddstr(item,"status","pending");
    bits256_str(str,paymentspent), jaddbits256(item,"paymentspent",paymentspent);
    bits256_str(str,Apaymentspent), jaddbits256(item,"Apaymentspent",Apaymentspent);
    bits256_str(str,depositspent), jaddbits256(item,"depositspent",depositspent);
    if ( origfinishedflag == 0 && finishedflag != 0 )
    {
        //printf("SWAP %u-%u finished!\n",requestid,quoteid);
        sprintf(fname,"%s/SWAPS/%u-%u.finished",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
        if ( (fp= fopen(fname,"wb")) != 0 )
        {
            char *itemstr;
            itemstr = jprint(item,0);
            fprintf(fp,"%s\n",itemstr);
            free(itemstr);
            fclose(fp);
        }
    }
    return(item);
}

char *basilisk_swaplist()
{
    char fname[512],*status; FILE *fp; cJSON *item,*retjson,*array,*totalsobj; uint32_t quoteid,requestid; int64_t KMDtotals[16],BTCtotals[16],Btotal,Ktotal; int32_t i;
    memset(KMDtotals,0,sizeof(KMDtotals));
    memset(BTCtotals,0,sizeof(BTCtotals));
    //,statebits; int32_t optionduration; struct basilisk_request R; bits256 privkey;
    retjson = cJSON_CreateObject();
    array = cJSON_CreateArray();
    sprintf(fname,"%s/SWAPS/list",GLOBAL_DBDIR), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"rb")) != 0 )
    {
        //struct basilisk_swap *swap;
        int32_t flag = 0;
        while ( fread(&requestid,1,sizeof(requestid),fp) == sizeof(requestid) && fread(&quoteid,1,sizeof(quoteid),fp) == sizeof(quoteid) )
        {
            flag = 0;
            /*for (i=0; i<myinfo->numswaps; i++)
                if ( (swap= myinfo->swaps[i]) != 0 && swap->I.req.requestid == requestid && swap->I.req.quoteid == quoteid )
                {
                    jaddi(array,basilisk_swapjson(swap));
                    flag = 1;
                    break;
                }*/
            if ( flag == 0 )
            {
                if ( (item= basilisk_remember(KMDtotals,BTCtotals,requestid,quoteid)) != 0 )
                {
                    jaddi(array,item);
                    if ( 1 && (status= jstr(item,"status")) != 0 && strcmp(status,"pending") == 0 )
                        break;
                }
            }
        }
        fclose(fp);
    }
    jaddstr(retjson,"result","success");
    jadd(retjson,"swaps",array);
    if ( cJSON_GetArraySize(array) > 0 )
    {
        totalsobj = cJSON_CreateObject();
        for (Btotal=i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
            if ( BTCtotals[i] != 0 )
                jaddnum(totalsobj,txnames[i],dstr(BTCtotals[i])), Btotal += BTCtotals[i];
        jadd(retjson,"BTCtotals",totalsobj);
        totalsobj = cJSON_CreateObject();
        for (Ktotal=i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
            if ( KMDtotals[i] != 0 )
                jaddnum(totalsobj,txnames[i],dstr(KMDtotals[i])), Ktotal += KMDtotals[i];
        jadd(retjson,"KMDtotals",totalsobj);
        jaddnum(retjson,"KMDtotal",dstr(Ktotal));
        jaddnum(retjson,"BTCtotal",dstr(Btotal));
        if ( Ktotal > 0 && Btotal < 0 )
            jaddnum(retjson,"avebuy",(double)-Btotal/Ktotal);
        else if ( Ktotal < 0 && Btotal > 0 )
            jaddnum(retjson,"avesell",(double)-Btotal/Ktotal);
    }
    array = cJSON_CreateArray();
    /*for (i=0; i<sizeof(myinfo->linfos)/sizeof(*myinfo->linfos); i++)
    {
        if ( myinfo->linfos[i].base[0] != 0 && myinfo->linfos[i].rel[0] != 0 )
            jaddi(array,linfo_json(&myinfo->linfos[i]));
    }
    jadd(retjson,"quotes",array);*/
    return(jprint(retjson,1));
}

