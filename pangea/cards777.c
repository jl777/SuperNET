/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
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
#ifdef later

#ifdef DEFINES_ONLY
#ifndef cards777_h
#define cards777_h

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include "../iguana777.h"

#endif
#else
#ifndef cards777_c
#define cards777_c

#ifndef cards777_h
#define DEFINES_ONLY
#include "cards777.c"
#undef DEFINES_ONLY
#endif
#include "../includes/curve25519.h"

bits256 xoverz_donna(bits256 a);
bits256 crecip_donna(bits256 a);
bits256 fmul_donna(bits256 a,bits256 b);

void calc_shares(unsigned char *shares,unsigned char *secret,int32_t size,int32_t width,int32_t M,int32_t N,unsigned char *sharenrs);
int32_t init_sharenrs(unsigned char sharenrs[255],unsigned char *orig,int32_t m,int32_t n);
void gfshare_ctx_dec_newshares(void *ctx,unsigned char *sharenrs);
void gfshare_ctx_dec_giveshare(void *ctx,unsigned char sharenr,unsigned char *share);
void gfshare_ctx_dec_extract(void *ctx,unsigned char *secretbuf);
void *gfshare_ctx_init_dec(unsigned char *sharenrs,uint32_t sharecount,uint32_t size);
void gfshare_ctx_free(void *ctx);

bits256 cards777_initcrypt(bits256 data,bits256 privkey,bits256 pubkey,int32_t invert)
{
    bits256 hash; //bits320 hexp;
    hash = curve25519_shared(privkey,pubkey);
    if ( invert != 0 )
        hash = crecip_donna(hash);
    return(fmul_donna(data,hash));
    //hexp = fexpand(hash);
    //if ( invert != 0 )
    //    hexp = crecip(hexp);
    //return(fcontract(fmul(fexpand(data),hexp)));
}

bits256 cards777_cardpriv(bits256 playerpriv,bits256 *cardpubs,int32_t numcards,bits256 cipher)
{
    bits256 cardpriv,checkpub; int32_t i;
    for (i=0; i<numcards; i++)
    {
        cardpriv = cards777_initcrypt(cipher,playerpriv,cardpubs[i],1);
        //printf("(%llx %llx) ",(long long)cardpriv.txid,(long long)curve25519_shared(playerpriv,cardpubs[i]).txid);
        checkpub = curve25519(cardpriv,curve25519_basepoint9());
        if ( memcmp(checkpub.bytes,cardpubs[i].bytes,sizeof(bits256)) == 0 )
        {
            //printf("%d ",cardpriv.bytes[1]);
            //printf("decrypted card.%d %llx\n",cardpriv.bytes[1],(long long)cardpriv.txid);
            return(cardpriv);
        }
    }
    //printf("\nplayerpriv %llx cipher.%llx\n",(long long)playerpriv.txid,(long long)cipher.txid);
    memset(cardpriv.bytes,0,sizeof(cardpriv));
    return(cardpriv);
}

int32_t cards777_checkcard(bits256 *cardprivp,int32_t cardi,int32_t slot,int32_t destplayer,bits256 playerpriv,bits256 *cardpubs,int32_t numcards,bits256 card)
{
    bits256 cardpriv;
    cardpriv = cards777_cardpriv(playerpriv,cardpubs,numcards,card);
    if ( cardpriv.txid != 0 )
    {
        if ( slot >= 0 && destplayer != slot )
            printf(">>>>>>>>>>>> ERROR ");
        if ( Debuglevel > 2 )
            printf("slot.%d B DECODED cardi.%d destplayer.%d cardpriv.[%d]\n",slot,cardi,destplayer,cardpriv.bytes[1]);
        *cardprivp = cardpriv;
        return(cardpriv.bytes[1]);
    }
    memset(cardprivp,0,sizeof(*cardprivp));
    return(-1);
}

int32_t cards777_validate(bits256 cardpriv,bits256 final,bits256 *cardpubs,int32_t numcards,bits256 *audit,int32_t numplayers,bits256 playerpub)
{
    int32_t i; bits256 val,checkcard,ver;//,tmp; //bits320 val;
    //val = fexpand(final);
    val = final;
    for (i=numplayers-1; i>0; i--)
    {
        //val = fmul(fexpand(audit[i]),val);
        //tmp = fcontract(val);
        val = fmul_donna(audit[i],val);
        //if ( memcmp(tmp.bytes,audit[i-1].bytes,sizeof(tmp)) != 0 )
        //    printf("cards777_validate: mismatched audit[%d] %llx vs %llx %llx\n",i-1,(long long)tmp.txid,(long long)audit[i-1].txid,(long long)audit[i].txid);
    }
    checkcard = val;//fcontract(val);
    if ( memcmp(checkcard.bytes,audit[0].bytes,sizeof(checkcard)) != 0 )
    {
        printf("cards777_validate: checkcard not validated %llx vs %llx numplayers.%d\n",(long long)checkcard.txid,(long long)audit[0].txid,numplayers);
        return(-1);
    }
    ver = cards777_initcrypt(cardpriv,cardpriv,playerpub,0);
    if ( memcmp(checkcard.bytes,ver.bytes,sizeof(checkcard)) != 0 )
    {
        printf("cards777_validate: ver not validated %llx vs %llx\n",(long long)checkcard.txid,(long long)ver.txid);
        return(-1);
    }
    return(cardpriv.bytes[1]);
}

int32_t cards777_shuffle(bits256 *shuffled,bits256 *cards,int32_t numcards,int32_t N)
{
    int32_t i,j,pos,nonz,permi[CARDS777_MAXCARDS],desti[CARDS777_MAXCARDS]; uint8_t x; uint64_t mask;
    memset(desti,0,sizeof(desti));
    for (i=0; i<numcards; i++)
        desti[i] = i;
    for (i=0; i<numcards; i++)
    {
        randombytes(&x,1);
        pos = (x % ((numcards-1-i) + 1));
        //printf("%d ",pos);
        permi[i] = desti[pos];
        desti[pos] = desti[numcards-1 - i];
        desti[numcards-1 - i] = -1;
    }
    //printf("pos\n");
    for (mask=i=nonz=0; i<numcards; i++)
    {
        if ( 0 && Debuglevel > 2 )
            printf("%d ",permi[i]);
        mask |= (1LL << permi[i]);
        for (j=0; j<N; j++,nonz++)
            shuffled[nonz] = cards[permi[i]*N + j];//, printf("%llx ",(long long)shuffled[nonz].txid);
    }
    if ( Debuglevel > 2 )
        printf("shuffled mask.%llx err.%llx\n",(long long)mask,(long long)(mask ^ ((1LL<<numcards)-1)));
    return(0);
}

void cards777_layer(bits256 *layered,bits256 *xoverz,bits256 *incards,int32_t numcards,int32_t N)
{
    int32_t i,k,nonz = 0; bits256 z_x; //bits320 bp,x,z,x_z,z_x;
    //bp = fexpand(curve25519_basepoint9());
    //bp = curve25519_basepoint9();
    for (i=nonz=0; i<numcards; i++)
    {
        for (k=0; k<N; k++,nonz++)
        {
            if ( 0 )
            {
                //cmult(&x,&z,rand256(1),bp);
                //x_z = fmul(x,crecip(z));
                //z_x = crecip(x_z);
                //layered[nonz] = fcontract(fmul(z_x,fexpand(incards[nonz])));
                //xoverz[nonz] = fcontract(x_z);
            }
            else
            {
                xoverz[nonz] = xoverz_donna(rand256(1));
                z_x = crecip_donna(xoverz[nonz]);
                layered[nonz] = fmul_donna(z_x,incards[nonz]);

            }
            //printf("{%llx -> %llx}.%d ",(long long)incards[nonz].txid,(long long)layered[nonz].txid,nonz);
        }
        //printf("card.%d\n",i);
    }
}

int32_t cards777_calcmofn(uint8_t *allshares,uint8_t *myshares[],uint8_t *sharenrs,int32_t M,bits256 *xoverz,int32_t numcards,int32_t N)
{
    int32_t size,j;
    size = N * sizeof(bits256) * numcards;
    calc_shares(allshares,(void *)xoverz,size,size,M,N,sharenrs); // PM &allshares[playerj * size] to playerJ
    for (j=0; j<N; j++)
        myshares[j] = &allshares[j * size];
    return(size);
}

uint8_t *cards777_recover(uint8_t *shares[],uint8_t *sharenrs,int32_t M,int32_t numcards,int32_t N)
{
    void *G; int32_t i,size; uint8_t *recover,recovernrs[255];
    size = N * sizeof(bits256) * numcards;
    if ( (recover= calloc(1,size)) == 0 )
    {
        printf("cards777_recover: unexpected out of memory error\n");
        return(0);
    }
    memset(recovernrs,0,sizeof(recovernrs));
    for (i=0; i<N; i++)
        if ( shares[i] != 0 )
            recovernrs[i] = sharenrs[i];
    G = gfshare_ctx_init_dec(recovernrs,N,size);
    for (i=0; i<N; i++)
        if ( shares[i] != 0 )
            gfshare_ctx_dec_giveshare(G,i,shares[i]);
    gfshare_ctx_dec_newshares(G,recovernrs);
    gfshare_ctx_dec_extract(G,recover);
    gfshare_ctx_free(G);
    return(recover);
}

bits256 cards777_pubkeys(bits256 *pubkeys,int32_t numcards,bits256 cmppubkey)
{
    int32_t i; bits256 bp,pubkey,hash,check,prod; //bits320 prod,hexp; // cJSON *array; char *hexstr;
    memset(check.bytes,0,sizeof(check));
    memset(bp.bytes,0,sizeof(bp)), bp.bytes[0] = 9;
    //prod = fmul(fexpand(bp),crecip(fexpand(bp)));
    prod = fmul_donna(bp,crecip_donna(bp));
    for (i=0; i<numcards; i++)
    {
        pubkey = pubkeys[i];
        vcalc_sha256(0,hash.bytes,pubkey.bytes,sizeof(pubkey));
        hash.bytes[0] &= 0xf8, hash.bytes[31] &= 0x7f, hash.bytes[31] |= 64;
        //hexp = fexpand(hash);
        //prod = fmul(prod,hexp);
        prod = fmul_donna(prod,hash);
    }
    check = prod;//fcontract(prod);
    if ( cmppubkey.txid != 0 )
    {
        if ( memcmp(check.bytes,cmppubkey.bytes,sizeof(check)) != 0 )
            printf("cards777_pubkeys: mismatched pubkeys permicheck.%llx != prod.%llx\n",(long long)check.txid,(long long)pubkey.txid);
        //else printf("pubkeys matched\n");
    }
    return(check);
}

bits256 cards777_initdeck(bits256 *cards,bits256 *cardpubs,int32_t numcards,int32_t N,bits256 *playerpubs,bits256 *playerprivs)
{
    char buf[4096]; bits256 privkey,pubkey,hash, bp,prod; int32_t i,j,nonz,num = 0; uint64_t mask = 0;
    //bp = fexpand(curve25519_basepoint9());
    //prod = crecip(bp);
    //prod = fmul(bp,prod);
    bp = curve25519_basepoint9();
    prod = crecip_donna(bp);
    prod = fmul_donna(bp,prod);
    if ( Debuglevel > 2 )
        printf("card777_initdeck unit.%llx\n",(long long)prod.txid);
    nonz = 0;
    while ( mask != (1LL << numcards)-1 )
    {
        privkey = curve25519_keypair(&pubkey);
        buf[0] = 0;
        if ( (i=privkey.bytes[1]) < numcards && ((1LL << i) & mask) == 0 )
        {
            mask |= (1LL << i);
            cardpubs[num] = pubkey;
            if ( playerprivs != 0 )
                sprintf(buf+strlen(buf),"%llx.",(long long)privkey.txid);
            for (j=0; j<N; j++,nonz++)
            {
                cards[nonz] = cards777_initcrypt(privkey,privkey,playerpubs[j],0);
                if ( playerprivs != 0 )
                    sprintf(buf+strlen(buf),"[%llx * %llx -> %llx] ",(long long)cards[nonz].txid,(long long)curve25519_shared(playerprivs[j],pubkey).txid,(long long)cards777_initcrypt(cards[nonz],playerprivs[j],pubkey,1).txid);
            }
            vcalc_sha256(0,hash.bytes,pubkey.bytes,sizeof(pubkey));
            hash.bytes[0] &= 0xf8, hash.bytes[31] &= 0x7f, hash.bytes[31] |= 64;
            //hexp = fexpand(hash);
            //prod = fmul(prod,hexp);
            prod = fmul_donna(prod,hash);
            //printf("(%s) num.%d [%llx] %d prod.%llx\n",buf,num,(long long)mask ^ ((1LL << numcards)-1),i,(long long)prod.txid);
            num++;
        }
    }
    if ( playerprivs != 0 )
        printf("\n%llx %llx playerprivs\n",(long long)playerprivs[0].txid,(long long)playerprivs[1].txid);
    if ( 0 && Debuglevel > 2 )
    {
        for (i=0; i<numcards; i++)
            printf("%d ",cards[i*N].bytes[1]);
        printf("init order %llx (%llx %llx)\n",(long long)prod.txid,(long long)playerpubs[0].txid,(long long)playerpubs[1].txid);
    }
    //return(fcontract(prod));
    return(prod);
}

uint8_t *cards777_encode(bits256 *encoded,bits256 *xoverz,uint8_t *allshares,uint8_t *myshares[],uint8_t sharenrs[255],int32_t M,bits256 *ciphers,int32_t numcards,int32_t N)
{
    bits256 shuffled[CARDS777_MAXCARDS * CARDS777_MAXPLAYERS];
    cards777_shuffle(shuffled,ciphers,numcards,N);
    cards777_layer(encoded,xoverz,shuffled,numcards,N);
    memset(sharenrs,0,255);
    init_sharenrs(sharenrs,0,N,N);
    cards777_calcmofn(allshares,myshares,sharenrs,M,xoverz,numcards,N);
    memcpy(ciphers,shuffled,numcards * N * sizeof(bits256));
    if ( 1 )
    {
        /*{
            init_hexbytes_noT(nrs,dp->hand.sharenrs,dp->N);
            if ( (nrs= jstr(json,"sharenrs")) != 0 )
                decode_hex(dp->hand.sharenrs,(int32_t)strlen(nrs)>>1,nrs);
        }*/
        int32_t i,j,m,size; uint8_t *recover,*testshares[CARDS777_MAXPLAYERS],testnrs[255];
        size = N * sizeof(bits256) * numcards;
        for (j=0; j<1; j++)
        {
            memset(testnrs,0,sizeof(testnrs));
            memset(testshares,0,sizeof(testshares));
            m = (rand() % N) + 1;
            if ( m < M )
                m = M;
            if ( init_sharenrs(testnrs,sharenrs,m,N) < 0 )
            {
                printf("iter.%d error init_sharenrs(m.%d of n.%d)\n",j,m,N);
                return(0);
            }
            for (i=0; i<N; i++)
                if ( testnrs[i] == sharenrs[i] )
                    testshares[i] = myshares[i];
            if ( (recover= cards777_recover(testshares,sharenrs,M,numcards,N)) != 0 )
            {
                if ( memcmp(xoverz,recover,size) != 0 )
                    fprintf(stderr,"(ERROR m.%d M.%d N.%d)\n",m,M,N);
                else fprintf(stderr,"reconstructed with m.%d M.%d N.%d\n",m,M,N);
                free(recover);
            } else printf("nullptr from cards777_recover\n");
        }
    }
    return(allshares);
}

bits256 cards777_decode(bits256 *seedp,bits256 *xoverz,int32_t destplayer,bits256 cipher,bits256 *outcards,int32_t numcards,int32_t N)
{
    int32_t i,ind;
    memset(seedp->bytes,0,sizeof(*seedp));
    for (i=0; i<numcards; i++)
    {
        ind = i*N + destplayer;
        //printf("[%llx] ",(long long)outcards[ind].txid);
        if ( memcmp(outcards[ind].bytes,cipher.bytes,32) == 0 )
        {
            *seedp = xoverz[ind];
            //cipher = fcontract(fmul(fexpand(xoverz[ind]),fexpand(cipher)));
            cipher = fmul_donna(xoverz[ind],cipher);
            //printf("matched %d -> %llx\n",i,(long long)cipher.txid);
            return(cipher);
        }
    }
    if ( i == numcards )
    {
        printf("decryption error %llx: destplayer.%d no match\n",(long long)cipher.txid,destplayer);
        memset(cipher.bytes,0,sizeof(cipher));
        //cipher = cards777_cardpriv(playerpriv,cardpubs,numcards,cipher);
    }
    return(cipher);
}

struct cards777_privdata *cards777_allocpriv(int32_t numcards,int32_t N)
{
    struct cards777_privdata *priv;
    if ( (priv= calloc(1,sizeof(*priv) + sizeof(bits256) * (2*((N * numcards * N) + (N * numcards))))) == 0 )
    {
        printf("cards777_allocpriv: unexpected out of memory error\n");
        return(0);
    }
    priv->audits = &priv->data[0];
    priv->outcards = &priv->audits[N * numcards * N];
    priv->xoverz = &priv->outcards[N * numcards];
    priv->allshares = (void *)&priv->xoverz[N * numcards]; // N*numcards*N
    return(priv);
}

struct cards777_pubdata *cards777_allocpub(int32_t M,int32_t numcards,int32_t N)
{
    struct cards777_pubdata *dp;
    if ( (dp= calloc(1,sizeof(*dp) + sizeof(bits256) * ((numcards + 1) + (N * numcards)))) == 0 )
    {
        printf("cards777_allocpub: unexpected out of memory error\n");
        return(0);
    }
    dp->M = M, dp->N = N, dp->numcards = numcards;
    dp->hand.cardpubs = &dp->data[0];
    dp->hand.final = &dp->hand.cardpubs[numcards + 1];
    return(dp);
}

int32_t cards777_testinit(struct hostnet777_server *srv,int32_t M,struct hostnet777_client **clients,int32_t N,int32_t numcards)
{
    //static int64_t balances[9];
    int32_t i; uint8_t sharenrs[255]; //,destplayer,cardibits256 *ciphers,cardpriv,card; uint64_t mask = 0;
    struct cards777_pubdata *dp; //struct cards777_privdata *priv; struct pangea_info *sp;
    if ( srv->num != N )
    {
        printf("srv->num.%d != N.%d\n",srv->num,N);
        return(-1);
    }
    memset(sharenrs,0,sizeof(sharenrs));
    init_sharenrs(sharenrs,0,N,N); // this needs to be done to start a hand
    for (i=0; i<N; i++)
    {
        dp = srv->clients[i].pubdata = cards777_allocpub(M,numcards,N);
        //sp = dp->table;
        memcpy(dp->hand.sharenrs,sharenrs,dp->N);
        /*for (j=0; j<N; j++)
            sp->playerpubs[j] = srv->clients[j].pubkey;
        for (j=0; j<N; j++)
        {
            balances[j] = 100;
            dp->balances[j] = &balances[j];
        }*/
        printf("deprecated, need to init sp->\n");
        //priv = srv->clients[i].privdata = cards777_allocpriv(numcards,N);
        //priv->privkey = (i == 0) ? srv->H.privkey : clients[i]->H.privkey;
        /*if ( i == 0 )
            dp->checkprod = cards777_initdeck(priv->outcards,dp->cardpubs,numcards,N,dp->playerpubs), refdp = dp;
        else memcpy(dp->cardpubs,refdp->cardpubs,sizeof(*dp->cardpubs) * numcards);*/
    }
    return(0);
    /*priv = srv->clients[0].privdata;
    ciphers = priv->outcards;
    for (i=1; i<N; i++)
    {
        dp = srv->clients[i].pubdata;
        priv = srv->clients[i].privdata;
        cards777_encode(priv->outcards,priv->xoverz,priv->allshares,priv->myshares,dp->sharenrs,dp->M,ciphers,dp->numcards,dp->N);
        ciphers = priv->outcards;
    }
    for (cardi=0; cardi<dp->numcards; cardi++)
    {
        for (destplayer=0; destplayer<dp->N; destplayer++)
        {
            priv = srv->clients[dp->N - 1].privdata;
            card = priv->outcards[cardi*dp->N + destplayer];
            for (i=N-1; i>=0; i--)
            {
                j = (i > 0) ? i : destplayer;
                //printf("cardi.%d destplayer.%d i.%d j.%d\n",cardi,destplayer,i,j);
                dp = srv->clients[j].pubdata;
                priv = srv->clients[j].privdata;
                cardpriv = cards777_cardpriv(priv->privkey,dp->cardpubs,dp->numcards,card);
                if ( cardpriv.txid != 0 )
                {
                    mask |= (1LL << cardpriv.bytes[1]);
                    if ( destplayer != j )
                        printf(">>>>>>>>>>>> ERROR ");
                    printf("i.%d j.%d A DECODED cardi.%d destplayer.%d cardpriv.[%d] mask.%llx\n",i,j,cardi,destplayer,cardpriv.bytes[1],(long long)mask);
                    break;
                }
                card = cards777_decode(priv->xoverz,destplayer,card,priv->outcards,dp->numcards,dp->N);
                cardpriv = cards777_cardpriv(priv->privkey,dp->cardpubs,dp->numcards,card);
                if ( cardpriv.txid != 0 )
                {
                    mask |= (1LL << cardpriv.bytes[1]);
                    if ( destplayer != j )
                        printf(">>>>>>>>>>>> ERROR ");
                    printf("i.%d j.%d B DECODED cardi.%d destplayer.%d cardpriv.[%d] mask.%llx\n",i,j,cardi,destplayer,cardpriv.bytes[1],(long long)mask);
                    break;
                }
            }
        }
        printf("cardi.%d\n\n",cardi);
    }*/
    return(0);
}

void cards777_initid(struct hostnet777_id *id,bits256 pubkey,struct cards777_pubdata *dp,struct cards777_privdata *priv)
{
    id->pubkey = pubkey;
    id->nxt64bits = acct777_nxt64bits(pubkey);
    id->pubdata = dp;
    id->privdata = priv;
    id->pmsock = -1;
}

void cards777_test()
{
    int32_t i,j,vals[52][52]; bits256 keypairs[52][2],otherpairs[52][2],matrix[52][52]; char buf[512];
    FILE *fp;
    if ( (fp= fopen("/persistent/test","rb")) != 0 )
    {
        if ( fread(buf,6,1,fp) <= 0 )
            printf("read error for /persistent/test\n");
        buf[6] = 0;
        printf("test exists (%s)\n",buf);
        fclose(fp);
    } else printf("testfile not present\n");
    for (i=0; i<52; i++)
        keypairs[i][0] = curve25519_keypair(&keypairs[i][1]);
    for (j=0; j<52; j++)
        otherpairs[j][0] = curve25519_keypair(&otherpairs[j][1]);
    bits256 zmone;zmone = crecip_donna(keypairs[0][0]);
    printf("DEBUG.%d %llx vs %llx | %llx -> %llx/%llx\n",Debuglevel,(long long)keypairs[0][0].txid,(long long)fcontract(fexpand(keypairs[0][0])).txid,(long long)zmone.txid,(long long)fexpand(fmul_donna(keypairs[0][0],zmone)).txid,(long long)fmul(fexpand(keypairs[0][0]),fexpand(zmone)).txid);
    for (i=0; i<52; i++)
    {break;
        buf[0] = 0;
        for (j=0; j<52; j++)
        {
            matrix[i][j] = fmul_donna(keypairs[j][1],otherpairs[i][1]);
            vals[i][j] = matrix[i][j].bytes[1] % 52;
            sprintf(buf+strlen(buf),"%d ",vals[i][j]);
        }
        printf("%s\n",buf);
    }
    struct hostnet777_server *srv;  int32_t M,N = 9; //struct hostnet777_client **clients;
    struct cards777_pubdata *dp; struct cards777_privdata *priv;
    bits256 checkprod,cards[52],playerpubs[9],playerprivs[9];
    //clients = calloc(N+1,sizeof(*clients));
    if ( (srv= hostnet777_server(keypairs[0][0],keypairs[0][1],0,0,0,N)) == 0 )
    {
        printf("cant create hostnet777 server\n");
        return;
    }
    M = (N >> 1) + 1;
    for (i=0; i<N; i++)
    {
        cards777_initid(&srv->clients[i],keypairs[i][1],cards777_allocpub(M,52,N),cards777_allocpriv(52,N));
        playerprivs[i] = keypairs[i][0];
        playerpubs[i] = keypairs[i][1];
        if ( i == 0 )
        {
            srv->H.privkey = keypairs[i][0];
            srv->H.pubkey = keypairs[i][1];
        }
        else
        {
        }
    }
    dp = srv->clients[0].pubdata;
    dp->N = N; dp->M = M; dp->numcards = 52;
    checkprod = cards777_initdeck(cards,dp->hand.cardpubs,52,N,playerpubs,0);
    printf("deck initialzed %llx\n",(long long)checkprod.txid);
    uint8_t sharenrs[255]; uint64_t mask = 0; int32_t cardi,destplayer;
    bits256 card,cardpriv,seed,*ciphers = cards;
    for (i=1; i<N; i++)
    {
        dp = srv->clients[i].pubdata;
        dp->N = N; dp->M = M; dp->numcards = 52;
        priv = srv->clients[i].privdata;
        cards777_encode(priv->outcards,priv->xoverz,priv->allshares,priv->myshares,sharenrs,dp->M,ciphers,dp->numcards,dp->N);
        ciphers = priv->outcards;
    }
    printf("deck encrypted\n");
    for (cardi=0; cardi<dp->numcards; cardi++)
    {
        for (destplayer=0; destplayer<dp->N; destplayer++)
        {
            priv = srv->clients[dp->N - 1].privdata;
            card = priv->outcards[cardi*dp->N + destplayer];
            for (i=N-1; i>=0; i--)
            {
                j = (i > 0) ? i : destplayer;
                //printf("cardi.%d destplayer.%d i.%d j.%d\n",cardi,destplayer,i,j);
                dp = srv->clients[j].pubdata;
                priv = srv->clients[j].privdata;
                cardpriv = cards777_cardpriv(keypairs[j][0],dp->hand.cardpubs,dp->numcards,card);
                if ( cardpriv.txid != 0 )
                {
                    mask |= (1LL << cardpriv.bytes[1]);
                    if ( destplayer != j )
                        printf(">>>>>>>>>>>> ERROR ");
                    printf("i.%d j.%d A DECODED cardi.%d destplayer.%d cardpriv.[%d] mask.%llx\n",i,j,cardi,destplayer,cardpriv.bytes[1],(long long)mask);
                    break;
                }
                card = cards777_decode(&seed,priv->xoverz,destplayer,card,priv->outcards,dp->numcards,dp->N);
                cardpriv = cards777_cardpriv(keypairs[j][0],dp->hand.cardpubs,dp->numcards,card);
                if ( cardpriv.txid != 0 )
                {
                    mask |= (1LL << cardpriv.bytes[1]);
                    if ( destplayer != j )
                        printf(">>>>>>>>>>>> ERROR ");
                    printf("i.%d j.%d B DECODED cardi.%d destplayer.%d cardpriv.[%d] mask.%llx\n",i,j,cardi,destplayer,cardpriv.bytes[1],(long long)mask);
                    break;
                }
            }
        }
        printf("cardi.%d\n\n",cardi);
        break;
    }
}

#endif
#endif

#endif
