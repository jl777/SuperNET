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
//  main.c
//  stats
//
//  Copyright © 2017 SuperNET. All rights reserved.
//

#include <stdio.h>
#include <stdint.h>
#include "OS_portable.h"
#define MAX(a,b) ((a) > (b) ? (a) : (b))


#define IGUANA_URL "http://127.0.0.1:7778"
#define STATS_DESTDIR "/var/www/html"
#define STATS_DEST "/var/www/html/DEXstats.json"

char CURRENCIES[][8] = { "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD", // major currencies
    "CNY", "RUB", "MXN", "BRL", "INR", "HKD", "TRY", "ZAR", "PLN", "NOK", "SEK", "DKK", "CZK", "HUF", "ILS", "KRW", "MYR", "PHP", "RON", "SGD", "THB", "BGN", "IDR", "HRK", // end of currencies
};

char ASSETCHAINS_SYMBOL[16] = { "KV" };

struct komodo_state
{
    bits256 NOTARIZED_HASH,NOTARIZED_DESTTXID;
    int32_t SAVEDHEIGHT,CURRENT_HEIGHT,NOTARIZED_HEIGHT;
    uint32_t SAVEDTIMESTAMP;
    uint64_t deposited,issued,withdrawn,approved,redeemed,shorted;
    struct notarized_checkpoint *NPOINTS; int32_t NUM_NPOINTS;
    struct komodo_event **Komodo_events; int32_t Komodo_numevents;
    uint32_t RTbufs[64][3]; uint64_t RTmask;
};

struct komodo_state KOMODO_STATE;

void komodo_kvupdate(int32_t ht,bits256 txid,int32_t vout,uint8_t *opretbuf,int32_t opretlen,uint64_t value)
{
    static bits256 zeroes;
    uint32_t flags; bits256 pubkey,refpubkey,sig; int32_t i,refvaluesize,hassig,coresize,haspubkey,height,kvheight; uint16_t keylen,valuesize,newflag = 0; uint8_t *key,*valueptr,keyvalue[10000];
    iguana_rwnum(0,&opretbuf[1],sizeof(keylen),&keylen);
    iguana_rwnum(0,&opretbuf[3],sizeof(valuesize),&valuesize);
    iguana_rwnum(0,&opretbuf[5],sizeof(height),&height);
    iguana_rwnum(0,&opretbuf[9],sizeof(flags),&flags);
    key = &opretbuf[13];
    if ( keylen+13 > opretlen )
    {
        printf("komodo_kvupdate: keylen.%d + 13 > opretlen.%d\n",keylen,opretlen);
        return;
    }
    valueptr = &key[keylen];
    coresize = (int32_t)(sizeof(flags)+sizeof(height)+sizeof(keylen)+sizeof(valuesize)+keylen+valuesize+1);
    if ( opretlen == coresize || opretlen == coresize+sizeof(bits256) || opretlen == coresize+2*sizeof(bits256) )
    {
        memset(&pubkey,0,sizeof(pubkey));
        memset(&sig,0,sizeof(sig));
        if ( (haspubkey= (opretlen >= coresize+sizeof(bits256))) != 0 )
        {
            for (i=0; i<32; i++)
                ((uint8_t *)&pubkey)[i] = opretbuf[coresize+i];
        }
        if ( (hassig= (opretlen == coresize+sizeof(bits256)*2)) != 0 )
        {
            for (i=0; i<32; i++)
                ((uint8_t *)&sig)[i] = opretbuf[coresize+sizeof(bits256)+i];
        }
        /*if ( (refvaluesize= komodo_kvsearch((bits256 *)&refpubkey,height,&flags,&kvheight,&keyvalue[keylen],key,keylen)) >= 0 )
        {
            if ( memcmp(&zeroes,&refpubkey,sizeof(refpubkey)) != 0 )
            {
                if ( komodo_kvsigverify(keyvalue,keylen+refvaluesize,refpubkey,sig) < 0 )
                {
                    //printf("komodo_kvsigverify error [%d]\n",coresize-13);
                    return;
                }
            }
        }*/
        for (i=0; i<keylen; i++)
            putchar((char)key[i]);
        printf(" -> ");
        for (i=0; i<coresize; i++)
            putchar((char)valueptr[i]);
        char str[65]; printf(" [%d] %s/v%d ht.%d height.%d\n",valuesize,bits256_str(str,txid),vout,ht,height);
    }
}

void komodo_eventadd_opreturn(struct komodo_state *sp,char *symbol,int32_t height,bits256 txid,uint64_t value,uint16_t vout,uint8_t *opretbuf,uint16_t opretlen)
{
    if ( sp != 0 )
    {
        if ( opretbuf[0] == 'K' && opretlen != 40 )
        {
            komodo_kvupdate(height,txid,vout,opretbuf,opretlen,value);
        }
    }
}

void komodo_setkmdheight(struct komodo_state *sp,int32_t kmdheight,uint32_t timestamp)
{
    if ( sp != 0 )
    {
        if ( kmdheight > sp->SAVEDHEIGHT )
        {
            sp->SAVEDHEIGHT = kmdheight;
            sp->SAVEDTIMESTAMP = timestamp;
        }
        if ( kmdheight > sp->CURRENT_HEIGHT )
            sp->CURRENT_HEIGHT = kmdheight;
    }
}

void komodo_eventadd_kmdheight(struct komodo_state *sp,char *symbol,int32_t height,int32_t kmdheight,uint32_t timestamp)
{
    uint32_t buf[2];
    if ( kmdheight > 0 )
    {
        buf[0] = (uint32_t)kmdheight;
        buf[1] = timestamp;
        //komodo_eventadd(sp,height,symbol,KOMODO_EVENT_KMDHEIGHT,(uint8_t *)buf,sizeof(buf));
        if ( sp != 0 )
            komodo_setkmdheight(sp,kmdheight,timestamp);
    }
    else
    {
        kmdheight = -kmdheight;
        //komodo_eventadd(sp,height,symbol,KOMODO_EVENT_REWIND,(uint8_t *)&height,sizeof(height));
        //if ( sp != 0 )
        //    komodo_event_rewind(sp,symbol,height);
    }
}

int32_t komodo_parsestatefile(struct komodo_state *sp,FILE *fp,char *symbol,char *dest)
{
    static int32_t errs;
    int32_t func,ht,notarized_height,num,matched=0; bits256 notarized_hash,notarized_desttxid; uint8_t pubkeys[64][33];
    if ( (func= fgetc(fp)) != EOF )
    {
        if ( ASSETCHAINS_SYMBOL[0] == 0 && strcmp(symbol,"KMD") == 0 )
            matched = 1;
        else matched = (strcmp(symbol,ASSETCHAINS_SYMBOL) == 0);
        if ( fread(&ht,1,sizeof(ht),fp) != sizeof(ht) )
            errs++;
        //printf("fpos.%ld func.(%d %c) ht.%d ",ftell(fp),func,func,ht);
        if ( func == 'P' )
        {
            if ( (num= fgetc(fp)) <= 64 )
            {
                if ( fread(pubkeys,33,num,fp) != num )
                    errs++;
                else
                {
                    //printf("updated %d pubkeys at %s ht.%d\n",num,symbol,ht);
                    //if ( (KOMODO_EXTERNAL_NOTARIES != 0 && matched != 0) || (strcmp(symbol,"KMD") == 0 && KOMODO_EXTERNAL_NOTARIES == 0) )
                     //   komodo_eventadd_pubkeys(sp,symbol,ht,num,pubkeys);
                }
            } else printf("illegal num.%d\n",num);
        }
        else if ( func == 'N' )
        {
            if ( fread(&notarized_height,1,sizeof(notarized_height),fp) != sizeof(notarized_height) )
                errs++;
            if ( fread(&notarized_hash,1,sizeof(notarized_hash),fp) != sizeof(notarized_hash) )
                errs++;
            if ( fread(&notarized_desttxid,1,sizeof(notarized_desttxid),fp) != sizeof(notarized_desttxid) )
                errs++;
            //if ( matched != 0 ) global independent states -> inside *sp
            //komodo_eventadd_notarized(sp,symbol,ht,dest,notarized_hash,notarized_desttxid,notarized_height);
        }
        else if ( func == 'U' ) // deprecated
        {
            uint8_t n,nid; bits256 hash; uint64_t mask;
            n = fgetc(fp);
            nid = fgetc(fp);
            //printf("U %d %d\n",n,nid);
            if ( fread(&mask,1,sizeof(mask),fp) != sizeof(mask) )
                errs++;
            if ( fread(&hash,1,sizeof(hash),fp) != sizeof(hash) )
                errs++;
            //if ( matched != 0 )
            //    komodo_eventadd_utxo(sp,symbol,ht,nid,hash,mask,n);
        }
        else if ( func == 'K' )
        {
            int32_t kheight;
            if ( fread(&kheight,1,sizeof(kheight),fp) != sizeof(kheight) )
                errs++;
            //if ( matched != 0 ) global independent states -> inside *sp
            //printf("%s.%d load[%s] ht.%d\n",ASSETCHAINS_SYMBOL,ht,symbol,kheight);
            komodo_eventadd_kmdheight(sp,symbol,ht,kheight,0);
        }
        else if ( func == 'T' )
        {
            int32_t kheight,ktimestamp;
            if ( fread(&kheight,1,sizeof(kheight),fp) != sizeof(kheight) )
                errs++;
            if ( fread(&ktimestamp,1,sizeof(ktimestamp),fp) != sizeof(ktimestamp) )
                errs++;
            //if ( matched != 0 ) global independent states -> inside *sp
            //printf("%s.%d load[%s] ht.%d t.%u\n",ASSETCHAINS_SYMBOL,ht,symbol,kheight,ktimestamp);
            komodo_eventadd_kmdheight(sp,symbol,ht,kheight,ktimestamp);
        }
        else if ( func == 'R' )
        {
            uint16_t olen,v; uint64_t ovalue; bits256 txid; uint8_t opret[16384];
            if ( fread(&txid,1,sizeof(txid),fp) != sizeof(txid) )
                errs++;
            if ( fread(&v,1,sizeof(v),fp) != sizeof(v) )
                errs++;
            if ( fread(&ovalue,1,sizeof(ovalue),fp) != sizeof(ovalue) )
                errs++;
            if ( fread(&olen,1,sizeof(olen),fp) != sizeof(olen) )
                errs++;
            if ( olen < sizeof(opret) )
            {
                if ( fread(opret,1,olen,fp) != olen )
                    errs++;
                if ( 0 && matched != 0 )
                {
                    int32_t i;  for (i=0; i<olen; i++)
                        printf("%02x",opret[i]);
                    printf(" %s.%d load[%s] opret[%c] len.%d %.8f\n",ASSETCHAINS_SYMBOL,ht,symbol,opret[0],olen,(double)ovalue/SATOSHIDEN);
                }
                komodo_eventadd_opreturn(sp,symbol,ht,txid,ovalue,v,opret,olen); // global shared state -> global PAX
            } else
            {
                int32_t i;
                for (i=0; i<olen; i++)
                    fgetc(fp);
                //printf("illegal olen.%u\n",olen);
            }
        }
        else if ( func == 'D' )
        {
            printf("unexpected function D[%d]\n",ht);
        }
        else if ( func == 'V' )
        {
            int32_t numpvals; uint32_t pvals[128];
            numpvals = fgetc(fp);
            if ( numpvals*sizeof(uint32_t) <= sizeof(pvals) && fread(pvals,sizeof(uint32_t),numpvals,fp) == numpvals )
            {
                //if ( matched != 0 ) global shared state -> global PVALS
                //printf("%s load[%s] prices %d\n",ASSETCHAINS_SYMBOL,symbol,ht);
                //komodo_eventadd_pricefeed(sp,symbol,ht,pvals,numpvals);
                //printf("load pvals ht.%d numpvals.%d\n",ht,numpvals);
            } else printf("error loading pvals[%d]\n",numpvals);
        }
        else printf("[%s] %s illegal func.(%d %c)\n",ASSETCHAINS_SYMBOL,symbol,func,func);
        return(func);
    } else return(-1);
}

void stats_stateupdate(char *destdir,char *statefname,int32_t maxseconds)
{
    static long lastpos;
    char symbol[64],base[64],dest[64]; int32_t n; FILE *fp; uint32_t starttime; struct komodo_state *sp;
    starttime = (uint32_t)time(NULL);
    strcpy(base,"KV");
    strcpy(symbol,"KV");
    strcpy(dest,"KMD");
    sp = &KOMODO_STATE;
    n = 0;
    if ( (fp= fopen(statefname,"rb")) != 0 && sp != 0 )
    {
        fseek(fp,0,SEEK_END);
        if ( ftell(fp) > lastpos )
        {
            fseek(fp,lastpos,SEEK_SET);
            while ( komodo_parsestatefile(sp,fp,symbol,dest) >= 0 && n < 1000 )
            {
                if ( n == 999 )
                {
                    if ( time(NULL) < starttime+maxseconds )
                        n = 0;
                    else break;
                }
                n++;
            }
            lastpos = ftell(fp);
        }
        fclose(fp);
    }
}

char *stats_update(char *destdir,char *statefname)
{
    cJSON *retjson = cJSON_CreateArray();
    stats_stateupdate(destdir,statefname,10);
    return(jprint(retjson,1));
}

int main(int argc, const char * argv[])
{
    FILE *fp; char *filestr,*statefname;
    if ( argc < 2 )
        statefname = "/root/.komodo/KV/komodostate";
    else statefname = (char *)argv[1];
    printf("DEX stats running\n");
    while ( 1 )
    {
        if ( (filestr= stats_update(STATS_DEST,statefname)) != 0 )
        {
            printf("%u: %s\n",(uint32_t)time(NULL),filestr);
            if ( (fp= fopen(STATS_DEST,"wb")) != 0 )
            {
                fwrite(filestr,1,strlen(filestr)+1,fp);
                fclose(fp);
            }
            free(filestr);
        }
        sleep(60);
    }
    return 0;
}
