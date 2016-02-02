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
#include "exchanges777.h"

int32_t Peggy_inds[539] = {289, 404, 50, 490, 59, 208, 87, 508, 366, 288, 13, 38, 159, 440, 120, 480, 361, 104, 534, 195, 300, 362, 489, 108, 143, 220, 131, 244, 133, 473, 315, 439, 210, 456, 219, 352, 153, 444, 397, 491, 286, 479, 519, 384, 126, 369, 155, 427, 373, 360, 135, 297, 256, 506, 322, 425, 501, 251, 75, 18, 420, 537, 443, 438, 407, 145, 173, 78, 340, 240, 422, 160, 329, 32, 127, 128, 415, 495, 372, 522, 60, 238, 129, 364, 471, 140, 171, 215, 378, 292, 432, 526, 252, 389, 459, 350, 233, 408, 433, 51, 423, 19, 62, 115, 211, 22, 247, 197, 530, 7, 492, 5, 53, 318, 313, 283, 169, 464, 224, 282, 514, 385, 228, 175, 494, 237, 446, 105, 150, 338, 346, 510, 6, 348, 89, 63, 536, 442, 414, 209, 216, 227, 380, 72, 319, 259, 305, 334, 236, 103, 400, 176, 267, 355, 429, 134, 257, 527, 111, 287, 386, 15, 392, 535, 405, 23, 447, 399, 291, 112, 74, 36, 435, 434, 330, 520, 335, 201, 478, 17, 162, 483, 33, 130, 436, 395, 93, 298, 498, 511, 66, 487, 218, 65, 309, 419, 48, 214, 377, 409, 462, 139, 349, 4, 513, 497, 394, 170, 307, 241, 185, 454, 29, 367, 465, 194, 398, 301, 229, 212, 477, 303, 39, 524, 451, 116, 532, 30, 344, 85, 186, 202, 517, 531, 515, 230, 331, 466, 147, 426, 234, 304, 64, 100, 416, 336, 199, 383, 200, 166, 258, 95, 188, 246, 136, 90, 68, 45, 312, 354, 184, 314, 518, 326, 401, 269, 217, 512, 81, 88, 272, 14, 413, 328, 393, 198, 226, 381, 161, 474, 353, 337, 294, 295, 302, 505, 137, 207, 249, 46, 98, 27, 458, 482, 262, 253, 71, 25, 0, 40, 525, 122, 341, 107, 80, 165, 243, 168, 250, 375, 151, 503, 124, 52, 343, 371, 206, 178, 528, 232, 424, 163, 273, 191, 149, 493, 177, 144, 193, 388, 1, 412, 265, 457, 255, 475, 223, 41, 430, 76, 102, 132, 96, 97, 316, 472, 213, 263, 3, 317, 324, 274, 396, 486, 254, 205, 285, 101, 21, 279, 58, 467, 271, 92, 538, 516, 235, 332, 117, 500, 529, 113, 445, 390, 358, 79, 34, 488, 245, 83, 509, 203, 476, 496, 347, 280, 12, 84, 485, 323, 452, 10, 146, 391, 293, 86, 94, 523, 299, 91, 164, 363, 402, 110, 321, 181, 138, 192, 469, 351, 276, 308, 277, 428, 182, 260, 55, 152, 157, 382, 121, 507, 225, 61, 431, 31, 106, 327, 154, 16, 49, 499, 73, 70, 449, 460, 187, 24, 248, 311, 275, 158, 387, 125, 67, 284, 35, 463, 190, 179, 266, 376, 221, 42, 26, 290, 357, 268, 43, 167, 99, 374, 242, 156, 239, 403, 339, 183, 320, 180, 306, 379, 441, 20, 481, 141, 77, 484, 69, 410, 502, 172, 417, 118, 461, 261, 47, 333, 450, 296, 453, 368, 359, 437, 421, 264, 504, 281, 270, 114, 278, 56, 406, 448, 411, 521, 418, 470, 123, 455, 148, 356, 468, 109, 204, 533, 365, 8, 345, 174, 370, 28, 57, 11, 2, 231, 310, 196, 119, 82, 325, 44, 342, 37, 189, 142, 222, 9, 54, };

char *peggy_mapname(char *basebuf,char *relbuf,int32_t i) // sorry it is messy thing
{
    char *base,*rel,buf[16];
    base = rel = 0;
    strcpy(buf,peggy_bases[i]);
    base = buf, rel = "BTCD";
    if ( strlen(buf) > 3 && strcmp(buf+strlen(buf)-3,"USD") == 0 )
    {
        if ( strcmp(buf,"BTCUSD") == 0 )
            base = "BTC";
        buf[strlen(buf)-3] = 0;
    }
    else if ( strcmp(buf,"COPPER") == 0 || strcmp(buf,"NGAS") == 0 || strcmp(buf,"UKOIL") == 0 || strcmp(buf,"USOIL") == 0 || strcmp(buf,"US30") == 0 || strcmp(buf,"SPX500") == 0 || strcmp(buf,"NAS100") == 0 )
        rel = "USD";
    else if ( strcmp(buf,"BUND") == 0 )
        rel = "yield";
    else if ( strcmp(buf,"EUSTX50") == 0 )
        rel = "EUR";
    else if ( strcmp(buf,"JPN225") == 0 )
        rel = "JPY";
    else if ( strcmp(buf,"UK100") == 0 )
        rel = "GBP";
    else if ( strcmp(buf,"GER30") == 0 )
        rel = "EUR";
    else if ( strcmp(buf,"SUI30") == 0 )
        rel = "CHF";
    else if ( strcmp(buf,"AUS200") == 0 )
        rel = "AUD";
    else if ( strcmp(buf,"HKG33") == 0 )
        rel = "HKD";
    else if ( strlen(buf) > 3 && strcmp(buf+strlen(buf)-3,"BTC") == 0 )
        base = buf, buf[strlen(buf)-3] = 0;
    if ( i == sizeof(peggy_bases)/sizeof(*peggy_bases)-1 && strcmp(peggy_bases[i],"BTCUSD") == 0 )
        base = "BTC", rel = "USD";
    else if ( i == sizeof(peggy_bases)/sizeof(*peggy_bases)-2 && strcmp(peggy_bases[i],"BTCCNY") == 0 )
        base = "BTC", rel = "CNY";
    else if ( i == sizeof(peggy_bases)/sizeof(*peggy_bases)-3 && strcmp(peggy_bases[i],"BTCRUB") == 0 )
        base = "BTC", rel = "RUB";
    else if ( i == sizeof(peggy_bases)/sizeof(*peggy_bases)-4 && strcmp(peggy_bases[i],"XAUUSD") == 0 )
        base = "XAU", rel = "USD";
    else if ( i == 0 )
        base = "BTCD", rel = "maincurrency peggy, realtime";
    basebuf[0] = relbuf[0] = 0;
    if ( rel != 0 )
        strcpy(relbuf,rel);//, printf("rel.(%s) ",rel);
    if ( base != 0 )
        strcpy(basebuf,base);//, printf("base.(%s) ",base);
    return(basebuf);
}

uint64_t peggy_basebits(char *name)
{
    int32_t i; char basebuf[64],relbuf[64];
    for (i=0; i<64; i++)
    {
        if ( strcmp(name,peggy_bases[i]) == 0 )
        {
            peggy_mapname(basebuf,relbuf,i);
            return(stringbits(basebuf));
        }
    }
    return(0);
}

uint64_t peggy_relbits(char *name)
{
    int32_t i; char basebuf[64],relbuf[64];
    for (i=0; i<64; i++)
    {
        if ( strcmp(name,peggy_bases[i]) == 0 )
        {
            peggy_mapname(basebuf,relbuf,i);
            return(stringbits(relbuf));
        }
    }
    return(0);
}

static uint64_t peggy_assetbits(char *name) { return((is_decimalstr(name) != 0) ? calc_nxt64bits(name) : stringbits(name)); }

int32_t find_uint64(int32_t *emptyslotp,uint64_t *nums,long max,uint64_t val)
{
    int32_t i;
    *emptyslotp = -1;
    for (i=0; i<max; i++)
    {
        if ( nums[i] == 0 )
        {
            *emptyslotp = i;
            break;
        }
        else if ( nums[i] == val )
        {
            if ( Debuglevel > 2 )
                printf("found in slot[%d] %llx\n",i,(long long)val);
            return(i);
        }
    }
    if ( Debuglevel > 2 )
        printf("emptyslot[%d] for %llx\n",i,(long long)val);
    return(-1);
}

int32_t add_uint64(uint64_t *nums,long max,uint64_t val)
{
    int32_t i,emptyslot;
    if ( (i= find_uint64(&emptyslot,nums,max,val)) >= 0 )
        return(i);
    else if ( emptyslot >= 0 )
    {
        nums[emptyslot] = val;
        return(emptyslot);
    } else return(-1);
}

// init time
void peggy_descriptions(struct peggy_info *PEGS,struct peggy_description *P,char *name,char *base,char *rel)
{
    int32_t emptyslot;
    strcpy(P->name,name), strcpy(P->base,base);
    if ( rel != 0 )
        strcpy(P->rel,rel);
    P->assetbits = peggy_assetbits(name), P->basebits = stringbits(base), P->relbits = stringbits(P->rel);
    P->baseid = add_uint64(PEGS->basebits,sizeof(PEGS->basebits)/sizeof(*PEGS->basebits),P->basebits);
    P->relid = add_uint64(PEGS->basebits,sizeof(PEGS->basebits)/sizeof(*PEGS->basebits),P->relbits);
    if ( find_uint64(&emptyslot,PEGS->basebits,sizeof(PEGS->basebits)/sizeof(*PEGS->basebits),P->basebits) != P->baseid )
        printf("(%s) (%s) (%s) error cant find baseid.%d for %llx\n",name,base,P->rel,P->baseid,(long long)P->basebits);
    if ( P->relbits != 0 && find_uint64(&emptyslot,PEGS->basebits,sizeof(PEGS->basebits)/sizeof(*PEGS->basebits),P->relbits) != P->relid )
        printf("(%s) (%s) (%s) error cant find relid.%d for %llx\n",name,base,P->rel,P->relid,(long long)P->relbits);
}

/*int32_t peggy_timeframes(struct peggy_limits *limits,int64_t *scales,uint32_t *timeframes,int32_t numtimeframes,uint64_t maxsupply,uint64_t maxnetbalance)
 {
 int32_t i;
 memset(limits,0,sizeof(*limits));
 limits->maxsupply = maxsupply, limits->maxnetbalance = maxnetbalance;
 if ( limits->maxsupply < 0 || limits->maxnetbalance < 0 )
 {
 printf("peggy_check_limits: maxnetbalance %lld > %d\n",(long long)limits->maxnetbalance,(int32_t)PRICE_RESOLUTION);
 return(-1);
 }
 limits->numtimeframes = (numtimeframes <= MAX_TIMEFRAMES) ? numtimeframes : MAX_TIMEFRAMES;
 for (i=0; i<limits->numtimeframes; i++)
 {
 limits->scales[i] = scales[i];
 if ( (limits->timeframes[i]= PEGGY_DAYTICKS * timeframes[i]) > MAX_TIMEFRAME || (i > 0 && limits->timeframes[i] <= limits->timeframes[i-1]) )
 {
 printf("createpeg: illegal timeframe.%d: %d %d vs %d\n",i,timeframes[i],limits->timeframes[i],MAX_TIMEFRAME);
 getchar(); return(-1);
 }
 }
 limits->timeframes[0] = 0;
 return(0);
 }*/

int32_t peggy_lockparms(struct peggy_lock *dest,int32_t peg,struct peggy_lock *lockparms)
{
    if ( lockparms->minlockdays > lockparms->maxlockdays )
    {
        printf("peggy_check_lockparms: minlockdays %d > %d maxlockdays\n",lockparms->minlockdays,lockparms->maxlockdays);
        return(-1);
	}
    if ( lockparms->mixrange == 0 )
        lockparms->mixrange = PEGGY_MIXRANGE;
    if ( lockparms->extralockdays < PEGGY_MINEXTRADAYS * 2 )
        lockparms->extralockdays = PEGGY_MINEXTRADAYS * 2;
    *dest = *lockparms, dest->peg = peg;
    return(0);
}

int32_t peggy_setvars(struct peggy_info *PEGS,struct peggy *PEG,int16_t baseid,int16_t relid,int32_t peg,uint64_t maxsupply,uint64_t maxnetbalance,struct peggy_lock *lockparms,uint32_t unitincr,int32_t dailyrate,struct price_resolution *initialprices,int32_t numprices,int32_t hasprice)
{
    int32_t i;
    PEG->name.id = peg, PEG->name.hasprice = hasprice;
    //if ( peggy_timeframes(&PEG->limits,limits->scales,limits->timeframes,limits->numtimeframes,limits->maxsupply,limits->maxnetbalance) < 0 )
    //    return(-1);
    if ( peggy_lockparms(&PEG->lockparms,peg,lockparms) < 0 )
        return(-1);
    PEG->unitincr = unitincr;
    PEG->maxdailyrate = dailyrate;
    PEG->maxsupply = maxsupply, PEG->maxnetbalance = maxnetbalance;
    if ( initialprices != 0 )
    {
        if ( numprices > 0 )
        {
            //if ( initialprices[0].Pval >= PRICE_RESOLUTION_MAXPVAL )
            //    initialprices[0].Pval = PRICE_RESOLUTION_MAXPVAL;
            PEG->genesisprice = PEG->dayprice = PEG->price = initialprices[0];
            for (i=0; i<numprices; i++)
                peggy_setprice(PEG,initialprices[i],i);
        }
        else if ( peg != 0 )
            return(-1);
    }
    return(0);
}

struct price_resolution peggy_scaleprice(struct price_resolution price,int64_t peggymils)
{
    price.Pval = (10000 * price.Pval) / peggymils;
    return(price);
}

struct peggy *peggy_createpair(struct peggy_info *PEGS,int64_t quorum,int64_t decisionthreshold,char *name,char *base,char *rel,uint64_t maxsupply,uint64_t maxnetbalance,struct peggy_lock *lockparms,uint32_t unitincr,int32_t maxdailyrate,uint32_t firsttimestamp,struct price_resolution *initialprices,int32_t numprices,struct price_resolution spread,uint16_t maxmargin,struct price_resolution mindenomination,int32_t contractnum,int32_t hasprice,int32_t peggymils)
{
    struct peggy *PEG; char *maincurrency; uint64_t assetbits,mainunitsize; int32_t i;
    maincurrency = PEGS->maincurrency, mainunitsize = PEGS->mainunitsize;
    if ( lockparms == 0 )
        lockparms = &PEGS->default_lockparms;
    //if ( limits == 0 )
    //    limits = &PEGS->default_limits;
    if ( (PEGS->numpegs == 0 && stringbits(base) != PEGS->mainbits) || maxmargin > PEGGY_MARGINMAX )
    {
        printf("peggy_create: numpegs.%d mismatched maincurrency.(%s) || illegal maxmargin.%d vs %d\n",PEGS->numpegs,maincurrency,maxmargin,PEGGY_MARGINMAX);
        return(0);
    }
    if ( firsttimestamp + (numprices-1)*PEGGY_DAYTICKS > time(NULL) )
    {
        printf("peggy_createpair latest price must be in the past: 1st.%u + numprices.%d -> %u vs %u\n",firsttimestamp,numprices,firsttimestamp + (numprices-1)*PEGGY_DAYTICKS,(uint32_t)time(NULL));
        return(0);
    }
    if ( quorum == 0 )
        quorum = PEGS->quorum;
    if ( decisionthreshold == 0 )
        decisionthreshold = PEGS->decisionthreshold;
    assetbits = peggy_assetbits(name);
    if ( PEGS->numpegs > 0 )
    {
        for (i=0; i<PEGS->numpegs; i++)
            if ( PEGS->contracts[i]->name.assetbits == assetbits )
            {
                printf("peggy_create: cant create duplicate peggy.(%s) base.(%s) rel.(%s)\n",name,base,rel);
                return(0);
            }
    }
    if ( hasprice != 0 )
        PEG = &PEGS->pricedpegs[PEGS->numpricedpegs].PEG;
    else PEG = &PEGS->pairedpegs[PEGS->numpairedpegs];
    memset(PEG,0,sizeof(*PEG));
    peggy_descriptions(PEGS,&PEG->name,name,base,rel);
    PEG->pool.quorum = (quorum != 0) ? quorum : PEGS->quorum, PEG->pool.decisionthreshold = (decisionthreshold != 0) ? decisionthreshold : PEGS->decisionthreshold;
    PEG->pool.mainunitsize = PEGS->mainunitsize, PEG->pool.mainbits = PEGS->mainbits;
    PEG->genesistime = firsttimestamp, PEG->name.id = PEGS->numpegs;
    PEG->spread = spread, PEG->lockparms.margin = maxmargin, PEG->mindenomination = mindenomination;
    if ( hasprice == 0 )
        PEG->baseprices = PEGS->pricedpegs[PEG->name.baseid].prices, PEG->relprices = PEGS->pricedpegs[PEG->name.relid].prices;
    else PEG->baseprices = PEGS->pricedpegs[PEG->name.id].prices, PEG->relprices = 0;
    if ( peggy_setvars(PEGS,PEG,PEG->name.baseid,PEG->name.relid,PEGS->numpegs,maxsupply,maxnetbalance,lockparms,unitincr,maxdailyrate,initialprices,numprices,hasprice) < 0 )
    {
        printf("peggy_create: error init peggy.(%s) base.(%s) rel.(%s)\n",name,base,rel);
        return(0);
    }
    //printf("PEG.%p num.%d priced.%d paired.%d\n",PEG,PEGS->numpegs,PEGS->numpricedpegs,PEGS->numpairedpegs);
    if ( hasprice != 0 )
        PEGS->numpricedpegs++;
    else PEGS->numpairedpegs++;
    PEGS->contracts[PEGS->numpegs++] = PEG;
    PEG->peggymils = peggymils;
    PEG->name.enabled = 1;
    return(PEG);
}

struct peggy_info *peggy_init(char *path,int32_t maxdays,char *maincurrency,uint64_t maincurrencyunitsize,uint64_t quorum,uint64_t decisionthreshold,struct price_resolution spread,uint32_t dailyrate,int32_t interesttenths,int32_t posboost,int32_t negpenalty,int32_t feediv,int32_t feemult,uint32_t firsttimestamp,uint32_t BTCD_price0)
{
    //struct peggy_limits limits = { { PERCENTAGE(10), PERCENTAGE(25), PERCENTAGE(33), PERCENTAGE(50) }, SATOSHIDEN * 10000, SATOSHIDEN * 1000, { 0, 30, 90, 180 }, 4 };
    struct peggy_lock default_lockparms = { 7, 365, 7, 0, 180, 0, -1 };
    struct price_resolution mindenom,price; struct peggy_info *PEGS = calloc(1,sizeof(*PEGS));
    //if ( default_limits != 0 )
    //    limits = *default_limits;
    spread.Pval = PERCENTAGE(1);
    OS_ensure_directory(path);
    strcpy(PEGS->maincurrency,maincurrency);
    PEGS->mainbits = stringbits(maincurrency), PEGS->mainunitsize = maincurrencyunitsize, PEGS->quorum = quorum, PEGS->decisionthreshold = decisionthreshold;
    PEGS->default_lockparms = default_lockparms, PEGS->default_lockparms.maxlockdays = maxdays;
    //PEGS->default_limits = limits,
    PEGS->default_spread = spread, PEGS->default_dailyrate = dailyrate;
    PEGS->interesttenths = interesttenths, PEGS->posboost = posboost, PEGS->negpenalty = negpenalty, PEGS->feediv = feediv, PEGS->feemult = feemult;
    mindenom.Pval = PRICE_RESOLUTION;
    PEGS->genesistime = firsttimestamp;
    price.Pval = PEGS->BTCD_price0 = BTCD_price0;
    printf("set genesistime.%u BTCD0.%u\n",firsttimestamp,BTCD_price0);
    peggy_createpair(PEGS,0,0,"BTCD","BTCD",0,SATOSHIDEN*1000000,SATOSHIDEN*100000,0,SATOSHIDEN,PEGGY_RATE_777,firsttimestamp,&price,1,spread,0,mindenom,0,1,peggy_mils(0));
    //PEGS->accts = accts777_init(path,0);
    return(PEGS);
}
//////////// end of consensus safe

long hdecode_varint(uint64_t *valp,uint8_t *ptr,long offset,long mappedsize)
{
    uint16_t s; uint32_t i; int32_t c;
    if ( ptr == 0 )
        return(-1);
    *valp = 0;
    if ( offset < 0 || offset >= mappedsize )
        return(-1);
    c = ptr[offset++];
    switch ( c )
    {
        case 0xfd: if ( offset+sizeof(s) > mappedsize ) return(-1); memcpy(&s,&ptr[offset],sizeof(s)), *valp = s, offset += sizeof(s); break;
        case 0xfe: if ( offset+sizeof(i) > mappedsize ) return(-1); memcpy(&i,&ptr[offset],sizeof(i)), *valp = i, offset += sizeof(i); break;
        case 0xff: if ( offset+sizeof(*valp) > mappedsize ) return(-1); memcpy(valp,&ptr[offset],sizeof(*valp)), offset += sizeof(*valp); break;
        default: *valp = c; break;
    }
    return(offset);
}

struct peggy_info *peggy_genesis(int32_t lookbacks[OPRETURNS_CONTEXTS],struct peggy_info *PEGS,char *path,uint32_t firsttimestamp,char *opreturnstr)
{
    //struct peggy_limits limits = { { PERCENTAGE(10), PERCENTAGE(25), PERCENTAGE(33), PERCENTAGE(50) }, SATOSHIDEN * 10000, SATOSHIDEN * 1000, { 0, 30, 90, 180 }, 4 };
    char name[64],base[64],rel[64]; uint8_t opret[1024]; struct peggy_tx Ptx; struct peggy *PEG;
    struct price_resolution mindenom,spread,price; uint64_t len; long offset; uint64_t maxsupply=0,maxnetbalance=0;
    int32_t i,c,baseid,relid,peggymils=0,signedcount,datalen,n=0,maxmargin=0,numprices,err=-1; uint32_t pval = 0;
    numprices = 1;
    datalen = (int32_t)strlen(opreturnstr) / 2;
    decode_hex(opret,datalen,opreturnstr);
    printf("peggy_genesis(%s)\n",opreturnstr);
    if ( opret[0] == OP_RETURN_OPCODE )
    {
        offset = hdecode_varint(&len,opret,1,sizeof(opret));
        if ( opret[offset] == 'P' && opret[offset+1] == 'A' && opret[offset+2] == 'X' )
        {
            printf("deser\n");
            if ( (n= serdes777_deserialize(&signedcount,&Ptx,firsttimestamp,opret+offset+3,(int32_t)len-3)) > 0 )
            {
                err = 0;
                for (i=0; i<Ptx.details.price.num; i++)
                    if ( Ptx.details.price.feed[i] == 0 )
                        break;
                if ( i == Ptx.details.price.num )
                {
                    printf("GENESIS.(%s)\n",opreturnstr);
                    for (i=0; i<Ptx.details.price.num; i++)
                        printf("%u ",Ptx.details.price.feed[i]);
                    printf("prices\n");
                    lookbacks[0] = 0, lookbacks[1] = 1000;
                    if ( PEGS == 0 )
                    {
                        spread.Pval = PERCENTAGE(1);
                        PEGS = peggy_init(path,PEGGY_MAXLOCKDAYS,"BTCD",SATOSHIDEN/100,1,1,spread,PEGGY_RATE_777,40,10,2,5,2,Ptx.timestamp,Ptx.details.price.feed[0]);
                        //EGS->accts = accts777_init(path,0);
                        PEGS->genesis = opreturnstr, opreturnstr = 0;
                    }
                } else printf("i.%d vs %d\n",i,Ptx.details.price.num);
            } else printf("deser got n.%d\n",n);
        } else printf("illegal opret.(%c%c%c)\n",opret[offset],opret[offset+1],opret[offset+2]);
    } else printf("opret[0] %d\n",opret[0]);
    if ( err < 0 || PEGS == 0 )
        return(0);
    mindenom.Pval = PRICE_RESOLUTION;
    spread.Pval = PERCENTAGE(1);
    for (i=1; i<sizeof(peggy_bases)/sizeof(*peggy_bases)+28; i++)
    {
        price.Pval = 0;
        if ( i < sizeof(peggy_bases)/sizeof(*peggy_bases) )
        {
            if ( peggy_bases[i] == 0 )
                continue;
            peggy_mapname(base,rel,i);
            price.Pval = Ptx.details.price.feed[i];
            if ( i <= 8 )
                maxmargin = 25;
            else if ( i < 16 )
                maxmargin = 15;
            else maxmargin = 10;
            peggymils = peggy_mils(i);
            if ( (mindenom.Pval= ((double)PRICE_RESOLUTION * peggymils) / 10000.) == 0 )
                mindenom.Pval = PRICE_RESOLUTION;
            strcpy(name,base);
            if ( strcmp(rel,"BTCD") != 0 && is_decimalstr(base+strlen(base)-2) == 0 && strncmp(rel,"yield",5) != 0 && strcmp(base,"Copper") != 0 && strcmp(base,"NGAS") != 0 && strcmp(base,"UKOil") != 0 && strcmp(base,"USOil") != 0  )
                strcat(name,rel);
            maxsupply = SATOSHIDEN * 10000, maxnetbalance = SATOSHIDEN * 1000;
            if ( strcmp(base,"BTC") == 0 || strcmp(base,"NXT") == 0 || strcmp(base,"USD") == 0 || strcmp(base,"CNY") == 0 )
                maxsupply *= 10, maxnetbalance *= 10;
            price.Pval = Ptx.details.price.feed[i];
            peggy_mapname(base,rel,i);
            pval = Ptx.details.price.feed[i];
        }
        else if ( i-sizeof(peggy_bases)/sizeof(*peggy_bases) < PEGGY_MAXPAIREDPEGS )
        {
            extern short Contract_base[],Contract_rel[];
            maxsupply = SATOSHIDEN * 10000, maxnetbalance = SATOSHIDEN * 1000;
            mindenom.Pval = PRICE_RESOLUTION * 10;
            c = i - (int32_t)(sizeof(peggy_bases)/sizeof(*peggy_bases));
            strcpy(base,CURRENCIES[Contract_base[c]]), strcpy(rel,CURRENCIES[Contract_rel[c]]);
            strcpy(name,base), strcat(name,rel);
            baseid = Contract_base[c]+1, relid = Contract_rel[c]+1;
            peggymils = (PEGS->contracts[baseid]->peggymils * 10000) / PEGS->contracts[relid]->peggymils;
            if ( strcmp(PEGS->contracts[baseid]->name.base,base) == 0 && strcmp(PEGS->contracts[relid]->name.base,rel) == 0 )
                price.Pval = (PRICE_RESOLUTION * Ptx.details.price.feed[baseid]) / Ptx.details.price.feed[relid];
            else printf("mismatched %p base.(%s) baseid.%d (%s) or %p rel.(%s) relid.%d (%s)\n",PEGS->contracts[baseid],PEGS->contracts[baseid]->name.base,baseid,base,PEGS->contracts[relid],PEGS->contracts[relid]->name.base,relid,rel);
            pval = (uint32_t)price.Pval;
        } else printf("peggy_genesis RAN out of space\n");
        if ( (PEG= peggy_createpair(PEGS,0,0,name,base,rel,maxsupply,maxnetbalance,0,SATOSHIDEN*10,PEGGY_RATE_777,firsttimestamp,&price,numprices,spread,maxmargin,mindenom,i,i<sizeof(peggy_bases)/sizeof(*peggy_bases),peggymils)) != 0 )
        {
            price = peggy_scaleprice(price,peggymils);
            struct price_resolution x = peggy_price(PEG,0);
            printf("%9s.(%-8s %5s) %17.10f %.10f %-10d maxmargin %2dx maxsupply %6.0f BTCD maxdiff %7.0f spread %.3f denom %-10.6f mils.%d\n",PEG->name.name,PEG->name.base,PEG->name.rel,Pval(&price),Pval(&x),pval,maxmargin,dstr(maxsupply),dstr(maxnetbalance),Pval(&spread),Pval(&mindenom),PEG->peggymils);
            n++;
        }
    }
    printf("genesis prices t%u vs %u\n",Ptx.timestamp,firsttimestamp);
    return(PEGS);
}

char *peggybase(uint32_t blocknum,uint32_t blocktimestamp)
{
    int32_t nonz; struct peggy_info *PEGS = opreturns_context("peggy",0);
    if ( PEGS != 0 )
        return(peggy_emitprices(&nonz,PEGS,blocktimestamp,PEGS->genesis != 0 ? 0 : PEGGY_MAXLOCKDAYS));
    return(0);
}

char *peggypayments(uint32_t blocknum,uint32_t blocktimestamp)
{
    int32_t peggy_payments(queue_t *PaymentsQ,struct opreturn_payment *payments,int32_t max,uint32_t currentblocknum,uint32_t blocknum,uint32_t blocktimestamp);
    struct opreturn_payment payments[8192]; cJSON *json;
    int32_t i,n; struct peggy_info *PEGS = opreturns_context("peggy",0);
    memset(payments,0,sizeof(payments));
    if ( PEGS != 0 && PEGS->accts != 0 && (n= peggy_payments(&PEGS->accts->PaymentsQ,payments,sizeof(payments)/sizeof(*payments),blocknum,blocknum,blocktimestamp)) > 0 )
    {
        json = cJSON_CreateObject();
        for (i=0; i<n; i++)
            jaddnum(json,payments[i].coinaddr,payments[i].value);
        return(jprint(json,1));
    }
    return(clonestr("{}"));
}

int32_t peggyblock(char *jsonstr)
{
    printf("got peggyblock.(%s)\n",jsonstr);
    return(0);
}

void peggy()
{
    int32_t lookbacks[OPRETURNS_CONTEXTS],nonz,num,peggylen; uint32_t timestamp;// = (uint32_t)time(0);
    FILE *fp; uint8_t opret[8192]; char fname[512],*opreturnstr; struct peggy_info *PEGS = opreturns_context("peggy",0);
    if ( 0 && PEGS != 0 )
    {
        opreturnstr = peggy_emitprices(&nonz,PEGS,timestamp,PEGS->genesis != 0 ? 0 : PEGGY_MAXLOCKDAYS);
        if ( opreturnstr != 0 )
        {
            printf("OPRETURN.(%s)\n",opreturnstr);
            //if ( Debuglevel > 2 )
                printf("update.%d opreturns.(%s) t%u\n",PEGS->numopreturns,opreturnstr,timestamp);
            sprintf(fname,"opreturns/%d",PEGS->numopreturns);
            if ( (fp= fopen(fname,"wb")) != 0 )
            {
                fwrite(opreturnstr,1,strlen(opreturnstr)+1,fp);
                fclose(fp);
            }
            if ( nonz == 64 && PEGS->genesis == 0 )
                peggy_genesis(lookbacks,PEGS,PEGS->path,timestamp,opreturnstr);
            else
            {
                num = 1;
                peggylen = (int32_t)strlen(opreturnstr) / 2;
                decode_hex(opret,peggylen,opreturnstr);
                opreturns_process(1,PEGS->numopreturns,PEGS->numopreturns,timestamp,0,0,opret,peggylen);
                free(opreturnstr);
                PEGS->numopreturns++;
            }
        }
    }
}

uint64_t map_apr(uint64_t *spreadp,int32_t maxdays,double apr)
{
    int64_t bestdiff,diff; int32_t i; uint64_t rate,bestsatoshis,satoshis,bestrate = 0,target;
    target = PRICE_RESOLUTION * (1. + apr/100.);
    bestrate = ((PRICE_RESOLUTION * log(apr)/10) / (365-1));
    satoshis = peggy_compound(0,PRICE_RESOLUTION,bestrate,365);
    bestdiff = (satoshis - target);
    if ( bestdiff < 0 )
        bestdiff = -bestdiff;
    //err = ((double)bestdiff / target);
    //n = (int32_t)(err * 4. * bestrate);
    //if ( n < 1000 )
    //    n = 1000;
    //printf("err %f %d: new bestdiff %llu, bestrate %llu, satoshis %.8f target %.8f\n",err,n,(long long)bestdiff,(long long)bestrate,(double)satoshis/PRICE_RESOLUTION,(double)target/PRICE_RESOLUTION);
    //for (i=0,rate=bestrate-n; rate<=bestrate+2*n; rate++,i++)
    for (i=0,rate=1; rate<PRICE_RESOLUTION/100; rate++,i++)
    {
        satoshis = peggy_compound(0,PRICE_RESOLUTION,rate,365);
        diff = (satoshis - target);
        if ( diff < 0 )
            diff = -diff;
        if ( diff < bestdiff )
        {
            //printf("i.%d of %d: new bestdiff %llu -> %llu, rate %llu -> %llu, satoshis %.8f target %.8f\n",i,n,(long long)bestdiff,(long long)diff,(long long)bestrate,(long long)rate,(double)satoshis/PRICE_RESOLUTION,(double)target/PRICE_RESOLUTION);
            bestdiff = diff, bestrate = rate, bestsatoshis = satoshis;
            if ( diff == 0 )
                break;
        }
    }
    //printf("\nnew bestdiff %llu rate %llu, satoshis %.8f target %.8f\n",(long long)bestdiff,(long long)bestrate,(double)bestsatoshis/PRICE_RESOLUTION,(double)target/PRICE_RESOLUTION);
    *spreadp = PERCENTAGE((apr * maxdays)/365);
    return(bestrate);
}

uint64_t peggy_dailyrates()
{
    //struct peggy_limits limits = { { PERCENTAGE(10), PERCENTAGE(25), PERCENTAGE(33), PERCENTAGE(50) }, SATOSHIDEN * 10000, SATOSHIDEN * 1000, { 0, 30, 90, 180 }, 4 };
    uint64_t satoshis,maxspread; int64_t err,errsum; int32_t i,milliperc;
    dailyrates[0] = (int32_t)map_apr(&maxspread,PEGGY_MAXLOCKDAYS,(double)7770/1000);
    satoshis = peggy_compound(0,SATOSHIDEN,dailyrates[0],365);
    printf("%.2f%% %d %llu -> %llu %.2f%%\n",(double)7770/1000,dailyrates[0],(long long)SATOSHIDEN,(long long)satoshis,100. * ((double)(satoshis-SATOSHIDEN)/SATOSHIDEN));
    for (errsum=i=0; i<=100; i++)
    {
        satoshis = peggy_compound(0,SATOSHIDEN,dailyrates[i],365);
        //printf("%.1f%%: %d %llu -> %llu %.3f%%\n",(double)i*.1,dailyrates[i],(long long)PRICE_RESOLUTION,(long long)satoshis,100. * (double)satoshis/PRICE_RESOLUTION - 100.);
        printf("%.2f%% ",100. * (double)satoshis/SATOSHIDEN - 100.);
        err = (satoshis - SATOSHIDEN) - (i == 0 ? 7770000 : i*100000);
        errsum += err < 0 ? -err : err;
        //printf("i.%d err %lld sum %lld\n",i,(long long)err,(long long)errsum);
    }
    errsum /= 101;
    printf("dailyrate check errsum %lld %f%% ave err\n",(long long)errsum,100*dstr(errsum));
    if ( errsum > 10000 )
    {
        //int32_t dailyrates[101];
        for (milliperc=100; milliperc<=10000; milliperc+=100)
        {
            dailyrates[milliperc/100] = (int32_t)map_apr(&maxspread,PEGGY_MAXLOCKDAYS,(double)milliperc/1000);
            satoshis = peggy_compound(0,SATOSHIDEN,dailyrates[milliperc/100],365);
            printf("%.2f%% %d %llu -> %llu %.3f%%\n",(double)milliperc/1000,dailyrates[milliperc/100],(long long)SATOSHIDEN,(long long)satoshis,100. * ((double)(satoshis-SATOSHIDEN)/SATOSHIDEN));
        }
        for (i=0; i<=100; i++)
            printf("%d, ",dailyrates[i]);
        printf("dailyrates in 0.1%% incr\n");
        printf("root.%lld resolution.%lld squared.%llu maxPval.%llu maxunits.%d\n",(long long)PRICE_RESOLUTION_ROOT,(long long)PRICE_RESOLUTION,(long long)PRICE_RESOLUTION2,(long long)PRICE_RESOLUTION_MAXPVAL,PRICE_RESOLUTION_MAXUNITS);
    }
    return(errsum);
}

void *peggy_replay(char *path,struct txinds777_info *opreturns,void *_PEGS,uint32_t blocknum,char *opreturnstr,uint8_t *data,int32_t datalen)
{
    int32_t lookbacks[OPRETURNS_CONTEXTS]; long allocsize; uint64_t len; int32_t n,signedcount,valid=0;
    long offset; struct price_resolution tmp;
    char fname[512]; uint8_t opret[8192]; struct peggy_tx Ptx; struct peggy_info *PEGS = _PEGS;
    if ( blocknum == 0 )
        opreturnstr = PEGGY_GENESIS;
    //printf("replay genesis.%p opreturnstr.%p data.%p\n",PEGGY_GENESIS,opreturnstr,data);
    if ( data == 0 )
    {
        data = opret;
        if ( opreturnstr == 0 )
        {
            sprintf(fname,"%s/%d",path,blocknum);
            if ( (opreturnstr= OS_filestr(&allocsize,fname)) != 0 )
            {
                //printf("loaded.(%s) %s\n",fname,opreturnstr);
                if ( is_hexstr(opreturnstr,(int32_t)strlen(opreturnstr)) != 0 )
                    valid = 1;
            } //else printf("couldnt find.(%s)\n",fname);
        } else valid = 1;
        if ( valid != 0 )
        {
            datalen = (int32_t)strlen(opreturnstr) / 2;
            decode_hex(opret,datalen,opreturnstr);
        } else return(0);
    }
    if ( data != 0 && data[0] == OP_RETURN_OPCODE )
    {
        offset = hdecode_varint(&len,data,1,sizeof(opret));
        if ( data[offset] == 'P' && data[offset+1] == 'A' && data[offset+2] == 'X' )
        {
            if ( (n= serdes777_deserialize(&signedcount,&Ptx,0,&data[offset+3],(int32_t)(len - 3))) < 0 )
                printf("peggy_process.%d peggy_deserialize error datalen.%d t%d\n",blocknum,datalen,Ptx.timestamp);
            else
            {
                int32_t j,nonz = 0;
                for (j=0; j<Ptx.details.price.num; j++)
                {
                    if ( Ptx.details.price.feed[j] != 0 )
                    {
                        tmp.Pval = Ptx.details.price.feed[j];
                        tmp = peggy_scaleprice(tmp,peggy_mils(j));
                        nonz++;
                        fprintf(stderr,"(%s %u %.6f) ",peggy_bases[j],Ptx.details.price.feed[j],Pval(&tmp));
                    }
                }
                //fprintf(stderr,"%d ",nonz);
                printf("PEGS.%p PEGGY type.%d %u num.%d nonz.%d\n",PEGS,Ptx.txtype,Ptx.timestamp,Ptx.details.price.num,nonz);
                if ( PEGS == 0 && nonz == Ptx.details.price.num )
                    PEGS = peggy_genesis(lookbacks,PEGS,path,Ptx.timestamp,opreturnstr);
                else if ( PEGS != 0 && Ptx.timestamp > PEGS->genesistime )
                {
                    Ptx.flags |= PEGGY_FLAGS_PEGGYBASE;
                    if ( peggy_process(PEGS,1,&Ptx.funding.src.coinaddr,Ptx.funding.amount,&data[offset+3],(int32_t)len-3,blocknum,Ptx.timestamp,blocknum) < 0 )
                    {
                        printf("error processing blocknum.%u Ptx.blocknum %u\n",blocknum,blocknum);
                    }
                }
                if ( PEGS != 0 )
                    PEGS->numopreturns++;
            }
        } else printf("illegal.(%c%c%c)\n",data[offset],data[offset+1],data[offset+2]);
    } else printf("missing OP_RETURN_OPCODE [%02x]\n",data[0]);
    return(PEGS);
}

uint32_t peggy_currentblock(void *_PEGS) { struct peggy_info *PEGS; if ( (PEGS= _PEGS) != 0 ) return(PEGS->numopreturns); return(0); }

void peggy_geninds()
{
    int32_t inds[PEGGY_NUMCOEFFS],tmp,i,n = PEGGY_NUMCOEFFS;
    for (i=0; i<n; i++)
        inds[i] = i;
    printf("int32_t Peggy_inds[%d] = {",PEGGY_NUMCOEFFS);
    while ( n > 0 )
    {
        i = ((rand() >> 8) % n);
        //printf("(n.%d [%d] i.%d [%d]) ",n,inds[n],i,inds[i]);
        n--;
        tmp = inds[n];
        inds[n] = inds[i];
        inds[i] = tmp;
    }
    for (i=0; i<PEGGY_NUMCOEFFS; i++)
        printf("%d, ",inds[i]);
    printf("};\n");
}

struct peggy_info *peggy_lchain(struct txinds777_info *opreturns,char *path)
{
    double startmilli; int32_t i; struct peggy_info *tmp,*PEGS = 0;
    startmilli = OS_milliseconds();
    printf("about to replay\n");
    for (i=0; i<1000000; i++)
    {
        if ( PEGS == 0 && (PEGS= peggy_replay(path,opreturns,PEGS,0,0,0,0)) == 0 )
            break;
        else if ( (tmp= peggy_replay(path,opreturns,PEGS,i,0,0,0)) != PEGS )
            break;
    }
    if ( PEGS != 0 )
        printf("loaded %d in %.3f millis per opreturn\n",PEGS->numopreturns,(OS_milliseconds() - startmilli)/PEGS->numopreturns);// getchar();
    return(PEGS);
}

int32_t peggy_init_contexts(struct txinds777_info *opreturns,uint32_t RTblocknum,uint32_t RTblocktimestamp,char *path,void *globals[OPRETURNS_CONTEXTS],int32_t lookbacks[OPRETURNS_CONTEXTS],int32_t maxcontexts)
{
    double startmilli; char buf[512]; struct price_resolution spread; struct peggy_info *PEGS=0,*PEGS2=0;
    if ( maxcontexts != 2 )
    {
        printf("peggy needs 2 contexts\n");
        exit(-1);
    }
    calc_smooth_code(127,7);
    if ( sizeof(Peggy_inds)/sizeof(*Peggy_inds) != PEGGY_NUMCOEFFS )
    {
        peggy_geninds();
        printf("need to update Peggy_inds with above\n");
        exit(-1);
    }
    peggy_dailyrates();
    spread.Pval = PERCENTAGE(1);
    //if ( (PEGS= peggy_lchain(opreturns,"opreturns")) == 0 )
        PEGS = peggy_init(path,PEGGY_MAXLOCKDAYS,"BTCD",SATOSHIDEN/100,100,10,spread,PEGGY_RATE_777,40,10,2,5,2,0,0);
    globals[0] = PEGS;
    sprintf(buf,"%s_PERM",path);
    globals[1] = PEGS2 = peggy_init(buf,PEGGY_MAXLOCKDAYS,"BTCD",SATOSHIDEN/100,1,1,spread,PEGGY_RATE_777,40,10,2,5,2,PEGS->genesistime,PEGS->BTCD_price0);
    startmilli = OS_milliseconds();
    peggy_clone(buf,PEGS2,PEGS);
    printf("cloned %d in %.3f millis per opreturn\n",PEGS->numopreturns,(OS_milliseconds() - startmilli)/PEGS->numopreturns); sleep(3);
    return(2);
}
