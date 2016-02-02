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

uint64_t peggy_smooth_coeffs[PEGGY_NUMCOEFFS] =	// numprimes.13
{
    962714545, 962506087, 962158759, 961672710, 961048151, 960285354, 959384649, 958346426, 957171134, // x.8
    955859283, 954411438, 952828225, 951110328, 949258485, 947273493, 945156207, 942907532, 940528434, // x.17
    938019929, 935383089, 932619036, 929728945, 926714044, 923575608, 920314964, 916933485, 913432593, // x.26
    909813756, 906078486, 902228342, 898264923, 894189872, 890004874, 885711650, 881311964, 876807614, // x.35
    872200436, 867492300, 862685110, 857780804, 852781347, 847688737, 842505000, 837232189, 831872382, // x.44
    826427681, 820900212, 815292123, 809605581, 803842772, 798005901, 792097186, 786118864, 780073180, // x.53
    773962395, 767788778, 761554609, 755262175, 748913768, 742511686, 736058231, 729555707, 723006417, // x.62
    716412665, 709776755, 703100984, 696387648, 689639036, 682857428, 676045100, 669204315, 662337327, // x.71
    655446378, 648533696, 641601496, 634651978, 627687325, 620709702, 613721256, 606724115, 599720386, // x.80
    592712154, 585701482, 578690411, 571680955, 564675105, 557674825, 550682053, 543698699, 536726645, // x.89
    529767743, 522823816, 515896658, 508988029, 502099660, 495233249, 488390461, 481572928, 474782249, // x.98
    468019988, 461287675, 454586804, 447918836, 441285195, 434687268, 428126409, 421603932, 415121117, // x.107
    408679208, 402279408, 395922888, 389610779, 383344175, 377124134, 370951677, 364827785, 358753406, // x.116
    352729449, 346756785, 340836251, 334968645, 329154729, 323395230, 317690838, 312042206, 306449955, // x.125
    300914667, 295436891, 290017141, 284655897, 279353604, 274110676, 268927490, 263804394, 258741701, // x.134
    253739694, 248798623, 243918709, 239100140, 234343077, 229647649, 225013957, 220442073, 215932043, // x.143
    211483883, 207097585, 202773112, 198510404, 194309373, 190169909, 186091877, 182075118, 178119452, // x.152
    174224676, 170390565, 166616873, 162903335, 159249664, 155655556, 152120688, 148644718, 145227287, // x.161
    141868021, 138566528, 135322401, 132135218, 129004542, 125929924, 122910901, 119946997, 117037723, // x.170
    114182582, 111381062, 108632643, 105936795, 103292978, 100700645, 98159238, 95668194, 93226942, // x.179
    90834903, 88491495, 86196126, 83948203, 81747126, 79592292, 77483092, 75418916, 73399150, // x.188
    71423178, 69490383, 67600142, 65751837, 63944844, 62178541, 60452305, 58765515, 57117547, // x.197
    55507781, 53935597, 52400377, 50901505, 49438366, 48010349, 46616844, 45257246, 43930951, // x.206
    42637360, 41375878, 40145912, 38946876, 37778185, 36639262, 35529533, 34448428, 33395384, // x.215
    32369842, 31371249, 30399057, 29452725, 28531717, 27635503, 26763558, 25915365, 25090413, // x.224
    24288196, 23508216, 22749980, 22013003, 21296806, 20600917, 19924870, 19268206, 18630475, // x.233
    18011231, 17410035, 16826458, 16260073, 15710466, 15177224, 14659944, 14158231, 13671694, // x.242
    13199950, 12742625, 12299348, 11869759, 11453500, 11050225, 10659590, 10281262, 9914910, // x.251
    9560213, 9216856, 8884529, 8562931, 8251764, 7950739, 7659571, 7377984, 7105706, // x.260
    6842471, 6588020, 6342099, 6104460, 5874861, 5653066, 5438844, 5231969, 5032221, // x.269
    4839386, 4653254, 4473620, 4300287, 4133059, 3971747, 3816167, 3666139, 3521488, // x.278
    3382043, 3247640, 3118115, 2993313, 2873079, 2757266, 2645728, 2538325, 2434919, // x.287
    2335380, 2239575, 2147382, 2058677, 1973342, 1891262, 1812325, 1736424, 1663453, // x.296
    1593311, 1525898, 1461118, 1398879, 1339091, 1281666, 1226519, 1173569, 1122736, // x.305
    1073944, 1027117, 982185, 939076, 897725, 858065, 820033, 783568, 748612, // x.314
    715108, 682999, 652233, 622759, 594527, 567488, 541597, 516808, 493079, // x.323
    470368, 448635, 427841, 407948, 388921, 370725, 353326, 336692, 320792, // x.332
    305596, 291075, 277202, 263950, 251292, 239204, 227663, 216646, 206130, // x.341
    196094, 186517, 177381, 168667, 160356, 152430, 144874, 137671, 130806, // x.350
    124264, 118031, 112093, 106437, 101050, 95921, 91039, 86391, 81968, // x.359
    77759, 73755, 69945, 66322, 62877, 59602, 56488, 53528, 50716, // x.368
    48043, 45505, 43093, 40803, 38629, 36564, 34604, 32745, 30980, // x.377
    29305, 27717, 26211, 24782, 23428, 22144, 20927, 19774, 18681, // x.386
    17646, 16665, 15737, 14857, 14025, 13237, 12491, 11786, 11118, // x.395
    10487, 9890, 9325, 8791, 8287, 7810, 7359, 6933, 6531, // x.404
    6151, 5792, 5453, 5133, 4831, 4547, 4278, 4024, 3785, // x.413
    3560, 3347, 3147, 2958, 2779, 2612, 2454, 2305, 2164, // x.422
    2032, 1908, 1791, 1681, 1577, 1480, 1388, 1302, 1221, // x.431
    1145, 1073, 1006, 942, 883, 827, 775, 725, 679, // x.440
    636, 595, 557, 521, 487, 456, 426, 399, 373, // x.449
    348, 325, 304, 284, 265, 248, 231, 216, 202, // x.458
    188, 175, 164, 153, 142, 133, 124, 115, 107, // x.467
    100, 93, 87, 81, 75, 70, 65, 61, 56, // x.476
    53, 49, 45, 42, 39, 36, 34, 31, 29, // x.485
    27, 25, 23, 22, 20, 19, 17, 16, 15, // x.494
    14, 13, 12, 11, 10, 9, 9, 8, 7, // x.503
    7, 6, 6, 5, 5, 5, 4, 4, 4, // x.512
    3, 3, 3, 3, 2, 2, 2, 2, 2, // x.521
    2, 2, 1, 1, 1, 1, 1, 1, 1, // x.530
    1, 1, 1, 1, 1, 1, 0, 0, // isum 100000000000
};

int32_t dailyrates[101] =
{
    0, 27, 55, 82, 110, 137, 164, 192, 219, 246, 273, 300, 327, 355, 382, 409, 436, 463, 489, 516, 543, 570, 597, 624, 651, 677, 704, 731, 757, 784, 811, 837, 864, 890, 917, 943, 970, 996, 1023, 1049, 1076, 1102, 1128, 1155, 1181, 1207, 1233, 1259, 1286, 1312, 1338, 1364, 1390, 1416, 1442, 1468, 1494, 1520, 1546, 1572, 1598, 1624, 1649, 1675, 1701, 1727, 1752, 1778, 1804, 1830, 1855, 1881, 1906, 1932, 1957, 1983, 2008, 2034, 2059, 2085, 2110, 2136, 2161, 2186, 2212, 2237, 2262, 2287, 2313, 2338, 2363, 2388, 2413, 2438, 2463, 2488, 2513, 2538, 2563, 2588, 2613
};

int32_t peggy_setprice(struct peggy *PEG,struct price_resolution price,int32_t minute)
{
    if ( PEG->name.hasprice != 0 )
    {
        if ( price.Pval > PRICE_RESOLUTION_MAXPVAL )
        {
            printf("peggy_setdayprice clip.%lld with %lld\n",(long long)price.Pval,(long long)PRICE_RESOLUTION_MAXPVAL);
            price.Pval = PRICE_RESOLUTION_MAXPVAL;
        }
        else if ( price.Pval <= 0 )
        {
            printf("peggy_setdayprice illegal negative of zeroprice %lld %s\n",(long long)price.Pval,PEG->name.name);
            price.Pval = 0;
        }
        if ( PEG->baseprices[minute] != 0 )
            price.Pval = (uint32_t)(price.Pval + PEG->baseprices[minute]) >> 1;
        else if ( minute > PEG->RTminute )
            PEG->RTminute = minute;
        PEG->baseprices[minute] = (uint32_t)price.Pval;
        while ( --minute > 0 && PEG->baseprices[minute] == 0 )
            PEG->baseprices[minute] = (uint32_t)price.Pval;
    }
    return(minute);
}

struct price_resolution peggy_shortprice(struct peggy *PEG,struct price_resolution price)
{
    struct price_resolution shortprice;
    memset(&shortprice,0,sizeof(shortprice));
    if ( price.Pval != 0 )
        shortprice.Pval = ((PRICE_RESOLUTION * PEG->genesisprice.Pval) / price.Pval);
        return(shortprice);
}

struct price_resolution peggy_price(struct peggy *PEG,int32_t minute)
{
    struct price_resolution relprice,price;
    memset(&price,0,sizeof(price));
    if ( minute == PEG->RTminute )
        minute--;
    while ( (price.Pval= PEG->baseprices[minute]) == 0 && minute >= 0 )
        minute--;
    if ( PEG->name.hasprice == 0 )
    {
        relprice.Pval = PEG->relprices[minute];
        if ( relprice.Pval != 0 )
        {
            if ( price.Pval < PRICE_RESOLUTION_MAXPVAL )
                price.Pval = (PRICE_RESOLUTION * price.Pval) / relprice.Pval;
            else price.Pval = PRICE_RESOLUTION_ROOT * ((PRICE_RESOLUTION_ROOT * price.Pval) / relprice.Pval);
        } else price.Pval = 0;
    }
    return(price);
}

struct price_resolution peggy_aveprice(struct peggy *PEG,int32_t day,int32_t width)
{
    int32_t i,n; struct price_resolution price,aveprice;
    aveprice.Pval = 0;
    for (i=n=0; i<width; i++,day++)
    {
        price.Pval = PEG->dayprices[day];
        if ( price.Pval != 0 )
            aveprice.Pval += price.Pval, n++;
    }
    if ( n != 0 )
        aveprice.Pval /= n;
        return(aveprice);
}

int32_t peggy_aprpercs(int64_t dailyrate)
{
    int32_t i;
    if ( dailyrate == PEGGY_RATE_777 )
        return(777);
    else if ( dailyrate == -PEGGY_RATE_777 )
        return(-777);
    for (i=0; i<sizeof(dailyrates)/sizeof(*dailyrates)-1; i++)
        if ( dailyrate >= dailyrates[i] && dailyrate < dailyrates[i+1] )
            return(i*10);
    return(0);
}

char *peggy_aprstr(int64_t dailyrate)
{
    static char aprstr[16];
    int32_t apr,dir = 1;
    if ( dailyrate < 0 )
        dir = -1, dailyrate = -dailyrate;
    apr = peggy_aprpercs(dailyrate);
    sprintf(aprstr,"%c%d.%02d%% APR",dir<0?'-':'+',apr/100,(apr%100));
    return(aprstr);
}

int64_t peggy_compound(int32_t dispflag,int64_t satoshis,int64_t dailyrate,int32_t n)
{
    int32_t i; int64_t compounded = satoshis;
    if ( dailyrate == 0 )
        return(satoshis);
    if ( dispflag != 0 )
        printf("peggy_compound rate.%lld n.%d %.8f %lld %lld -> ",(long long)dailyrate,n,dstr(satoshis),(long long)compounded,(long long)SCALED_PRICE(compounded,dailyrate));
    for (i=0; i<n; i++)
    {
        //tmp = (compounded * (PRICE_RESOLUTION + dailyrate)) / PRICE_RESOLUTION; // WARNING: Do not use floating-point math!
        compounded += SCALED_PRICE(compounded,dailyrate);
        if ( dispflag != 0 )
            printf("%.8f ",dstr(compounded));
    }
    if ( dispflag != 0 )
        printf("%.8f %.8f\n",dstr(compounded),(double)compounded/satoshis);
    if ( compounded < 0 )
        compounded = 0;
    return(compounded);
}

void peggy_updatemargin(struct peggy_margin *funds,int64_t satoshis,uint16_t margin,int64_t amount)
{
    if ( margin == 0 )
        funds->deposits += satoshis;
    else
    {
        funds->margindeposits += amount;
        funds->marginvalue += (amount * margin);
    }
}

void peggy_thanks_you(struct peggy_info *PEGS,int64_t tip) { PEGS->bank.crypto777_royalty += tip; }

void peggy_changereserve(struct peggy_info *PEGS,struct peggy *PEG,int32_t dir,struct peggy_entry *entry,int64_t satoshis,uint16_t margin,int64_t marginamount)
{
    int64_t *dest; uint64_t replenish = 0,fee = 0;
    if ( Debuglevel > 2 )
        printf("CHANGE %.8f: %c%s: %lld costbasis %.8f %s fee %.8f royalty %.8f estimated %.8f unlocked %.8f, interestpaid %.8f | units.%lld oppo.%lld\n",dstr(satoshis),entry->polarity<0?'-':'+',PEG->name.name,(long long)entry->denomination,dstr(entry->costbasis),peggy_aprstr(entry->dailyrate),dstr(entry->fee),dstr(entry->royalty),dstr(entry->estimated_interest),dstr(entry->interest_unlocked),dstr(entry->interestpaid),(long long)entry->supply.num,(long long)entry->supply.numoppo);
    PEGS->bank.APRfund_reserved += (entry->estimated_interest - entry->interest_unlocked);
    if ( PEG->pool.funds.deposits > 0 && PEGS->bank.funds.deposits > 0 )
    {
        if ( PEGS->bank.APRfund < 0 )
            PEGS->bank.APRfund += entry->fee;
        else
        {
            fee = entry->fee / PEGS->feediv, fee *= PEGS->feemult;
            PEGS->bank.APRfund += ((entry->fee - fee) - entry->interestpaid);
        }
    } else replenish = entry->fee;
    peggy_thanks_you(PEGS,entry->royalty + fee);
    peggy_updatemargin(&PEG->pool.funds,satoshis + replenish,margin,marginamount);
    peggy_updatemargin(&PEGS->bank.funds,satoshis + replenish,margin,marginamount);
    peggy_updatemargin(&PEGS->basereserves[entry->baseid].funds,dir * satoshis,margin,dir * marginamount);
    peggy_updatemargin(&PEGS->basereserves[entry->relid].funds,-dir * satoshis,margin,-dir * marginamount);
    //printf("dir.%d polarity.%d baseid.%d relid.%d sats %.8f [%.8f %.8f]\n",dir,entry->polarity,entry->baseid,entry->relid,dstr(satoshis),dstr(PEGS->basereserves[entry->baseid]),dstr(PEGS->basereserves[entry->relid]));
    dest = (entry->polarity < 0) ? &PEG->pool.liability.numoppo : &PEG->pool.liability.num;
    *dest += (dir * entry->denomination);
    if ( Debuglevel > 2 || (rand() % 1000) == 0 )
        printf(">>>>>>> %c%s %lld: cost %11.8f %s royalties %.8f APR.(R%.8f B%.8f) satoshis %11.8f %s.(+%lld -%lld) base.(%.8f %.8f) total %s (%.8f %.8f %.8f) (%.8f %.8f %.8f)\n",entry->polarity<0?'-':'+',PEG->name.name,(long long)entry->denomination,dstr(entry->costbasis),peggy_aprstr(entry->dailyrate),dstr(PEGS->bank.crypto777_royalty),dstr(PEGS->bank.APRfund_reserved),dstr(PEGS->bank.APRfund),dstr(satoshis),PEG->name.name,(long long)PEG->pool.liability.num,(long long)PEG->pool.liability.numoppo,dstr(PEGS->basereserves[entry->baseid].funds.deposits),dstr(PEGS->basereserves[entry->relid].funds.deposits),PEG->name.name,dstr(PEG->pool.funds.deposits),dstr(PEG->pool.funds.margindeposits),dstr(PEG->pool.funds.marginvalue),dstr(PEGS->bank.funds.deposits),dstr(PEGS->bank.funds.margindeposits),dstr(PEGS->bank.funds.marginvalue));
}

uint64_t peggy_satoshis(int32_t polarity,int16_t denomination,int64_t price,int64_t oppoprice)
{
    uint64_t satoshi;
    if ( polarity < 0 )
    {
        //satoshi = (denomination * price) / PRICE_RESOLUTION;
        //satoshi = (satoshi * oppoprice) / PRICE_RESOLUTION;
        //return((SATOSHIDEN * satoshi) / PRICE_RESOLUTION);
        
        satoshi = (oppoprice * price) / PRICE_RESOLUTION_ROOT;
        satoshi = ((SATOSHIDEN / PRICE_RESOLUTION_ROOT) * (satoshi * denomination)) / PRICE_RESOLUTION;
        return(satoshi);
        //return(denomination * price * oppoprice * (10 / (PRICE_RESOLUTION * PRICE_RESOLUTION * PRICE_RESOLUTION)));
    }
    else
    {
        //satoshi = (denomination * price) / PRICE_RESOLUTION;
        //return((SATOSHIDEN * satoshi) / PRICE_RESOLUTION);
        return((SATOSHIDEN * denomination * price) / PRICE_RESOLUTION);
    }
}

uint64_t peggy_poolmainunits(struct peggy_entry *entry,int32_t dir,int32_t polarity,struct price_resolution price,struct price_resolution oppoprice,struct price_resolution spread,uint64_t poolincr,int16_t denomunits)
{
    uint64_t mainunits,satoshis; struct price_resolution fee;
    entry->denomination = denomunits;
    entry->costbasis = peggy_satoshis(polarity,denomunits,price.Pval,oppoprice.Pval);
    if ( (entry->baseid != 0 || entry->relid != 0) && spread.Pval != 0 && (fee.Pval= SCALED_PRICE(price.Pval,spread.Pval)) != 0 )
        price.Pval += dir * fee.Pval;
    else fee.Pval = 0;
    satoshis = peggy_satoshis(polarity,denomunits,price.Pval,oppoprice.Pval);
    if ( (satoshis % poolincr) == 0 )
        dir = 0;
    mainunits = dir + (satoshis / poolincr);
    entry->total = poolincr * mainunits;
    entry->fee = (entry->total - entry->costbasis);
    if ( Debuglevel > 2 )
        printf("mainunits %llu: origcost %.8f [%.8f] denomination %d poolincr %.8f price %.6f spread %.6f fee %.8f\n",(long long)mainunits,dstr(entry->costbasis),dstr(entry->fee),denomunits,dstr(poolincr),Pval(&price),Pval(&spread),Pval(&fee));
    return(entry->total);
}

int64_t peggy_pairabs(int64_t basebalance,int64_t relbalance)
{
    int64_t baserelbalance;
    if ( (baserelbalance= basebalance) < 0 )
        baserelbalance = -baserelbalance;
    if ( relbalance < 0 )
        baserelbalance -= relbalance;
    else baserelbalance += relbalance;
    return(baserelbalance);
}

int64_t peggy_lockrate(struct peggy_entry *entry,struct peggy_info *PEGS,struct peggy *PEG,uint64_t satoshis,uint16_t numdays)
{
    int64_t diff,compounded,prod,dailyrate=0,both,needed = 0;
    if ( (both= entry->supply.num + entry->supply.numoppo) != 0 )
    {
        if ( (diff= (entry->supply.numoppo - entry->supply.num)) < 0 )
            entry->supplydiff = -diff;
        else entry->supplydiff = diff;
        prod = (PEG->maxdailyrate * diff);
        if ( prod > 0 )
            prod *= PEGS->posboost;
        dailyrate = (prod /  both) + dailyrates[PEGS->interesttenths];
        if ( dailyrate > PEGGY_RATE_777 )
            dailyrate = PEGGY_RATE_777;
        else if ( dailyrate < -PEGGY_RATE_777 )
            dailyrate = -PEGGY_RATE_777;
        if ( prod < 0 && dailyrate > 0 )
            dailyrate /= PEGS->negpenalty;
        compounded = peggy_compound(0,satoshis,dailyrate,numdays);
        needed = (compounded - satoshis);
        needed *= 3, needed /= 2;
        if ( Debuglevel > 2 )
            printf("2x needed %.8f dailyrate.%lld compounded %lld <- %lld diff.%lld prod.%lld both.%lld -> %lld %s\n",dstr(needed),(long long)dailyrate,(long long)compounded,(long long)satoshis,(long long)diff,(long long)prod,(long long)both,(long long)dailyrate,peggy_aprstr(dailyrate));
        if ( (PEGS->bank.APRfund_reserved + needed) > PEGS->bank.APRfund )
        {
            compounded = peggy_compound(1,satoshis,dailyrate,numdays);
            printf("reserved %.8f + needed %.8f) > APRfund %.8f\n",dstr(PEGS->bank.APRfund_reserved),dstr(needed),dstr(PEGS->bank.APRfund));
            needed = dailyrate = 0;
        } else entry->estimated_interest = needed;
    }
    entry->dailyrate = dailyrate;
    return(dailyrate);
}

int32_t peggy_islegal_amount(struct peggy_entry *entry,struct peggy_info *PEGS,struct peggy *PEG,int32_t dir,int64_t satoshis,int32_t numdays,uint16_t margin,struct price_resolution price)
{
    uint64_t newsupply; int64_t baserelbalance,newbaserel;
    if ( margin == 0 )
        entry->dailyrate = peggy_lockrate(entry,PEGS,PEG,satoshis,numdays);
    if ( entry->baseid == entry->relid )
    {
        printf("illegal baseid.%d relid.%d (%s)\n",PEG->name.baseid,PEG->name.relid,PEG->name.name);
        //getchar();
        return(1);
    }
    if ( PEG->name.id == 0 )
    {
        printf("BTCD is legal\n");
        return(1);
    }
    if ( (newsupply= ((PEG->pool.funds.deposits + PEG->pool.funds.marginvalue) + satoshis)) > PEG->maxsupply )
    {
        printf("peggy_islegal_amount %.8f %.8f newsupply %.8f > limits %.8f\n",dstr(PEG->pool.funds.deposits),dstr(PEG->pool.funds.marginvalue),dstr(newsupply),dstr(PEG->maxsupply));
        return(0);
    }
    //printf("baseid.%d relid.%d\n",entry->baseid,entry->relid);
    baserelbalance = peggy_pairabs(PEGS->basereserves[entry->baseid].funds.deposits,PEGS->basereserves[entry->relid].funds.deposits);
    newbaserel = peggy_pairabs(PEGS->basereserves[entry->baseid].funds.deposits + satoshis,PEGS->basereserves[entry->relid].funds.deposits - satoshis);
    if ( Debuglevel > 2 )
        printf("baseid.%d relid.%d satoshis %.8f baserelbalance %.8f newbaserel %.8f\n",entry->baseid,entry->relid,dstr(satoshis),dstr(baserelbalance),dstr(newbaserel));
    if ( newbaserel <= baserelbalance )
        return(1);
    //printf("entry->supplydiff.%lld diff %.8f vs maxnetbalance %.8f\n",(long long)entry->supplydiff,(double)(price.Pval*entry->supplydiff)/PRICE_RESOLUTION,dstr(PEG->limits.maxnetbalance));
    if ( PEG->maxnetbalance != 0 && (price.Pval * entry->supplydiff) / PRICE_RESOLUTION > PEG->maxnetbalance/SATOSHIDEN )
    {
        printf("entry->supplydiff.%lld diff %.8f vs maxnetbalance %.8f\n",(long long)entry->supplydiff,(double)(price.Pval*entry->supplydiff)/PRICE_RESOLUTION,dstr(PEG->maxnetbalance));
        return(0);
    }
    return(1);
}

static uint64_t peggy_assetbits(char *name) { return((is_decimalstr(name) != 0) ? calc_nxt64bits(name) : stringbits(name)); }

struct peggy *peggy_findpair(struct peggy_info *PEGS,char *name)
{
    int32_t i; uint64_t assetbits;
    if ( (assetbits= peggy_assetbits(name)) != 0 )
    {
        for (i=0; i<PEGS->numpegs; i++)
        {
            if ( PEGS->contracts[i]->name.assetbits == assetbits )
                return(PEGS->contracts[i]);
        }
    }
    return(0);
}

struct peggy *peggy_found(struct peggy_entry *entry,struct peggy *PEG,int32_t polarity)
{
    int64_t num,numoppo;
    memset(entry,0,sizeof(*entry));
    num = PEG->pool.liability.num, numoppo = PEG->pool.liability.numoppo;
    if ( polarity >= 0 )
        entry->polarity = 1, entry->baseid = PEG->name.baseid, entry->relid = PEG->name.relid, entry->supply.num = num, entry->supply.numoppo = numoppo;
    else entry->polarity = -1, entry->baseid = PEG->name.relid, entry->relid = PEG->name.baseid, entry->supply.num = numoppo, entry->supply.numoppo = num;
    //printf("(%s) -> baseid.%d relid.%d\n",PEG->name.name,entry->baseid,entry->relid);
    return(PEG);
}

struct peggy *peggy_find(struct peggy_entry *entry,struct peggy_info *PEGS,char *name,int32_t polarity)
{
    struct peggy *PEG;
    if ( (PEG= peggy_findpair(PEGS,name)) != 0 )
        return(peggy_found(entry,PEG,polarity));
    return(0);
}

struct peggy *peggy_findpeg(struct peggy_entry *entry,struct peggy_info *PEGS,int32_t peg)
{
    if ( peg >= 0 )
        return(peggy_found(entry,PEGS->contracts[peg],peg));
    else return(peggy_found(entry,PEGS->contracts[-peg],peg));
}

int32_t peggy_pegstr(char *buf,struct peggy_info *PEGS,char *name)
{
    int32_t peg=0; struct peggy *PEG;
    buf[0] = 0;
    if ( name != 0 )
    {
        strcpy(buf,name);
        if ( (PEG= peggy_findpair(PEGS,name)) != 0 )
            return(PEG->name.id);
    }
    return(peg);
}

int32_t peggy_setname(char *buf,char *name)
{
    return(peggy_pegstr(buf,opreturns_context("peggy",0),name));
}

int64_t peggy_calcspread(int64_t spread,int32_t lockdays) { return((lockdays < 30) ? spread : ((30 * spread) / lockdays)); }

uint64_t peggy_setunit(struct peggy_unit *U,struct peggy_entry *entry,struct peggy_info *PEGS,struct peggy_time T,struct peggy *PEG,uint64_t seed,uint64_t nxt64bits,struct peggy_lock *lock)
{
    int32_t numdays,polarity; uint64_t poolincr; int16_t denom; struct price_resolution spread;
    memset(U,0,sizeof(*U));
    U->lock = *lock;
    if ( (denom= lock->denom) < 0 )
        polarity = -1, denom = -denom;
    else polarity = 1;
    if ( denom >= PRICE_RESOLUTION_MAXUNITS )
    {
        printf("denom.%d is too big max %lld\n",denom,(long long)PRICE_RESOLUTION_MAXUNITS);
        return(0);
    }
    if ( U->lock.margin != 0 )
    {
        if ( U->lock.maxlockdays > PEGGY_MARGINLOCKDAYS )
        {
            printf("error: maxlockdays cant be more than PEGGY_MARGINLOCKDAYS %d for margin trading\n",PEGGY_MARGINLOCKDAYS);
            return(0);
        }
        else if ( U->lock.margin > PEG->lockparms.margin )
        {
            printf("error: margin.%d cant be more than %d for margin trading %s\n",U->lock.margin,PEG->lockparms.margin,PEG->name.name);
            return(0);
        }
        else if ( denom < U->lock.margin )
        {
            printf("error: denomination %lld must be >= margin %dx trading %s\n",(long long)denom,U->lock.margin,PEG->name.name);
            return(0);
        }
        else if ( (denom + entry->supply.num) > entry->supply.numoppo )
        {
            //printf("error: denom.%d supply %d %d > oppo %d -> balance violation %s\n",denom,entry->supply.num,denom+entry->supply.num,entry->supply.numoppo,PEG->name.name);
            return(0);
        }
        U->lock.redemptiongapdays = PEGGY_MARGINGAPDAYS;
    } else U->lock.redemptiongapdays = PEG->lockparms.redemptiongapdays;
    if ( U->lock.maxlockdays <= PEG->lockparms.maxlockdays )
        U->lock.maxlockdays = PEG->lockparms.maxlockdays;
    if ( U->lock.minlockdays >= PEG->lockparms.minlockdays )
        U->lock.minlockdays = PEG->lockparms.minlockdays;
    if ( U->lock.minlockdays > U->lock.maxlockdays )
        U->lock.minlockdays = U->lock.maxlockdays;
    if ( U->lock.clonesmear > PEG->lockparms.clonesmear )
        U->lock.clonesmear = PEG->lockparms.clonesmear;
    if ( U->lock.mixrange > PEG->lockparms.mixrange )
        U->lock.mixrange = PEG->lockparms.mixrange;
    U->lock.extralockdays = PEGGY_MINEXTRADAYS + (seed % PEG->lockparms.extralockdays);
    entry->price = PEG->dayprice;//peggy_nonzprice(PEGS,T,PEG,1,day);
    entry->oppoprice = peggy_shortprice(PEG,entry->price);//peggy_nonzprice(PEGS,T,PEG,-1,day);
    poolincr = PEG->pool.mainunitsize;
    U->timestamp = T.blocktimestamp, U->baseid = entry->baseid, U->relid = entry->relid; //, U->nxt64bits = nxt64bits,
    U->lock.peg = PEG->name.id * polarity;
    spread.Pval = peggy_calcspread(PEG->spread.Pval,U->lock.minlockdays + U->lock.extralockdays);
    peggy_poolmainunits(entry,1,polarity,entry->price,entry->oppoprice,spread,poolincr,denom);
    U->costbasis = entry->costbasis;
    numdays = (polarity > 0) ? (U->lock.maxlockdays + PEG->lockparms.extralockdays) : (U->lock.minlockdays + PEG->lockparms.extralockdays);
    return(entry->total * peggy_islegal_amount(entry,PEGS,PEG,polarity,entry->total,numdays,U->lock.margin,entry->price));
}

int64_t peggy_redeemhash(struct peggy_entry *entry,struct peggy_info *PEGS,struct peggy_time T,struct peggy_unit *U,int32_t lockdays)
{
    struct price_resolution price,oppoprice,spread; struct peggy *PEG; int32_t n,delta; uint64_t poolincr,interest,satoshis = 0;
    if ( (PEG= peggy_findpeg(entry,PEGS,U->lock.peg)) != 0 )
    {
        poolincr = PEG->pool.mainunitsize, oppoprice.Pval = spread.Pval = 0;
        delta = (T.blocktimestamp - U->timestamp) / PEGGY_DAYTICKS;
        lockdays += U->lock.extralockdays;
        if ( delta < lockdays )
            return(0);
        else if ( delta > (lockdays + U->lock.redemptiongapdays) )
            return(-1);
        T.blocktimestamp = U->timestamp + (lockdays * PEGGY_DAYTICKS);
        if ( (n= (int32_t)(U->costbasis / PEG->unitincr)) > 0 )
            T.blocktimestamp -= (n * PEGGY_DAYTICKS) / 2;
        else n = 1;
        price = peggy_aveprice(PEG,(T.blocktimestamp - PEG->genesistime) / PEGGY_DAYTICKS,n);
        if ( entry->polarity < 0 )
            oppoprice = peggy_shortprice(PEG,price);
        spread.Pval = peggy_calcspread(PEG->spread.Pval,lockdays);
        satoshis = peggy_poolmainunits(entry,-1,entry->polarity,price,oppoprice,spread,poolincr,U->lock.denom);
        entry->costbasis = U->costbasis;
        if ( U->estimated_interest != 0 )
        {
            interest = peggy_compound(0,satoshis,U->dailyrate,lockdays + U->lock.extralockdays) - satoshis;
            entry->interestpaid = (interest / poolincr) * poolincr;
            if ( entry->interestpaid > U->estimated_interest )
                entry->interestpaid = U->estimated_interest;
            entry->royalty += (interest - entry->interestpaid);
            entry->interest_unlocked = U->estimated_interest;
        }
        if ( U->lock.margin == 0 )
        {
            if ( PEG->pool.funds.deposits < satoshis )
                satoshis = PEG->pool.funds.deposits;
            else if (PEG->pool.funds.deposits >= (satoshis + entry->interestpaid) )
                satoshis += entry->interestpaid;
        }
        else
        {
            if ( PEG->pool.funds.margindeposits < satoshis )
                satoshis = PEG->pool.funds.margindeposits;
        }
    }
    return(satoshis);
}

uint64_t peggy_redeem(struct peggy_info *PEGS,struct peggy_time T,int32_t readonly,char *name,int32_t polarity,uint64_t nxt64bits,bits256 pubkey,uint16_t lockdays,uint8_t chainlen)
{
    struct peggy_entry entry; struct peggy_unit *U; struct peggy *PEG; int32_t peg; int64_t satoshis = 0; bits256 lockhash;
    if ( (PEG= peggy_findpair(PEGS,name)) != 0 )
    {
        peg = PEG->name.id * polarity;
        lockhash = acct777_lockhash(pubkey,lockdays,chainlen);
        if ( (U= peggy_match(PEGS->accts,peg,nxt64bits,lockhash,lockdays)) != 0 )
        {
            if ( (satoshis= peggy_redeemhash(&entry,PEGS,T,U,lockdays)) < 0 )
            {
                printf("Autopurge unit.%p\n",U);
                satoshis = 0;
            }
            if ( readonly == 0 )
            {
                peggy_changereserve(PEGS,PEG,-1,&entry,satoshis,U->lock.margin,U->marginamount);
                peggy_delete(PEGS->accts,U,satoshis == 0 ? PEGGY_RSTATUS_AUTOPURGED : PEGGY_RSTATUS_REDEEMED);
            }
        }
    }
	return(satoshis);
}

uint64_t peggy_createunit(struct peggy_info *PEGS,struct peggy_time T,struct peggy_unit *readU,uint64_t seed,char *name,uint64_t nxt64bits,bits256 lockhash,struct peggy_lock *lock,uint64_t amount,uint64_t marginamount)
{
    struct peggy_entry entry; struct peggy_unit U; int32_t peg,polarity; int16_t denomination; int64_t satoshis = 0; struct peggy *PEG = 0;
    denomination = lock->denom;
    if ( denomination < 0 )
        polarity = -1, denomination = -denomination;
    else polarity = 1;
    if ( denomination >= PRICE_RESOLUTION_MAXUNITS )
    {
        printf("denomination.%d is too big max %lld\n",denomination,(long long)PRICE_RESOLUTION_MAXUNITS);
        return(0);
    }
    if ( name == 0 )
    {
        if ( (peg= lock->peg) == 0 )
            PEG = PEGS->contracts[0];
        else if ( lock->peg < 0 )
            peg = -peg, polarity = -polarity;
        if ( peg >= PEGS->numpegs )
        {
            printf("illegal peg id.%d\n",lock->peg);
            return(0);
        }
        PEG = PEGS->contracts[peg];
        PEG = peggy_find(&entry,PEGS,PEG->name.name,polarity);
    } else PEG = peggy_find(&entry,PEGS,name,polarity);
    if ( PEG != 0 )
    {
        if ( (satoshis= peggy_setunit(&U,&entry,PEGS,T,PEG,seed,nxt64bits,lock)) != 0 )
        {
            U.estimated_interest = entry.estimated_interest, U.amount = amount, U.marginamount = marginamount;
            if ( readU == 0 )
            {
                if ( Debuglevel > 2 )
                    printf("%s.%d amount %.8f satoshis %.8f incr.%.8f price.%.8f\n",PEG->name.name,PEG->name.id,dstr(amount),dstr(satoshis),dstr(PEG->pool.mainunitsize),Pval(&entry.price));
                if ( (lock->margin == 0 && amount >= satoshis) || (marginamount * lock->margin) >= satoshis )
                {
                    peggy_changereserve(PEGS,PEG,1,&entry,entry.costbasis,lock->margin,marginamount);
                    peggy_addunit(PEGS->accts,&U,lockhash);
                    if ( Debuglevel > 2 )
                        printf("id.%d needed for interest reserved %.8f BTCD, royalty %.8f | dailyrate %lld %s\n",PEG->name.id,dstr(U.estimated_interest),dstr(amount) - dstr(satoshis),(long long)U.dailyrate,peggy_aprstr(U.dailyrate));
                } else printf("%s amount %.8f not enough for unit %.8f or margin.%d %llu %.8f\n",PEG->name.name,dstr(amount),dstr(satoshis),lock->margin,(long long)marginamount,dstr(marginamount * lock->margin)), satoshis = 0;
            }
        }
        if ( readU != 0 ) *readU = U, printf("%c%s cost %.8f %s\n",polarity < 0 ? '-' : '+',PEG->name.name,dstr(satoshis),peggy_aprstr(U.dailyrate));
    } else printf("peggy_createunit: cant find.(%s)\n",name);
    return(satoshis);
}

uint64_t peggy_gamblers(struct peggy_info *PEGS,struct peggy_time T,struct price_resolution prevprice,struct price_resolution newprice,struct peggy_bet *bets,int32_t numbets)
{
    int32_t i,j,match,oppo,numbest = 0; int64_t diff,preddiff,tmp,dist,bestdist;
    uint64_t bet,payout,totalbets,losingbets,winningbets,totalpayout,matchbets,oppobets,matchshares;
    matchshares = matchbets = oppobets = losingbets = winningbets = bestdist = totalpayout = match = oppo = 0;
    if ( bets != 0 )
    {
        for (totalbets=i=0; i<numbets; i++)
            if ( (bet= (bets[i].dirbet + bets[i].distbet)) != 0 )
                totalbets += bet;
    } else return(0);
    if ( (diff= (newprice.Pval - prevprice.Pval)) < 0 )
        diff = -1;
    else if ( diff > 0 )
        diff = 1;
    for (j=0; j<numbets; j++)
    {
        bets[j].minutes = (T.blocktimestamp - bets[j].timestamp) / PEGGY_MINUTE;
        bets[j].shares = bets[j].dist = 0;
        if ( (bet= bets[j].dirbet) != 0 )
        {
            if ( (preddiff= (bets[j].prediction.Pval - prevprice.Pval)) < 0 )
                preddiff = -1;
            else if ( preddiff > 0 )
                preddiff = 1;
            if ( (tmp= diff*preddiff) > 0 )
                match++, matchbets += bet, bets[j].shares = (bet * bets[j].minutes), matchshares += (bet * (1 + bets[j].minutes));
            else if ( tmp < 0 )
                oppo++, oppobets += bet;
        }
        if ( (bet= bets[j].distbet) != 0 )
        {
            if ( (dist= ((int64_t)newprice.Pval - bets[j].prediction.Pval)) < 0 )
                dist = -dist;
            bets[j].dist = ++dist;
            if ( bestdist == 0 || dist < bestdist )
                bestdist = dist;
        }
        bets[j].payout = 0;
    }
    for (j=0; j<numbets; j++)
    {
        if ( bets[j].dist == bestdist )
            winningbets += bets[j].distbet, numbest++;
        else losingbets += bets[j].distbet;
    }
    winningbets += (winningbets / 100);
    for (j=0; j<numbets; j++)
    {
        if ( bets[j].dist == bestdist && winningbets != 0 )
            bets[j].payout = bets[j].distbet + ((bets[j].distbet * losingbets) / winningbets);
    }
    matchshares += (matchshares / 100);
    for (payout=j=0; j<numbets; j++)
    {
        if ( bets[j].shares != 0 )
            bets[j].payout = bets[j].dirbet + ((bets[j].shares * oppobets) / matchshares);
        payout += bets[j].payout;
    }
    PEGS->bank.privatebetfees += (totalbets - payout);
    if ( numbets != 0 )
        printf("royalty %.8f (%.8f - payout %.8f) numbest.%d winningbets %.8f vs losingbets %.8f | match.%d %.8f, oppo.%d %.8f\n",dstr(totalbets - payout),dstr(totalbets),dstr(payout),numbest,dstr(winningbets),dstr(losingbets),match,dstr(matchbets),oppo,dstr(oppobets));
    return(totalpayout);
}

struct price_resolution peggy_newprice(struct peggy_info *PEGS,struct peggy *PEG,struct peggy_time T,uint32_t newpval)
{
    uint64_t sum,den,gap; int64_t diff; int32_t i,j,minute,iter; struct price_resolution price,shortprice,newprice;
    gap = (PEG->spread.Pval * newpval) / PRICE_RESOLUTION;
    if ( (newprice.Pval= newpval) != 0 )
    {
        for (iter=0; iter<1; iter++)
        {
            sum = den = 0;
            sum = (((uint64_t)peggy_smooth_coeffs[0]) * newprice.Pval);
            den = peggy_smooth_coeffs[0];
            minute = (T.blocktimestamp - PEG->genesistime) / PEGGY_MINUTE;
            //printf("peggy_newprice day.%d: %u sum %lld\n",day,newpval,(long long)sum);
            for (i=1; i<PEGGY_NUMCOEFFS; i++)
            {
                j = (minute - i);
                if ( j > 0 )
                {
                    price = peggy_price(PEG,j);
                    if ( price.Pval != 0 )
                    {
                        sum += (((uint64_t)peggy_smooth_coeffs[i]) * price.Pval);
                        den += peggy_smooth_coeffs[i];
                    }
                    //printf("i.%d ind.%d coeff.%llu add.%lld sum %lld den %lld %.6f -> %.7f\n",i,j,(long long)peggy_smooth_coeffs[i],(long long)price.Pval,(long long)sum,(long long)den,Pval(&price),(double)sum/(den));
                } else break;
            }
            price.Pval = newpval;
            //printf("sum %lld den %lld %.10f -> %.10f || ",(long long)sum,(long long)den,Pval(&price),(double)sum/(den));
            if ( den != 0 )
                price.Pval = (sum / den);
            else break;
            newprice = price;
            diff = (newprice.Pval - newpval);
            if ( diff < 0 )
                diff = -diff;
            if ( diff < gap )
                break;
            newprice.Pval = (newprice.Pval*7 + newpval) / 8;
            //printf("%.8f ",Pval(&newprice));
        }
        peggy_setprice(PEG,newprice,minute);
        shortprice = peggy_shortprice(PEG,newprice);
        price.Pval = newpval;
        if ( Debuglevel > 2 )
            fprintf(stderr,"t.%u M%d day.%-4d new %.8f short.%.8f pval.%.8f | first %.10f ",T.blocktimestamp,minute,minute/1440,Pval(&newprice),Pval(&shortprice),Pval(&price),Pval(&PEG->genesisprice));
    }
    return(newprice);
}

void peggy_margincalls(struct peggy_info *PEGS,struct peggy_time T,struct peggy *PEG,struct price_resolution newprice,struct price_resolution shortprice)
{
    int32_t i; struct peggy_unit *U; int64_t satoshis,gain,threshold; struct peggy_entry entry;
    for (i=0,U=&PEGS->accts->units[0]; i<PEGS->accts->numunits; i++,U++)
    {
        if ( U->lock.margin != 0 && PEG != 0 && (PEG->name.id == U->lock.peg || PEG->name.id == -U->lock.peg) )
        {
            if ( (PEG= peggy_findpeg(&entry,PEGS,U->lock.peg)) != 0 )
            {
                satoshis = peggy_poolmainunits(&entry,-1,entry.polarity,newprice,shortprice,PEG->spread,PEG->pool.mainunitsize,U->lock.denom);
                gain = entry.polarity * (satoshis - U->costbasis), threshold = -U->costbasis/U->lock.margin;
                if ( gain < threshold )
                {
                    printf("%s %8.6f %8.6f %2dx gain %11.8f polarity.%-2d (%11.8f - cost %11.8f) -> profit %11.8f margincall %11.8f ",PEG->name.name,Pval(&newprice),Pval(&shortprice),U->lock.margin,dstr(gain),entry.polarity,dstr(satoshis),dstr(U->costbasis),dstr(gain),dstr(threshold));
                    printf("MARGINCALLED\n");
                    peggy_changereserve(PEGS,PEG,-1,&entry,satoshis,U->lock.margin,U->marginamount);
                    peggy_delete(PEGS->accts,U,PEGGY_RSTATUS_MARGINCALL);
                }
            }
        }
    }
}

struct price_resolution peggy_priceconsensus(struct peggy_info *PEGS,struct peggy_time T,uint64_t seed,int16_t pricedpeg,struct peggy_vote *votes,uint32_t numvotes,struct peggy_bet *bets,uint32_t numbets)
{
    struct peggy_entry entry; struct price_resolution newprice,dayprice,tmp; struct peggy *PEG;
    int64_t delta,weight,totalwt = 0; int32_t i,j,n,minute,day,wts[PEGGY_NUMCOEFFS]; uint32_t start,k; uint64_t ind;
    newprice.Pval = 0;
    if ( (PEG= peggy_find(&entry,PEGS,PEGS->contracts[pricedpeg]->name.name,1)) != 0 )
    {
        for (i=n=0; i<numvotes; i++)
        {
            if ( votes[i].pval != 0 )
            {
                wts[i] = 1;//n + 1;
                n++;
                totalwt += wts[i];
            }
        }
        if ( n < PEG->pool.quorum || totalwt < PEG->pool.decisionthreshold )
            return(PEG->price);
        start = (uint32_t)(pricedpeg * seed);
        for (k=0; k<numvotes; k++)
        {
            if ( numvotes == PEGGY_NUMCOEFFS )
                ind = Peggy_inds[(k + start) % PEGGY_NUMCOEFFS];
            else ind = (start + k);
            i = (int32_t)(ind % numvotes);
            //fprintf(stderr,"(%d %d) ",i,k);
            weight = 0;
            if ( votes[i].pval != 0 )
            {
                for (j=0; j<numvotes; j++)
                {
                    if ( votes[j].pval != 0 )
                    {
                        //fprintf(stderr,"%lld ",(long long)(j*incr + seed) % numvotes);
                        if ( (delta= (votes[i].pval - votes[j].pval)) < 0 )//votes[j].price.Pval)) < 0 )
                            delta = -delta;
                        //printf("(%lld %llu %u).%lld ",(long long)delta,(long long)votes[i].pval,votes[j].tolerance,(long long)weight);
                        if ( delta <= votes[j].tolerance )//votes[j].tolerance.Pval )
                        {
                            weight += wts[j];
                            if ( weight > (totalwt >> 1) ) ////votes[j].weight;
                                break;
                        }
                    }
                }
            }
            //if ( strcmp("SuperNET",PEG->name.name) == 0 )
            //    fprintf(stderr,"%d.(%.6f %llu) ",i,(double)votes[i].pval/PRICE_RESOLUTION,(long long)weight);
            if ( weight > (totalwt >> 1) )
            {
                if ( Debuglevel > 2 )
                    fprintf(stderr,"%6d k%-4d %4d-> %.6f wt.%-4lld/%4lld ",votes[i].pval,k,i,Pval(&PEG->price),(long long)weight,(long long)totalwt);
                PEG->price = peggy_newprice(PEGS,PEG,T,votes[i].pval);
                break;
            }
        }
        if ( 0 && k == numvotes )
            fprintf(stderr,"no consensus for %s %6d k%-4d %4d-> %.6f wt.%-4lld/%4lld ",PEG->name.name,votes[i].tolerance,k,i,Pval(&PEG->price),(long long)weight,(long long)totalwt);
        if ( (day= (T.blocktimestamp - PEG->genesistime)/PEGGY_DAYTICKS) != PEG->day )
        {
            peggy_gamblers(PEGS,T,PEG->dayprice,PEG->price,bets,numbets);
            dayprice.Pval = 0;
            for (minute=PEG->day*1440,i=n=0; i<1440; i++,minute++)
            {
                tmp = peggy_price(PEG,minute);
                if ( tmp.Pval != 0 )
                    dayprice.Pval += tmp.Pval, n++;
            }
            if ( n != 0 )
                dayprice.Pval /= n;
            PEG->dayprice = dayprice;
            PEG->day = day;
            PEG->dayprices[day] = (uint32_t)dayprice.Pval;
            if ( Debuglevel > 2 )
                printf(">>>>>>>>>>>> DAY PRICE.%d %s %.8f\n",day,PEG->name.name,Pval(&dayprice));
            while ( --day > 0 && PEG->dayprices[day] == 0 )
                PEG->dayprices[day] = (uint32_t)dayprice.Pval;
        }
        peggy_margincalls(PEGS,T,PEG,PEG->price,peggy_shortprice(PEG,PEG->price));
        newprice = PEG->price;
    } else printf("cant find peg.%d\n",pricedpeg);
        return(newprice);
}
