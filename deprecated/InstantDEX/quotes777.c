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
#ifndef quotes777_h
#define quotes777_h

#include <stdio.h>
#include <stdint.h>
#include <memory.h>
#include "../iguana777.h"
#include "serdes777.c"
#include "peggy777.c"

#endif
#else
#ifndef quotes777_c
#define quotes777_c

#ifndef quotes777_h
#define DEFINES_ONLY
#include "quotes777.c"
//#include "serdes777.c"
#undef DEFINES_ONLY
#endif

//////////// must be consensus safe
#define PEGGY_GENESIS "6aef504158ec0014fee05dc20a0006048ed63e523f6d1062feb23622da928cf23ddcc3b53f23566bc6cab5ebd77cfbf8f0bccb34bff73c55d742dd232994bfbffe1cbab7119ab3d653a256b02d5b6f56c05b8817799f0d242f48c26d35c992ebfff14acdefbe253345d394e84d975334cd55f7d6cbad5a7bd9425b1d5db44944d40be5304b7b62ba0dbc20d3323d2b35f05f654bc95a5a2fdb5a30e46c6fd33b5ea078255f7cad9fd0dbd2fa5031ada4474cbba7b2ee64ef35df06bf3fd3eef6cd3f48339f3c0e080158a92862bbf20bc6702018effbaee525502eb463c74f7ca0dff4ae7cb55ee55ef7cb1c915e655649"

//#define PEGGY_GENESIS "6aef504547ec00143e3028ba0a000604800d0560da5a55fbb56121b403e9dfbbd99f6b05c9af5683676bdda7f39636c579515174afebe5ad659c44567df9f02eb1dc5e30b4cc1a96a0dab18b2e55e5fd771032f2ee3d34de9313d9ea2813d70e6995a2fe7d7b2854a6032c9d022d676a9ae0ed573ab57e4887761a85688b20b417ad099686a67a2b82cca6104698a254c5ca5fe95ab874649513bae9e4bcbc7e868497c3a9d6da3ad82d625f12078d50c48a2e492bd6665e9f86e3fbe4bf6ee1758a9461fee35068851562b3b68082645c92a8f35a61a2de5652478b441fc53aa96aaf169feaedaef7bf1472fb3542ee04"
//#define PEGGY_GENESIS "6af2504547ef00147eb3ccb70a0006f49b65bed5a3b5f867565be8feb53b1c694b1bd8bcf1039696d8b968a7ae93168e745c6737fe9b6ab079152a3cabeee24e4d48f9ade6b1b41a39fc3abe2a5ae6f9254de6cbf679ad6e338cdfd7b1b4b1e2689c555648a4087cd94aa44869ab48a65b1295f6f75f8bf760a42966bbf2c1d8d6811379d17916e99abdb6c5246a2a192969f101ae3cc9679d98c5abedb64b6d9ea3a5ee485fe3ea467b77e5add9c1fa2d0d0dc781a5046b686b5c3bcdd91b8abb6ed33c8c556e05c4778b0e6b30bd6d6f41cc381d50e7f5a565bd64e78ff696de8a9517ee5ec79f531c594510abdd25ac44e62a"

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

int32_t Peggy_inds[539] = {289, 404, 50, 490, 59, 208, 87, 508, 366, 288, 13, 38, 159, 440, 120, 480, 361, 104, 534, 195, 300, 362, 489, 108, 143, 220, 131, 244, 133, 473, 315, 439, 210, 456, 219, 352, 153, 444, 397, 491, 286, 479, 519, 384, 126, 369, 155, 427, 373, 360, 135, 297, 256, 506, 322, 425, 501, 251, 75, 18, 420, 537, 443, 438, 407, 145, 173, 78, 340, 240, 422, 160, 329, 32, 127, 128, 415, 495, 372, 522, 60, 238, 129, 364, 471, 140, 171, 215, 378, 292, 432, 526, 252, 389, 459, 350, 233, 408, 433, 51, 423, 19, 62, 115, 211, 22, 247, 197, 530, 7, 492, 5, 53, 318, 313, 283, 169, 464, 224, 282, 514, 385, 228, 175, 494, 237, 446, 105, 150, 338, 346, 510, 6, 348, 89, 63, 536, 442, 414, 209, 216, 227, 380, 72, 319, 259, 305, 334, 236, 103, 400, 176, 267, 355, 429, 134, 257, 527, 111, 287, 386, 15, 392, 535, 405, 23, 447, 399, 291, 112, 74, 36, 435, 434, 330, 520, 335, 201, 478, 17, 162, 483, 33, 130, 436, 395, 93, 298, 498, 511, 66, 487, 218, 65, 309, 419, 48, 214, 377, 409, 462, 139, 349, 4, 513, 497, 394, 170, 307, 241, 185, 454, 29, 367, 465, 194, 398, 301, 229, 212, 477, 303, 39, 524, 451, 116, 532, 30, 344, 85, 186, 202, 517, 531, 515, 230, 331, 466, 147, 426, 234, 304, 64, 100, 416, 336, 199, 383, 200, 166, 258, 95, 188, 246, 136, 90, 68, 45, 312, 354, 184, 314, 518, 326, 401, 269, 217, 512, 81, 88, 272, 14, 413, 328, 393, 198, 226, 381, 161, 474, 353, 337, 294, 295, 302, 505, 137, 207, 249, 46, 98, 27, 458, 482, 262, 253, 71, 25, 0, 40, 525, 122, 341, 107, 80, 165, 243, 168, 250, 375, 151, 503, 124, 52, 343, 371, 206, 178, 528, 232, 424, 163, 273, 191, 149, 493, 177, 144, 193, 388, 1, 412, 265, 457, 255, 475, 223, 41, 430, 76, 102, 132, 96, 97, 316, 472, 213, 263, 3, 317, 324, 274, 396, 486, 254, 205, 285, 101, 21, 279, 58, 467, 271, 92, 538, 516, 235, 332, 117, 500, 529, 113, 445, 390, 358, 79, 34, 488, 245, 83, 509, 203, 476, 496, 347, 280, 12, 84, 485, 323, 452, 10, 146, 391, 293, 86, 94, 523, 299, 91, 164, 363, 402, 110, 321, 181, 138, 192, 469, 351, 276, 308, 277, 428, 182, 260, 55, 152, 157, 382, 121, 507, 225, 61, 431, 31, 106, 327, 154, 16, 49, 499, 73, 70, 449, 460, 187, 24, 248, 311, 275, 158, 387, 125, 67, 284, 35, 463, 190, 179, 266, 376, 221, 42, 26, 290, 357, 268, 43, 167, 99, 374, 242, 156, 239, 403, 339, 183, 320, 180, 306, 379, 441, 20, 481, 141, 77, 484, 69, 410, 502, 172, 417, 118, 461, 261, 47, 333, 450, 296, 453, 368, 359, 437, 421, 264, 504, 281, 270, 114, 278, 56, 406, 448, 411, 521, 418, 470, 123, 455, 148, 356, 468, 109, 204, 533, 365, 8, 345, 174, 370, 28, 57, 11, 2, 231, 310, 196, 119, 82, 325, 44, 342, 37, 189, 142, 222, 9, 54, };

char *peggy_contracts[64] =
{
    "BTCD", "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD", // major currencies
    "CNY", "RUB", "MXN", "BRL", "INR", "HKD", "TRY", "ZAR", "PLN", "NOK", "SEK", "DKK", "CZK", "HUF", "ILS", "KRW", "MYR", "PHP", "RON", "SGD", "THB", "BGN", "IDR", "HRK",
    "BTCUSD", "NXTBTC", "SuperNET", "ETHBTC", "LTCBTC", "XMRBTC", "BTSBTC", "XCPBTC",  // BTC priced
    "XAUUSD", "XAGUSD", "XPTUSD", "XPDUSD", "Copper", "NGAS", "UKOil", "USOil", // USD priced
    "Bund", "NAS100", "SPX500", "US30", "EUSTX50", "UK100", "JPN225", "GER30", "SUI30", "AUS200", "HKG33", "XAUUSD", "BTCRUB", "BTCCNY", "BTCUSD" // abstract
};

uint32_t peggy_mils(int32_t i)
{
    uint32_t minmils = 0;
    if ( i == 0 )
        return(1000000);
    else if ( i <= 32 )
        minmils = 10 * prices777_mindenomination(i-1);
    else if ( i >= 64 )
        return(10000);
    else if ( peggy_contracts[i] != 0 )
    {
        if ( is_decimalstr(peggy_contracts[i]+strlen(peggy_contracts[i])-2) != 0 || strcmp(peggy_contracts[i],"BTCRUB") == 0 )
            minmils = 1;
        else if ( strncmp(peggy_contracts[i],"XAU",3) == 0 || strcmp(peggy_contracts[i],"BTCCNY") == 0 || strcmp(peggy_contracts[i],"BTCUSD") == 0 || strncmp(peggy_contracts[i],"XPD",3) == 0 || strncmp(peggy_contracts[i],"XPT",3) == 0 )
            minmils = 10;
        else if ( strcmp(peggy_contracts[i],"Bund") == 0 || strcmp(peggy_contracts[i],"UKOil") == 0 || strcmp(peggy_contracts[i],"USOil") == 0 )
            minmils = 100;
        else if ( strncmp(peggy_contracts[i],"LTC",3) == 0 || strcmp(peggy_contracts[i],"SuperNET") == 0 || strncmp(peggy_contracts[i],"XAG",3) == 0 || strncmp(peggy_contracts[i],"ETH",3) == 0 || strncmp(peggy_contracts[i],"XCP",3) == 0 )
            minmils = 1000;
        else if ( strncmp(peggy_contracts[i],"XMR",3) == 0 )
            minmils = 10000;
        else if ( strncmp(peggy_contracts[i],"NXT",3) == 0 || strncmp(peggy_contracts[i],"BTS",3) == 0 )
            minmils = 1000000;
        else if ( strncmp(peggy_contracts[i],"DOGE",3) == 0 )
            minmils = 100000000;
        else minmils = 10000;
    }
    return(minmils);
}

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
    ensure_directory(path);
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
    PEGS->accts = accts777_init(path,0);
    return(PEGS);
}
//////////// end of consensus safe

int32_t peggy_prices(struct price_resolution prices[64],double btcusd,double btcdbtc,char *contracts[],int32_t num,double *cprices,double *basevals)
{
    int32_t prices777_contractnum(char *base,char *rel);
    double btcdusd,price_in_btcd,dprice,usdcny,usdrub,btccny,btcrub,xauusd,usdprice=0.,usdval,btcprice=0.; int32_t contractnum,base,nonz = 0;
    if ( btcusd > SMALLVAL && btcdbtc > SMALLVAL && (usdval= basevals[0]) > SMALLVAL )
    {
        xauusd = usdcny = usdrub = btccny = btcrub = 0.;
        for (contractnum=0; contractnum<num; contractnum++)
            if ( strcmp(contracts[contractnum],"XAUUSD") == 0 )
            {
                xauusd = cprices[contractnum];
                break;
            }
        if (  basevals[8] > SMALLVAL )
        {
            usdcny = (basevals[0] * peggy_mils(8)) / (basevals[8] * peggy_mils(0));
            btccny = 1000 * btcusd * usdcny;
        }
        if ( basevals[9] > SMALLVAL )
        {
            usdrub = (basevals[0] * peggy_mils(9)) / (basevals[9] * peggy_mils(0));
            btcrub = 1000 * btcusd * usdrub;
        }
        btcdusd = (btcusd * btcdbtc);
        printf("xauusd %f usdval %f %f %f usdcny %f usdrub %f btcusd %f btcdbtc %f btcdusd %f btccny %f btcrub %f\n",xauusd,usdval,basevals[8],basevals[9],usdcny,usdrub,btcusd,btcdbtc,btcdusd,btccny,btcrub);
        prices[0].Pval = (PRICE_RESOLUTION * 100. * btcdbtc);
        for (base=0,contractnum=1; base<32; base++,contractnum++)
        {
            if ( strcmp(contracts[contractnum],CURRENCIES[base]) == 0 )
            {
                if ( (dprice= basevals[base]) > SMALLVAL )
                {
                    nonz++;
                    if ( base == 0 )
                        usdprice = price_in_btcd = (1. / btcdusd);
                    else price_in_btcd = (dprice / (btcdusd * usdval));
                    prices[contractnum].Pval = (PRICE_RESOLUTION * price_in_btcd);
                }
            } else printf("unexpected list entry %s vs %s at %d\n",contracts[contractnum],CURRENCIES[base],contractnum);
        }
        if ( strcmp(contracts[contractnum],"BTCUSD") != 0 )
            printf("unexpected contract (%s) at %d\n",contracts[contractnum],contractnum);
        btcprice = (1. / btcdbtc);
        prices[contractnum++].Pval = (PRICE_RESOLUTION / btcdbtc) / 1000.;
        printf("btcprice %f = 1/%f %llu\n",btcprice,1./btcdbtc,(long long)prices[contractnum-1].Pval);
        for (; contractnum<64; contractnum++)
        {
            //dprice = 0;
            if ( contractnum == 63 && strcmp(contracts[contractnum],"BTCUSD") == 0 )
                dprice = btcusd;
            else if ( contractnum == 62 && strcmp(contracts[contractnum],"BTCCNY") == 0 )
                dprice = btccny;
            else if ( contractnum == 61 && strcmp(contracts[contractnum],"BTCRUB") == 0 )
                dprice = btcrub;
            else if ( contractnum == 60 && strcmp(contracts[contractnum],"XAUUSD") == 0 )
                dprice = xauusd;
            else
            {
                dprice = cprices[contractnum];
                if ( dprice > SMALLVAL && strlen(contracts[contractnum]) > 3 )
                {
                    if ( strcmp(contracts[contractnum]+strlen(contracts[contractnum])-3,"USD") == 0 || strcmp(contracts[contractnum],"Copper") == 0 || strcmp(contracts[contractnum],"NGAS") == 0 || strcmp(contracts[contractnum],"UKOil") == 0 || strcmp(contracts[contractnum],"USOil") == 0 )
                        dprice *= usdprice;
                    else if ( strcmp(contracts[contractnum],"SuperNET") == 0 )
                    {
                        printf("SuperNET %f -> %f\n",dprice,dprice*btcprice);
                        dprice *= btcprice;
                    }
                    else if ( strcmp(contracts[contractnum]+strlen(contracts[contractnum])-3,"BTC") == 0 )
                        dprice *= btcprice;
                }
            }
            prices[contractnum].Pval = (uint64_t)((PRICE_RESOLUTION * dprice) * ((double)peggy_mils(contractnum) / 10000.));
            //if ( Debuglevel > 2 )
            {
                struct price_resolution tmp;
                tmp = peggy_scaleprice(prices[contractnum],peggy_mils(contractnum));
                printf("%.8f btcprice %.6f %f -->>> %s %.6f -> %llu %.6f mils.%d\n",cprices[contractnum],btcprice,cprices[contractnum]*btcprice,contracts[contractnum],Pval(&tmp),(long long)prices[contractnum].Pval,Pval(&prices[contractnum]),peggy_mils(contractnum));
            }
        }
    }
    return(nonz);
}

char *peggy_emitprices(int32_t *nonzp,struct peggy_info *PEGS,uint32_t blocktimestamp,int32_t maxlockdays)
{
    double matrix[32][32],RTmatrix[32][32],cprices[64],basevals[64]; struct price_resolution prices[256];
    cJSON *json,*array; char *jsonstr,*opreturnstr = 0; int32_t i,nonz = 0;
    memset(cprices,0,sizeof(cprices));
    //printf("peggy_emitprices\n");
    if ( prices777_getmatrix(basevals,&PEGS->btcusd,&PEGS->btcdbtc,matrix,cprices+1,peggy_contracts+1,sizeof(peggy_contracts)/sizeof(*peggy_contracts)-1,blocktimestamp) > 0 )
    {
        cprices[0] = PEGS->btcdbtc;
        /*for (i=0; i<32; i++)
            printf("%f ",basevals[i]);
        printf("basevals\n");
        for (i=0; i<64; i++)
            printf("%f ",cprices[i]);
        printf("cprices\n");*/
        json = cJSON_CreateObject(), array = cJSON_CreateArray();
        memset(prices,0,sizeof(prices));
        memset(matrix,0,sizeof(matrix));
        memset(RTmatrix,0,sizeof(RTmatrix));
        peggy_prices(prices,PEGS->btcusd,PEGS->btcdbtc,peggy_contracts,sizeof(peggy_contracts)/sizeof(*peggy_contracts),cprices,basevals);
        for (i=0; i<sizeof(peggy_contracts)/sizeof(*peggy_contracts); i++)
        {
            jaddinum(array,prices[i].Pval);
            if ( prices[i].Pval != 0 )
                nonz++;
            if ( Debuglevel > 2 )
                printf("{%s %.6f %u}.%d ",peggy_contracts[i],Pval(&prices[i]),(uint32_t)prices[i].Pval,peggy_mils(i));
        }
        jaddnum(json,"txtype",PEGGY_TXPRICES);
        //jaddnum(json,"btcusd",btc.Pval);
        if ( maxlockdays != 0 )
        {
            jaddnum(json,"timestamp",blocktimestamp);
            jaddnum(json,"maxlockdays",maxlockdays);
        }
        //jaddstr(json,"privkey","1259ec21d31a30898d7cd1609f80d9668b4778e3d97e941044b39f0c44d2e51b");
        jadd(json,"details",array);
        jsonstr = jprint(json,1);
        //printf("%s\n",jsonstr);
        opreturnstr = peggy_tx(jsonstr);
        free(jsonstr);
    } else printf("pricematrix returned null\n");
    *nonzp = nonz;
    //printf("nonz.%d\n",nonz);
    return(opreturnstr);
}

uint64_t peggy_basebits(char *name)
{
    int32_t i; char basebuf[64],relbuf[64];
    for (i=0; i<64; i++)
    {
        if ( strcmp(name,peggy_contracts[i]) == 0 )
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
        if ( strcmp(name,peggy_contracts[i]) == 0 )
        {
            peggy_mapname(basebuf,relbuf,i);
            return(stringbits(relbuf));
        }
    }
    return(0);
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
                        PEGS->accts = accts777_init(path,0);
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
    for (i=1; i<sizeof(peggy_contracts)/sizeof(*peggy_contracts)+28; i++)
    {
        price.Pval = 0;
        if ( i < sizeof(peggy_contracts)/sizeof(*peggy_contracts) )
        {
            if ( peggy_contracts[i] == 0 )
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
        else if ( i-sizeof(peggy_contracts)/sizeof(*peggy_contracts) < PEGGY_MAXPAIREDPEGS )
        {
            extern short Contract_base[],Contract_rel[];
            maxsupply = SATOSHIDEN * 10000, maxnetbalance = SATOSHIDEN * 1000;
            mindenom.Pval = PRICE_RESOLUTION * 10;
            c = i - (int32_t)(sizeof(peggy_contracts)/sizeof(*peggy_contracts));
            strcpy(base,CURRENCIES[Contract_base[c]]), strcpy(rel,CURRENCIES[Contract_rel[c]]);
            strcpy(name,base), strcat(name,rel);
            baseid = Contract_base[c]+1, relid = Contract_rel[c]+1;
            peggymils = (PEGS->contracts[baseid]->peggymils * 10000) / PEGS->contracts[relid]->peggymils;
            if ( strcmp(PEGS->contracts[baseid]->name.base,base) == 0 && strcmp(PEGS->contracts[relid]->name.base,rel) == 0 )
                price.Pval = (PRICE_RESOLUTION * Ptx.details.price.feed[baseid]) / Ptx.details.price.feed[relid];
            else printf("mismatched %p base.(%s) baseid.%d (%s) or %p rel.(%s) relid.%d (%s)\n",PEGS->contracts[baseid],PEGS->contracts[baseid]->name.base,baseid,base,PEGS->contracts[relid],PEGS->contracts[relid]->name.base,relid,rel);
            pval = (uint32_t)price.Pval;
        } else printf("peggy_genesis RAN out of space\n");
        if ( (PEG= peggy_createpair(PEGS,0,0,name,base,rel,maxsupply,maxnetbalance,0,SATOSHIDEN*10,PEGGY_RATE_777,firsttimestamp,&price,numprices,spread,maxmargin,mindenom,i,i<sizeof(peggy_contracts)/sizeof(*peggy_contracts),peggymils)) != 0 )
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
            if ( Debuglevel > 2 )
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
    extern int32_t dailyrates[];
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
    int32_t lookbacks[OPRETURNS_CONTEXTS]; uint64_t allocsize,len; int32_t n,signedcount,valid=0; long offset; struct price_resolution tmp;
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
            if ( (opreturnstr= loadfile(&allocsize,fname)) != 0 )
            {
                //printf("loaded.(%s) %s\n",fname,opreturnstr);
                if ( is_hexstr(opreturnstr) != 0 )
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
                        fprintf(stderr,"(%s %u %.6f) ",peggy_contracts[j],Ptx.details.price.feed[j],Pval(&tmp));
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

struct peggy_info *peggy_lchain(struct txinds777_info *opreturns,char *path)
{
    double startmilli; int32_t i; struct peggy_info *tmp,*PEGS = 0;
    startmilli = milliseconds();
    printf("about to replay\n");
    for (i=0; i<1000000; i++)
    {
        if ( PEGS == 0 && (PEGS= peggy_replay(path,opreturns,PEGS,0,0,0,0)) == 0 )
            break;
        else if ( (tmp= peggy_replay(path,opreturns,PEGS,i,0,0,0)) != PEGS )
            break;
    }
    if ( PEGS != 0 )
        printf("loaded %d in %.3f millis per opreturn\n",PEGS->numopreturns,(milliseconds() - startmilli)/PEGS->numopreturns);// getchar();
    return(PEGS);
}

void norm_smooth_wts(int32_t j,double *smoothwts,int32_t n)
{
	double wt; int32_t iter,i;
	for (iter=0; iter<13; iter++)
	{
		wt = 0.;
		for (i=0; i<n; i++)
			wt += smoothwts[i];
		//printf("wtsum.j%d %.40f ",j,wt);
		for (i=0; i<n; i++)
			smoothwts[i] /= wt;
	}
	//printf("\n");
}

void calc_smooth_code(int32_t smoothwidth,int32_t _maxprimes)
{
	double _coeffs[5000],sum,coeffs[60][10000],smoothbuf[10000]; int32_t x,p,prime,numprimes; uint64_t val,isum = 0;
	_maxprimes = MIN((int32_t)(sizeof(coeffs)/(sizeof(double)*10000))-1,_maxprimes);
	smoothwidth = MIN((int32_t)(sizeof(_coeffs)/sizeof(*_coeffs)),smoothwidth);
	x = 5000;
    memset(smoothbuf,0,sizeof(smoothbuf));
	coeffs[0][x-2] = coeffs[0][x] = coeffs[0][x+2] = 1./3.;
	for (numprimes=_maxprimes; numprimes>=3; numprimes--)
	{
		for (p=1; p<numprimes; p++)
		{
			memcpy(coeffs[p],coeffs[p-1],sizeof(coeffs[p]));
			prime = smallprimes[p];
			for (x=0; x<10000; x++)
			{
				coeffs[p][x] += (coeffs[p-1][x - prime] / 3.);
				coeffs[p][x] += (coeffs[p-1][x] / 3.);
				coeffs[p][x] += (coeffs[p-1][x + prime] / 3.);
			}
		}
		memcpy(smoothbuf,coeffs[numprimes-1],sizeof(smoothbuf));
		memset(coeffs,0,sizeof(coeffs));
		sum = 0.;
		for (x=0; x<10000; x++)
		{
			if ( smoothbuf[x] != 0. )
			{
				sum += smoothbuf[x];
				//printf("(%d %f) ",x-5000,smoothbuf[x]);
			}
		}
		//printf("maxprimes.%d\n",maxprimes);
		for (x=0; x<10000; x++)
			coeffs[0][x] = (smoothbuf[x] / sum);
	}
	sum = 0.;
	for (x=0; x<10000; x++)
		sum += smoothbuf[x];
	memset(coeffs,0,sizeof(coeffs));
	if ( sum != 0. )
	{
		printf("double Smooth_coeffs[%d] =	// numprimes.%d\n{\n",smoothwidth,_maxprimes);
		for (x=0; x<10000; x++)
		{
			if ( smoothbuf[x] != 0. )
			{
				smoothbuf[x] = (1000000. * 1000000. * smoothbuf[x]) / sum;
				//printf("(%d %f) ",x-5000,smoothbuf[x]);
			}
		}
		_coeffs[0] = smoothbuf[5000];
		for (x=1; x<=smoothwidth; x++)
		{
			if ( fabs(smoothbuf[5000 - x] - smoothbuf[5000 + x]) > SMALLVAL )
				printf("x.%d error %.20f != %.20f [%.20f]\n",x,smoothbuf[5000 - x],smoothbuf[5000 + x],smoothbuf[5000 - x] - smoothbuf[5000 + x]);
			_coeffs[x-1] = (smoothbuf[5000 - x] + smoothbuf[5000 + x]) / 2.;
		}
		sum = 0.;
		for (x=0; x<smoothwidth; x++)
			sum += _coeffs[x];
		if ( sum != 0. )
		{
			for (x=0; x<smoothwidth; x++)
			{
                val = ((SATOSHIDEN * 1000. * _coeffs[x] + sum*.4825) / sum);
                printf("%lld, ",(long long)val);
                isum += val;
				//printf("%.0f, ",SATOSHIDEN*1000*_coeffs[x]/sum);
				if ( (x%9) == 8 )
					printf("// x.%d\n",x);
			}
            printf("// isum %lld\n",(long long)isum);
		}
	}
	printf("\n}; // %llu\n",(long long)isum);
	//printf("_Constants size %d\n",(int)__constant_size);
}

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

int32_t peggy_init_contexts(struct txinds777_info *opreturns,uint32_t RTblocknum,uint32_t RTblocktimestamp,char *path,void *globals[OPRETURNS_CONTEXTS],int32_t lookbacks[OPRETURNS_CONTEXTS],int32_t maxcontexts)
{
    double startmilli; char buf[512]; struct price_resolution spread; struct peggy_info *PEGS=0,*PEGS2=0;
    if ( maxcontexts != 2 )
    {
        printf("peggy needs 2 contexts\n");
        exit(-1);
    }
  //calc_smooth_code(539,13);
    if ( sizeof(Peggy_inds)/sizeof(*Peggy_inds) != PEGGY_NUMCOEFFS )
    {
        peggy_geninds();
        printf("need to update Peggy_inds with above\n");
        exit(-1);
    }
    peggy_dailyrates();
    spread.Pval = PERCENTAGE(1);
    if ( (PEGS= peggy_lchain(opreturns,"opreturns")) == 0 )
        PEGS = peggy_init(path,PEGGY_MAXLOCKDAYS,"BTCD",SATOSHIDEN/100,100,10,spread,PEGGY_RATE_777,40,10,2,5,2,0,0);
    globals[0] = PEGS;
    sprintf(buf,"%s_PERM",path);
    globals[1] = PEGS2 = peggy_init(buf,PEGGY_MAXLOCKDAYS,"BTCD",SATOSHIDEN/100,1,1,spread,PEGGY_RATE_777,40,10,2,5,2,PEGS->genesistime,PEGS->BTCD_price0);
    startmilli = milliseconds();
    peggy_clone(buf,PEGS2,PEGS);
    printf("cloned %d in %.3f millis per opreturn\n",PEGS->numopreturns,(milliseconds() - startmilli)/PEGS->numopreturns); sleep(3);
    return(2);
}

#endif
#endif
#include <stdint.h>
extern int32_t Debuglevel;

#endif
