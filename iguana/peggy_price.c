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

#define _extrapolate_Spline(Splines,gap) ((double)(Splines)[0] + ((gap) * ((double)(Splines)[1] + ((gap) * ((double)(Splines)[2] + ((gap) * (double)(Splines)[3]))))))
#define _extrapolate_Slope(Splines,gap) ((double)(Splines)[1] + ((gap) * ((double)(Splines)[2] + ((gap) * (double)(Splines)[3]))))

#define PRICE_BLEND(oldval,newval,decay,oppodecay) ((oldval == 0.) ? newval : ((oldval * decay) + (oppodecay * newval)))
#define PRICE_BLEND64(oldval,newval,decay,oppodecay) ((oldval == 0) ? newval : ((oldval * decay) + (oppodecay * newval) + 0.499))

#define dto64(x) ((int64_t)((x) * (double)SATOSHIDEN * SATOSHIDEN))
#define dto32(x) ((int32_t)((x) * (double)SATOSHIDEN))
#define i64tod(x) ((double)(x) / ((double)SATOSHIDEN * SATOSHIDEN))
#define i32tod(x) ((double)(x) / (double)SATOSHIDEN)
#define _extrapolate_spline64(spline64,gap) ((double)i64tod((spline64)[0]) + ((gap) * ((double)i64tod(.001*.001*(spline64)[1]) + ((gap) * ((double)i64tod(.001*.001*.001*.001*(spline64)[2]) + ((gap) * (double)i64tod(.001*.001*.001*.001*.001*.001*(spline64)[3])))))))
#define _extrapolate_spline32(spline32,gap) ((double)i32tod((spline32)[0]) + ((gap) * ((double)i32tod(.001*.001*(spline32)[1]) + ((gap) * ((double)i32tod(.001*.001*.001*.001*(spline32)[2]) + ((gap) * (double)i32tod(.001*.001*.001*.001*.001*.001*(spline32)[3])))))))

static char *Yahoo_metals[] = { YAHOO_METALS };
uint64_t Currencymasks[NUM_CURRENCIES+1];

short Contract_base[NUM_COMBINED+1] = { 7, 7, 7, 7, 3, 1, 4, 5, 5, 0, 1, 3, 4, 0, 6, 1, 3, 4, 1, 1, 1, 1, 3, 3, 3, 0, 4, 4, 0,1,2,3,4,5,6,7, 8 };// Contract_base };
short  Contract_rel[NUM_COMBINED+1] = { 0, 6, 5, 2, 7, 7, 7, 2, 6, 5, 5, 5, 5, 6, 2, 6, 6, 6, 0, 4, 2, 3, 0, 2, 4, 2, 2, 0, 0,1,2,3,4,5,6,7,8 };// Contract_rel

short Baserel_contractdir[NUM_CURRENCIES+1][NUM_CURRENCIES+1] =
{
	{  1, -1,  1, -1, -1,  1,  1, -1, -1 },
	{  1,  1,  1,  1,  1,  1,  1,  1, -1 },
	{ -1, -1,  1, -1, -1, -1, -1, -1,  0 },
	{  1, -1,  1,  1,  1,  1,  1,  1, -1 },
	{  1, -1,  1, -1,  1,  1,  1,  1, -1 },
	{ -1, -1,  1, -1, -1,  1,  1, -1,  0 },
	{ -1, -1,  1, -1, -1, -1,  1, -1, -1 },
	{  1, -1,  1, -1, -1,  1,  1,  1,  0 },
	{ -1, -1,  0, -1, -1,  0, -1,  0,  1 },
};

short Currency_contracts[NUM_CURRENCIES+1][NUM_CURRENCIES] =
{
	{  0,  9, 13, 18, 22, 25, 27, 28, },
	{  5, 10, 15, 18, 19, 20, 21, 29, },
	{  3,  7, 14, 20, 23, 25, 26, 30, },
	{  4, 11, 16, 21, 22, 23, 24, 31, },
	{  6, 12, 17, 19, 24, 26, 27, 32, },
	{  2,  7,  8,  9, 10, 11, 12, 33, },
	{  1,  8, 13, 14, 15, 16, 17, 34, },
	{  0,  1,  2,  3,  4,  5,  6, 35, },
	{ 36, 37, -1, 38, 39, -1, 40, 41, },
};

short Currency_contractothers[NUM_CURRENCIES+1][NUM_CURRENCIES] =	// buggy!
{
	{ 7, 5, 6, 1, 3, 2, 4, 0, },
	{ 7, 5, 6, 0, 4, 2, 3, 1, },
	{ 7, 5, 6, 1, 3, 0, 4, 2, },
	{ 7, 5, 6, 1, 0, 2, 4, 3, },
	{ 7, 5, 6, 1, 3, 2, 0, 4, },
	{ 7, 2, 6, 0, 1, 3, 4, 5, },
	{ 7, 5, 0, 2, 1, 3, 4, 6, },
	{ 0, 6, 5, 2, 1, 3, 4, 7, },
	{ 0, 1,-1, 3, 4,-1, 5,-1, },
};

int32_t MINDENOMS[] = { 1000, 1000, 100000, 1000, 1000, 1000, 1000, 1000, // major currencies
    10000, 100000, 10000, 1000, 100000, 10000, 1000, 10000, 1000, 10000, 10000, 10000, 10000, 100000, 1000, 1000000, 1000, 10000, 1000, 1000, 10000, 1000, 10000000, 10000, // end of currencies
    1, 100, 1, 1, // metals, gold must be first
    1, 10, 100000, 100, 100, 10000000, 10000, 1000, 1000,  1000, 100000, 100000, 1000000 // cryptos
};

int32_t PAX_mindenomination(int32_t base)
{
    return(MINDENOMS[base]);
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

uint32_t peggy_mils(int32_t i)
{
    uint32_t minmils = 0;
    if ( i == 0 )
        return(1000000);
    else if ( i <= 32 )
        minmils = 10 * PAX_mindenomination(i-1);
    else if ( i >= 64 )
        return(10000);
    else if ( peggy_bases[i] != 0 )
    {
        if ( is_decimalstr(peggy_bases[i]+strlen(peggy_bases[i])-2) != 0 || strcmp(peggy_bases[i],"BTCRUB") == 0 )
            minmils = 1;
        else if ( strncmp(peggy_bases[i],"XAU",3) == 0 || strcmp(peggy_bases[i],"BTCCNY") == 0 || strcmp(peggy_bases[i],"BTCUSD") == 0 || strncmp(peggy_bases[i],"XPD",3) == 0 || strncmp(peggy_bases[i],"XPT",3) == 0 )
            minmils = 10;
        else if ( strcmp(peggy_bases[i],"BUND") == 0 || strcmp(peggy_bases[i],"UKOIL") == 0 || strcmp(peggy_bases[i],"USOIL") == 0 )
            minmils = 100;
        else if ( strncmp(peggy_bases[i],"LTC",3) == 0 || strcmp(peggy_bases[i],"SuperNET") == 0 || strncmp(peggy_bases[i],"XAG",3) == 0 || strncmp(peggy_bases[i],"ETH",3) == 0 || strncmp(peggy_bases[i],"XCP",3) == 0 )
            minmils = 1000;
        else if ( strncmp(peggy_bases[i],"XMR",3) == 0 )
            minmils = 10000;
        else if ( strncmp(peggy_bases[i],"NXT",3) == 0 || strncmp(peggy_bases[i],"BTS",3) == 0 )
            minmils = 1000000;
        else if ( strncmp(peggy_bases[i],"DOGE",3) == 0 )
            minmils = 100000000;
        else minmils = 10000;
    }
    return(minmils);
}

int32_t peggy_prices(struct price_resolution prices[64],double btcusd,double btcdbtc,char *contracts[],int32_t num,double *cprices,double *basevals)
{
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
                    if ( strcmp(contracts[contractnum]+strlen(contracts[contractnum])-3,"USD") == 0 || strcmp(contracts[contractnum],"COPPER") == 0 || strcmp(contracts[contractnum],"NGAS") == 0 || strcmp(contracts[contractnum],"UKOIL") == 0 || strcmp(contracts[contractnum],"USOIL") == 0 )
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

void init_Currencymasks()
{
	int32_t base,j,c; uint64_t basemask;
	for (base=0; base<NUM_CURRENCIES; base++)
	{
		basemask = 0L;
		for (j=0; j<7; j++)
		{
			if ( (c= Currency_contracts[base][j]) >= 0 )
			{
				basemask |= (1L << c);
				//printf("(%s %lx) ",CONTRACTS[c],1L<<c);
			}
		}
		Currencymasks[base] = basemask;
		printf("0x%llx, ",(long long)basemask);
	}
}

double calc_primary_currencies(double logmatrix[8][8],double *bids,double *asks)
{
	uint64_t nonzmask; int32_t c,base,rel; double bid,ask;
	memset(logmatrix,0,sizeof(double)*8*8);
	nonzmask = 0;
	for (c=0; c<28; c++)
	{
		bid = bids[c];
		ask = asks[c];
		if ( bid != 0 && ask != 0 )
		{
			base = Contract_base[c];
			rel = Contract_rel[c];
			nonzmask |= (1L << c);
			logmatrix[base][rel] = log(bid);
			logmatrix[rel][base] = -log(ask);
			//printf("[%f %f] ",bid,ask);
		}
	}
	//printf("%07lx\n",nonzmask);
	if ( nonzmask != 0 )
	{
		bids[USDNUM] = (logmatrix[USD][EUR] + logmatrix[USD][JPY] + logmatrix[USD][GBP] + logmatrix[USD][AUD] + logmatrix[USD][CAD] + logmatrix[USD][CHF] + logmatrix[USD][NZD]) / 8.;
		asks[USDNUM] = -(logmatrix[EUR][USD] + logmatrix[JPY][USD] + logmatrix[GBP][USD] + logmatrix[AUD][USD] + logmatrix[CAD][USD] + logmatrix[CHF][USD] + logmatrix[NZD][USD]) / 8.;
        
		bids[EURNUM] = (logmatrix[EUR][USD] + logmatrix[EUR][JPY] + logmatrix[EUR][GBP] + logmatrix[EUR][AUD] + logmatrix[EUR][CAD] + logmatrix[EUR][CHF] + logmatrix[EUR][NZD]) / 8.;
		asks[EURNUM] = -(logmatrix[USD][EUR] + logmatrix[JPY][EUR] + logmatrix[GBP][EUR] + logmatrix[AUD][EUR] + logmatrix[CAD][EUR] + logmatrix[CHF][EUR] + logmatrix[NZD][EUR]) / 8.;
        
		bids[JPYNUM] = (logmatrix[JPY][USD] + logmatrix[JPY][EUR] + logmatrix[JPY][GBP] + logmatrix[JPY][AUD] + logmatrix[JPY][CAD] + logmatrix[JPY][CHF] + logmatrix[JPY][NZD]) / 8.;
		asks[JPYNUM] = -(logmatrix[USD][JPY] + logmatrix[EUR][JPY] + logmatrix[GBP][JPY] + logmatrix[AUD][JPY] + logmatrix[CAD][JPY] + logmatrix[CHF][JPY] + logmatrix[NZD][JPY]) / 8.;
        
		bids[GBPNUM] = (logmatrix[GBP][USD] + logmatrix[GBP][EUR] + logmatrix[GBP][JPY] + logmatrix[GBP][AUD] + logmatrix[GBP][CAD] + logmatrix[GBP][CHF] + logmatrix[GBP][NZD]) / 8.;
		asks[GBPNUM] = -(logmatrix[USD][GBP] + logmatrix[EUR][GBP] + logmatrix[JPY][GBP] + logmatrix[AUD][GBP] + logmatrix[CAD][GBP] + logmatrix[CHF][GBP] + logmatrix[NZD][GBP]) / 8.;
        
		bids[AUDNUM] = (logmatrix[AUD][USD] + logmatrix[AUD][EUR] + logmatrix[AUD][JPY] + logmatrix[AUD][GBP] + logmatrix[AUD][CAD] + logmatrix[AUD][CHF] + logmatrix[AUD][NZD]) / 8.;
		asks[AUDNUM] = -(logmatrix[USD][AUD] + logmatrix[EUR][AUD] + logmatrix[JPY][AUD] + logmatrix[GBP][AUD] + logmatrix[CAD][AUD] + logmatrix[CHF][AUD] + logmatrix[NZD][AUD]) / 8.;
        
		bids[CADNUM] = (logmatrix[CAD][USD] + logmatrix[CAD][EUR] + logmatrix[CAD][JPY] + logmatrix[CAD][GBP] + logmatrix[CAD][AUD] + logmatrix[CAD][CHF] + logmatrix[CAD][NZD]) / 8.;
		asks[CADNUM] = -(logmatrix[USD][CAD] + logmatrix[EUR][CAD] + logmatrix[JPY][CAD] + logmatrix[GBP][CAD] + logmatrix[AUD][CAD] + logmatrix[CHF][CAD] + logmatrix[NZD][CAD]) / 8.;
        
		bids[CHFNUM] = (logmatrix[CHF][USD] + logmatrix[CHF][EUR] + logmatrix[CHF][JPY] + logmatrix[CHF][GBP] + logmatrix[CHF][AUD] + logmatrix[CHF][CAD] + logmatrix[CHF][NZD]) / 8.;
		asks[CHFNUM] = -(logmatrix[USD][CHF] + logmatrix[EUR][CHF] + logmatrix[JPY][CHF] + logmatrix[GBP][CHF] + logmatrix[AUD][CHF] + logmatrix[CAD][CHF] + logmatrix[NZD][CHF]) / 8.;
        
		bids[NZDNUM] = (logmatrix[NZD][USD] + logmatrix[NZD][EUR] + logmatrix[NZD][JPY] + logmatrix[NZD][GBP] + logmatrix[NZD][AUD] + logmatrix[NZD][CAD] + logmatrix[NZD][CHF]) / 8.;
		asks[NZDNUM] = -(logmatrix[USD][NZD] + logmatrix[EUR][NZD] + logmatrix[JPY][NZD] + logmatrix[GBP][NZD] + logmatrix[AUD][NZD] + logmatrix[CAD][NZD] + logmatrix[CHF][NZD]) / 8.;
		if ( nonzmask != ((1<<28)-1) )
		{
			for (base=0; base<8; base++)
			{
				if ( (nonzmask & Currencymasks[base]) != Currencymasks[base] )
					bids[base+28] = asks[base+28] = 0;
				//else printf("%s %9.6f | ",CONTRACTS[base+28],_pairaved(bids[base+28],asks[base+28]));
			}
			//printf("keep.%07lx\n",nonzmask);
			return(0);
		}
		if ( 0 && nonzmask != 0 )
		{
			for (base=0; base<8; base++)
				printf("%9.6f | ",_pairaved(bids[base+28],asks[base+28]));
			printf("%07llx\n",(long long)nonzmask);
		}
	}
	return(0);
}

double PAX_splineval(struct PAX_spline *spline,uint32_t timestamp,int32_t lookahead)
{
    int32_t i,gap,ind = (spline->num - 1);
    if ( timestamp >= spline->utc32[ind] )
    {
        gap = (timestamp - spline->utc32[ind]);
        if ( gap < lookahead )
            return(_extrapolate_spline64(spline->spline64[ind],gap));
        else return(0.);
    }
    else if ( timestamp <= spline->utc32[0] )
    {
        gap = (spline->utc32[0] - timestamp);
        if ( gap < lookahead )
            return(_extrapolate_spline64(spline->spline64[0],gap));
        else return(0.);
    }
    for (i=0; i<spline->num-1; i++)
    {
        ind = (i + spline->lasti) % (spline->num - 1);
        if ( timestamp >= spline->utc32[ind] && timestamp < spline->utc32[ind+1] )
        {
            spline->lasti = ind;
            return(_extrapolate_spline64(spline->spline64[ind],timestamp - spline->utc32[ind]));
        }
    }
    return(0.);
}

double PAX_calcspline(struct PAX_spline *spline,double *outputs,double *slopes,int32_t dispwidth,uint32_t *utc32,double *splinevals,int32_t num)
{
    static double errsums[3]; static int errcount;
	double c[MAX_SPLINES],f[MAX_SPLINES],dd[MAX_SPLINES],dl[MAX_SPLINES],du[MAX_SPLINES],gaps[MAX_SPLINES];
	int32_t n,i,lasti,x,numsplines,nonz; double vx,vy,vw,vz,gap,sum,xval,yval,abssum,lastval,lastxval,yval64,yval32,yval3; uint32_t gap32;
	sum = lastxval = n = lasti = nonz = 0;
	for (i=0; i<MAX_SPLINES&&i<num; i++)
	{
		if ( (f[n]= splinevals[i]) != 0. && utc32[i] != 0 )
		{
			//printf("i%d.(%f %f) ",i,utc[i],splinevals[i]);
			if ( n > 0 )
			{
				if ( (gaps[n-1]= utc32[i] - lastxval) < 0 )
				{
					printf("illegal gap %f to t%d\n",lastxval,utc32[i]);
					return(0);
				}
			}
			spline->utc32[n] = lastxval = utc32[i];
            n++;
		}
	}
	if ( (numsplines= n) < 4 )
		return(0);
	for (i=0; i<n-3; i++)
		dl[i] = du[i] = gaps[i+1];
	for (i=0; i<n-2; i++)
	{
		dd[i] = 2.0 * (gaps[i] + gaps[i+1]);
		c[i]  = (3.0 / (double)gaps[i+1]) * (f[i+2] - f[i+1]) - (3.0 / (double)gaps[i]) * (f[i+1] - f[i]);
	}
	//for (i=0; i<n; i++) printf("%f ",f[i]);
	//printf("F2[%d]\n",n);
	dd[0] += (gaps[0] + (double)gaps[0]*gaps[0] / gaps[1]);
	du[0] -= ((double)gaps[0]*gaps[0] / gaps[1]);
	dd[n-3] += (gaps[n-2] + (double)gaps[n-2]*gaps[n-2] / gaps[n-3]);
	dl[n-4] -= ((double)gaps[n-2]*gaps[n-2] / gaps[n-3]);
	
	//tridiagonal(n-2, dl, dd, du, c);
	for (i=0; i<n-1-2; i++)
	{
		du[i] /= dd[i];
		dd[i+1] -= dl[i]*du[i];
	}
	c[0] /= dd[0];
	for (i=1; i<n-2; i++)
		c[i] = (c[i] - dl[i-1] * c[i-1]) / dd[i];
	for (i=n-2-4; i>=0; i--)
		c[i] -= c[i+1] * du[i];
	//tridiagonal(n-2, dl, dd, du, c);
	
	for (i=n-3; i>=0; i--)
		c[i+1] = c[i];
	c[0] = (1.0 + (double)gaps[0] / gaps[1]) * c[1] - ((double)gaps[0] / gaps[1] * c[2]);
	c[n-1] = (1.0 + (double)gaps[n-2] / gaps[n-3] ) * c[n-2] - ((double)gaps[n-2] / gaps[n-3] * c[n-3]);
    //printf("c[n-1] %f, n-2 %f, n-3 %f\n",c[n-1],c[n-2],c[n-3]);
	abssum = nonz = lastval = 0;
    outputs[spline->firstx] = f[0];
    spline->num = numsplines;
    for (i=0; i<n; i++)
	{
        vx = f[i];
        vz = c[i];
        if ( i < n-1 )
        {
     		gap = gaps[i];
            vy = ((f[i+1] - f[i]) / gap) - (gap * (c[i+1] + 2.*c[i]) / 3.);
            vw = (c[i+1] - c[i]) / (3. * gap);
        }
        else
        {
            vy = 0;
            vw = 0;
        }
		//printf("%3d: t%u [%14.11f %14.11f %14.11f %14.11f] gap %f | %d\n",i,spline->utc32[i],(vx),vy*1000*1000,vz*1000*1000*1000*1000,vw*1000*1000*1000*1000*1000*1000,gap,conv_unixtime(&tmp,spline->utc32[i]));
		spline->dSplines[i][0] = vx, spline->dSplines[i][1] = vy, spline->dSplines[i][2] = vz, spline->dSplines[i][3] = vw;
		spline->spline64[i][0] = dto64(vx), spline->spline64[i][1] = dto64(vy*1000*1000), spline->spline64[i][2] = dto64(vz*1000*1000*1000*1000), spline->spline64[i][3] = dto64(vw*1000*1000*1000*1000*1000*1000);
		spline->spline32[i][0] = dto32(vx), spline->spline32[i][1] = dto32(vy*1000*1000), spline->spline32[i][2] = dto32(vz*1000*1000*1000*1000), spline->spline32[i][3] = dto32(vw*1000*1000*1000*1000*1000*1000);
		gap32 = gap = spline->dispincr;
		xval = spline->utc32[i] + gap;
		lastval = vx;
		while ( i < n-1 )
		{
			x = spline->firstx + ((xval - spline->utc32[0]) / spline->dispincr);
			if ( x > dispwidth-1 ) x = dispwidth-1;
			if ( x < 0 ) x = 0;
			if ( (i < n-2 && gap > gaps[i] + spline->dispincr) )
				break;
            if ( i == n-2 && xval > spline->utc32[n-1] + MAX_LOOKAHEAD*spline->dispincr )
            {
                //printf("x.%d dispwidth.%d xval %f > utc[n-1] %f + %f\n",x,dispwidth,xval,utc[n-1],MAX_LOOKAHEAD*incr);
                break;
            }
            if ( x >= 0 )
			{
				yval = _extrapolate_Spline(spline->dSplines[i],gap);
				yval64 = _extrapolate_spline64(spline->spline64[i],gap32);
                if ( (yval3 = PAX_splineval(spline,gap32 + spline->utc32[i],MAX_LOOKAHEAD*spline->dispincr)) != 0 )
                {
                    yval32 = _extrapolate_spline32(spline->spline32[i],gap32);
                    errsums[0] += fabs(yval - yval64), errsums[1] += fabs(yval - yval32), errsums[2] += fabs(yval - yval3), errcount++;
                    if ( fabs(yval - yval3) > SMALLVAL )
                        printf("(%.10f vs %.10f %.10f %.10f [%.16f %.16f %.16f]) ",yval,yval64,yval32,yval3, errsums[0]/errcount,errsums[1]/errcount,errsums[2]/errcount);
                }
				if ( yval > 5000. ) yval = 5000.;
				else if ( yval < -5000. ) yval = -5000.;
				if ( isnan(yval) == 0 )
				{
					outputs[x] = yval;
                    spline->lastval = outputs[x], spline->lastutc = xval;
                    if ( 1 && fabs(lastval) > SMALLVAL )
					{
						if ( lastval != 0 && outputs[x] != 0 )
						{
                            if ( slopes != 0 )
                                slopes[x] = (outputs[x] - lastval), abssum += fabs(slopes[x]);
							nonz++;
						}
					}
				}
				//else outputs[x] = 0.;
				//printf("x.%-4d %d %f %f %f i%-4d: gap %9.6f %9.6f last %9.6f slope %9.6f | %9.1f [%9.1f %9.6f %9.6f %9.6f %9.6f]\n",x,firstx,xval,utc[0],incr,i,gap,yval,lastval,slopes[x],xval,utc[i+1],dSplines[i][0],dSplines[i][1]*1000*1000,dSplines[i][2]*1000*1000*1000*1000,dSplines[i][3]*1000*1000*1000*1000*1000*1000);
			}
			gap32 += spline->dispincr, gap += spline->dispincr, xval += spline->dispincr;
		}
		//double pred = (i>0) ? _extrapolate_Spline(dSplines[i-1],gaps[i-1]) : 0.;
		//printf("%2d: w%8.1f [gap %f -> %9.6f | %9.6f %9.6f %9.6f %9.6f %9.6f]\n",i,weekinds[i],gap,pred,f[i],dSplines[i].x,1000000*dSplines[i].y,1000000*1000000*dSplines[i].z,1000000*1000000*1000*dSplines[i].w);
	}
	if ( nonz != 0 )
		abssum /= nonz;
	spline->aveslopeabs = abssum;
	return(lastval);
}

int32_t PAX_genspline(struct PAX_spline *spline,int32_t splineid,char *name,uint32_t *utc32,double *splinevals,int32_t maxsplines,double *refvals)
{
    int32_t i; double output[2048],slopes[2048],origvals[MAX_SPLINES];
    memset(spline,0,sizeof(*spline)), memset(output,0,sizeof(output)), memset(slopes,0,sizeof(slopes));
    spline->dispincr = 3600, spline->basenum = splineid, strcpy(spline->name,name);
    memcpy(origvals,splinevals,sizeof(*splinevals) * MAX_SPLINES);
    spline->lastval = PAX_calcspline(spline,output,slopes,sizeof(output)/sizeof(*output),utc32,splinevals,maxsplines);
    for (i=0; i<spline->num+3; i++)
    {
        if ( i < spline->num )
        {
            if ( refvals[i] != 0 && output[i * 24] != refvals[i] )
                printf("{%.8f != %.8f}.%d ",output[i * 24],refvals[i],i);
        }
        else printf("{%.8f %.3f} ",output[i * 24],slopes[i * 24]/spline->aveslopeabs);
        spline->pricevals[i] = output[i * 24];
    }
    printf("spline.%s num.%d\n",name,spline->num);
    return(spline->num);
}

int32_t PAX_calcmatrix(double matrix[32][32])
{
    int32_t basenum,relnum,nonz,vnum,iter,numbase,numerrs = 0; double sum,vsum,price,price2,basevals[32],errsum=0;
    memset(basevals,0,sizeof(basevals));
    for (iter=0; iter<2; iter++)
    {
        numbase = 32;
        for (basenum=0; basenum<numbase; basenum++)
        {
            for (vsum=sum=vnum=nonz=relnum=0; relnum<numbase; relnum++)
            {
                if ( basenum != relnum )
                {
                    if ( (price= matrix[basenum][relnum]) != 0. )
                    {
                        price /= (MINDENOMS[relnum] * .001);
                        price *= (MINDENOMS[basenum] * .001);
                        if ( iter == 0 )
                            sum += (price), nonz++;//, printf("%.8f ",price);
                        else sum += fabs((price) - (basevals[basenum] / basevals[relnum])), nonz++;
                    }
                    if ( (price2= matrix[relnum][basenum]) != 0. )
                    {
                        price2 *= (MINDENOMS[relnum] * .001);
                        price2 /= (MINDENOMS[basenum] * .001);
                        if ( iter == 0 )
                            vsum += (price2), vnum++;
                        else vsum += fabs(price2 - (basevals[relnum] / basevals[basenum])), vnum++;
                    }
                    //if ( iter == 0 && 1/price2 > price )
                    //    printf("base.%d rel.%d price2 %f vs %f\n",basenum,relnum,1/price2,price);
                }
            }
            if ( iter == 0 )
                sum += 1., vsum += 1.;
            if ( nonz != 0 )
                sum /= nonz;
            if ( vnum != 0 )
                vsum /= vnum;
            if ( iter == 0 )
                basevals[basenum] = (sum + 1./vsum) / 2.;
            else errsum += (sum + vsum)/2, numerrs++;//, printf("(%.8f %.8f) ",sum,vsum);
            //printf("date.%d (%.8f/%d %.8f/%d).%02d -> %.8f\n",i,sum,nonz,vsum,vnum,basenum,basevals[basenum]);
        }
        if ( iter == 0 )
        {
            for (sum=relnum=0; relnum<numbase; relnum++)
                sum += (basevals[relnum]);//, printf("%.8f ",(basevals[relnum]));
            //printf("date.%d sums %.8f and vsums iter.%d\n",i,sum/7,iter);
            sum /= (numbase - 1);
            for (relnum=0; relnum<numbase; relnum++)
                basevals[relnum] /= sum;//, printf("%.8f ",basevals[relnum]);
            //printf("date.%d sums %.8f and vsums iter.%d\n",i,sum,iter);
        }
        else
        {
            for (basenum=0; basenum<numbase; basenum++)
                matrix[basenum][basenum] = basevals[basenum];
        }
    }
    if ( numerrs != 0 )
        errsum /= numerrs;
    return(errsum);
}

int32_t PAX_getmatrix(double *basevals,struct peggy_info *PEGS,double Hmatrix[32][32],double *RTprices,char *contracts[],int32_t num,uint32_t timestamp)
{
    int32_t i,j,c; char name[16]; double btcusd,btcdbtc;
    memcpy(Hmatrix,PEGS->data.ecbmatrix,sizeof(PEGS->data.ecbmatrix));
    PAX_calcmatrix(Hmatrix);
    /*for (i=0; i<32; i++)
     {
     for (j=0; j<32; j++)
     printf("%.6f ",Hmatrix[i][j]);
     printf("%s\n",CURRENCIES[i]);
     }*/
    btcusd = PEGS->data.btcusd;
    btcdbtc = PEGS->data.btcdbtc;
    if ( btcusd > SMALLVAL )
        dxblend(&PEGS->btcusd,btcusd,.9);
    if ( btcdbtc > SMALLVAL )
        dxblend(&PEGS->btcdbtc,btcdbtc,.9);
    // char *cryptostrs[8] = { "btc", "nxt", "unity", "eth", "ltc", "xmr", "bts", "xcp" };
    // "BTCUSD", "NXTBTC", "SuperNET", "ETHBTC", "LTCBTC", "XMRBTC", "BTSBTC", "XCPBTC",  // BTC priced
    for (i=0; i<num; i++)
    {
        if ( contracts[i] == 0 )
            continue;
        if ( i == num-1 && strcmp(contracts[i],"BTCUSD") == 0 )
        {
            RTprices[i] = PEGS->btcusd;
            continue;
        }
        else if ( i == num-2 && strcmp(contracts[i],"BTCCNY") == 0 )
        {
            continue;
        }
        else if ( i == num-3 && strcmp(contracts[i],"BTCRUB") == 0 )
        {
            continue;
        }
        else if ( i == num-4 && strcmp(contracts[i],"XAUUSD") == 0 )
        {
            continue;
        }
        if ( strcmp(contracts[i],"NXTBTC") == 0 )
            RTprices[i] = PEGS->data.cryptos[1];
        else if ( strcmp(contracts[i],"SuperNET") == 0 )
            RTprices[i] = PEGS->data.cryptos[2];
        else if ( strcmp(contracts[i],"ETHBTC") == 0 )
            RTprices[i] = PEGS->data.cryptos[3];
        else if ( strcmp(contracts[i],"LTCBTC") == 0 )
            RTprices[i] = PEGS->data.cryptos[4];
        else if ( strcmp(contracts[i],"XMRBTC") == 0 )
            RTprices[i] = PEGS->data.cryptos[5];
        else if ( strcmp(contracts[i],"BTSBTC") == 0 )
            RTprices[i] = PEGS->data.cryptos[6];
        else if ( strcmp(contracts[i],"XCPBTC") == 0 )
            RTprices[i] = PEGS->data.cryptos[7];
        else if ( i < 32 )
        {
            basevals[i] = Hmatrix[i][i];
            //if ( Debuglevel > 2 )
            printf("(%s %f).%d ",CURRENCIES[i],basevals[i],i);
        }
        else if ( (c= PAX_contractnum(contracts[i],0)) >= 0 )
        {
            RTprices[i] = PEGS->data.RTprices[c];
            //if ( is_decimalstr(contracts[i]+strlen(contracts[i])-2) != 0 )
            //    cprices[i] *= .0001;
        }
        else
        {
            for (j=0; j<sizeof(Yahoo_metals)/sizeof(*Yahoo_metals); j++)
            {
                sprintf(name,"%sUSD",Yahoo_metals[j]);
                if ( contracts[i] != 0 && strcmp(name,contracts[i]) == 0 )
                {
                    RTprices[i] = PEGS->data.RTmetals[j];
                    break;
                }
            }
        }
        //if ( Debuglevel > 2 )
        printf("(%f %f) i.%d num.%d %s %f\n",PEGS->btcusd,PEGS->btcdbtc,i,num,contracts[i],RTprices[i]);
        //printf("RT.(%s %f) ",contracts[i],RTprices[i]);
    }
    return(PEGS->data.ecbdatenum);
}

char *peggy_emitprices(int32_t *nonzp,struct peggy_info *PEGS,uint32_t blocktimestamp,int32_t maxlockdays)
{
    double matrix[32][32],RTmatrix[32][32],cprices[64],basevals[64]; struct price_resolution prices[256];
    cJSON *json,*array; char *jsonstr,*opreturnstr = 0; int32_t i,nonz = 0;
    memset(cprices,0,sizeof(cprices));
    //printf("peggy_emitprices\n");
    if ( PAX_getmatrix(basevals,PEGS,matrix,cprices+1,peggy_bases+1,sizeof(peggy_bases)/sizeof(*peggy_bases)-1,blocktimestamp) > 0 )
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
        peggy_prices(prices,PEGS->btcusd,PEGS->btcdbtc,peggy_bases,sizeof(peggy_bases)/sizeof(*peggy_bases),cprices,basevals);
        for (i=0; i<sizeof(peggy_bases)/sizeof(*peggy_bases); i++)
        {
            jaddinum(array,prices[i].Pval);
            if ( prices[i].Pval != 0 )
                nonz++;
            //if ( Debuglevel > 2 )
            printf("{%s %.6f %u}.%d ",peggy_bases[i],Pval(&prices[i]),(uint32_t)prices[i].Pval,peggy_mils(i));
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

double PAX_baseprice(struct peggy_info *PEGS,uint32_t timestamp,int32_t basenum)
{
    double btc,btcd,btcdusd,usdval;
    btc = 1000. * _pairaved(PAX_splineval(&PEGS->splines[MAX_CURRENCIES+0],timestamp,0),PAX_splineval(&PEGS->splines[MAX_CURRENCIES+1],timestamp,0));
    btcd = .01 * PAX_splineval(&PEGS->splines[MAX_CURRENCIES+2],timestamp,0);
    if ( btc != 0. && btcd != 0. )
    {
        btcdusd = (btc * btcd);
        usdval = PAX_splineval(&PEGS->splines[USD],timestamp,0);
        if ( basenum == USD )
            return(1. / btcdusd);
        else return(PAX_splineval(&PEGS->splines[basenum],timestamp,0) / (btcdusd * usdval));
    }
    return(0.);
}

double PAX_getprice(char *retbuf,char *base,char *rel,char *contract,struct peggy_info *PEGS)
{
    int32_t i,c,basenum,relnum,n = 0; double yprice,daily,revdaily,price;
    struct PAX_data *dp = &PEGS->data;
    price = yprice = daily = revdaily = 0.;
    PAX_ispair(base,rel,contract);
    if ( base[0] != 0 && rel[0] != 0 )
    {
        basenum = PAX_basenum(base), relnum = PAX_basenum(rel);
        if ( basenum >= 0 && relnum >= 0 && basenum < MAX_CURRENCIES && relnum < MAX_CURRENCIES )
            daily = dp->dailyprices[basenum*MAX_CURRENCIES + relnum], revdaily = dp->dailyprices[relnum*MAX_CURRENCIES + basenum];
    }
    for (i=0; i<sizeof(Yahoo_metals)/sizeof(*Yahoo_metals); i++)
        if ( strncmp(Yahoo_metals[i],contract,3) == 0 && strcmp(contract+3,"USD") == 0 )
        {
            yprice = dp->metals[i];
            break;
        }
    sprintf(retbuf,"{\"result\":\"success\",\"contract\":\"%s\",\"base\":\"%s\",\"rel\":\"%s\"",contract,base,rel);
    if ( (c= PAX_contractnum(contract,0)) >= 0 )
    {
        if ( dp->tbids[c] != 0. && dp->tasks[c] != 0. )
        {
            price += (dp->tbids[c] + dp->tasks[c]), n += 2;
            sprintf(retbuf+strlen(retbuf),",\"truefx\":{\"timestamp\":\"%u\",\"bid\":%.8f,\"ask\":%.8f}",dp->ttimestamps[c],dp->tbids[c],dp->tasks[c]);
        }
        if ( dp->fbids[c] != 0. && dp->fasks[c] != 0. )
        {
            price += (dp->fbids[c] + dp->fasks[c]), n += 2;
            sprintf(retbuf+strlen(retbuf),",\"fxcm\":{\"bid\":%.8f,\"ask\":%.8f}",dp->fbids[c],dp->fasks[c]);
        }
        if ( dp->ibids[c] != 0. && dp->iasks[c] != 0. )
        {
            price += (dp->ibids[c] + dp->iasks[c]), n += 2;
            sprintf(retbuf+strlen(retbuf),",\"instaforex\":{\"timestamp\":%u,\"bid\":%.8f,\"ask\":%.8f}",dp->itimestamps[c],dp->ibids[c],dp->iasks[c]);
        }
        if ( yprice != 0. )
            sprintf(retbuf+strlen(retbuf),",\"yahoo\":{\"price\":%.8f}",yprice);
        if ( daily != 0. || revdaily != 0. )
            sprintf(retbuf+strlen(retbuf),",\"ecb\":{\"date\":\"%s\",\"daily\":%.8f,\"reverse\":%.8f}",dp->edate,daily,revdaily);
    }
    if ( n > 0 )
        price /= n;
    sprintf(retbuf+strlen(retbuf),",\"aveprice\":%.8f,\"n\":%d}",price,n);
    return(price);
}


#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

void PAX_init(struct peggy_info *PEGS)
{
    double commission = 0.;
    init_Currencymasks();
    tradebot_monitorall(0,0,0,0,"fxcm",commission);
    tradebot_monitorall(0,0,0,0,"truefx",commission);
    tradebot_monitorall(0,0,0,0,"instaforex",commission);
}

#include "../includes/iguana_apiundefs.h"
