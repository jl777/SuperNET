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

#include <math.h>
#include "../crypto777/OS_portable.h"

#define _extrapolate_Spline(Splines,gap) ((double)(Splines)[0] + ((gap) * ((double)(Splines)[1] + ((gap) * ((double)(Splines)[2] + ((gap) * (double)(Splines)[3]))))))
#define _extrapolate_Slope(Splines,gap) ((double)(Splines)[1] + ((gap) * ((double)(Splines)[2] + ((gap) * (double)(Splines)[3]))))

#define PRICE_BLEND(oldval,newval,decay,oppodecay) ((oldval == 0.) ? newval : ((oldval * decay) + (oppodecay * newval)))
#define PRICE_BLEND64(oldval,newval,decay,oppodecay) ((oldval == 0) ? newval : ((oldval * decay) + (oppodecay * newval) + 0.499))

#define USD 0
#define EUR 1
#define JPY 2
#define GBP 3
#define AUD 4
#define CAD 5
#define CHF 6
#define NZD 7
#define CNY 8
#define RUB 9

#define NZDUSD 0
#define NZDCHF 1
#define NZDCAD 2
#define NZDJPY 3
#define GBPNZD 4
#define EURNZD 5
#define AUDNZD 6
#define CADJPY 7
#define CADCHF 8
#define USDCAD 9
#define EURCAD 10
#define GBPCAD 11
#define AUDCAD 12
#define USDCHF 13
#define CHFJPY 14
#define EURCHF 15
#define GBPCHF 16
#define AUDCHF 17
#define EURUSD 18
#define EURAUD 19
#define EURJPY 20
#define EURGBP 21
#define GBPUSD 22
#define GBPJPY 23
#define GBPAUD 24
#define USDJPY 25
#define AUDJPY 26
#define AUDUSD 27

#define USDNUM 28
#define EURNUM 29
#define JPYNUM 30
#define GBPNUM 31
#define AUDNUM 32
#define CADNUM 33
#define CHFNUM 34
#define NZDNUM 35

#define NUM_CONTRACTS 28
#define NUM_CURRENCIES 8
#define NUM_COMBINED (NUM_CONTRACTS + NUM_CURRENCIES)
#define MAX_SPLINES 64
#define MAX_LOOKAHEAD 48

#define MAX_EXCHANGES 64
#define MAX_CURRENCIES 32
#define PRICE_DECAY 0.9

#define INSTANTDEX_EXCHANGEID 0
#define INSTANTDEX_UNCONFID 1
#define INSTANTDEX_NXTAEID 2
#define DAYS_FIFO (512)


struct prices777_data
{
    uint64_t tmillistamps[128]; double tbids[128],tasks[128],topens[128],thighs[128],tlows[128];
    double flhlogmatrix[8][8],flogmatrix[8][8],fbids[128],fasks[128],fhighs[128],flows[128];
    uint32_t itimestamps[128]; double ilogmatrix[8][8],ibids[128],iasks[128];
    char edate[128]; double ecbmatrix[32][32],dailyprices[MAX_CURRENCIES * MAX_CURRENCIES],metals[4];
    int32_t ecbdatenum,ecbyear,ecbmonth,ecbday; double RTmatrix[32][32],RTprices[128],RTmetals[4];
    double btcusd,btcdbtc,cryptos[8];
};

struct prices777_spline { char name[64]; int32_t splineid,lasti,basenum,num,firstx,dispincr,spline32[MAX_SPLINES][4]; uint32_t utc32[MAX_SPLINES]; int64_t spline64[MAX_SPLINES][4]; double dSplines[MAX_SPLINES][4],pricevals[MAX_SPLINES+MAX_LOOKAHEAD],lastutc,lastval,aveslopeabs; };
struct prices777_info
{
    struct prices777 *ptrs[1024],*truefx[128],*fxcm[128],*instaforex[128],*ecb[128];
    struct prices777_spline splines[128]; double cryptovols[2][8][2],btcusd,btcdbtc,cnyusd;
    int32_t num,numt,numf,numi,nume; char *jsonstr;
    char truefxuser[64],truefxpass[64]; uint64_t truefxidnum;
    struct prices777_data data,tmp; struct kv777 *kv;
    float ecbdaily[DAYS_FIFO][MAX_CURRENCIES][MAX_CURRENCIES];
} BUNDLE;

uint64_t Currencymasks[NUM_CURRENCIES+1];

char CONTRACTS[][16] = {  "NZDUSD", "NZDCHF", "NZDCAD", "NZDJPY", "GBPNZD", "EURNZD", "AUDNZD", "CADJPY", "CADCHF", "USDCAD", "EURCAD", "GBPCAD", "AUDCAD", "USDCHF", "CHFJPY", "EURCHF", "GBPCHF", "AUDCHF", "EURUSD", "EURAUD", "EURJPY", "EURGBP", "GBPUSD", "GBPJPY", "GBPAUD", "USDJPY", "AUDJPY", "AUDUSD", "USDCNY", "USDHKD", "USDMXN", "USDZAR", "USDTRY", "EURTRY", "TRYJPY", "USDSGD", "EURNOK", "USDNOK","USDSEK","USDDKK","EURSEK","EURDKK","NOKJPY","SEKJPY","USDPLN","EURPLN","USDILS", // no more currencies
    "XAUUSD", "XAGUSD", "XPTUSD", "XPDUSD", "Copper", "NGAS", "UKOil", "USOil", // commodities
    // cryptos
    "NAS100", "SPX500", "US30", "Bund", "EUSTX50", "UK100", "JPN225", "GER30", "SUI30", "AUS200", "HKG33", "FRA40", "ESP35", "ITA40", "USDOLLAR", // indices
    "SuperNET" // assets
};

char CURRENCIES[][8] = { "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD", // major currencies
    "CNY", "RUB", "MXN", "BRL", "INR", "HKD", "TRY", "ZAR", "PLN", "NOK", "SEK", "DKK", "CZK", "HUF", "ILS", "KRW", "MYR", "PHP", "RON", "SGD", "THB", "BGN", "IDR", "HRK", // end of currencies
    "XAU", "XAG", "XPT", "XPD", // metals, gold must be first
    "BTCD", "BTC", "NXT", "LTC", "ETH", "DOGE", "BTS", "MAID", "XCP",  "XMR" // cryptos
};

int32_t MINDENOMS[] = { 1000, 1000, 100000, 1000, 1000, 1000, 1000, 1000, // major currencies
   10000, 100000, 10000, 1000, 100000, 10000, 1000, 10000, 1000, 10000, 10000, 10000, 10000, 100000, 1000, 1000000, 1000, 10000, 1000, 1000, 10000, 1000, 10000000, 10000, // end of currencies
    1, 100, 1, 1, // metals, gold must be first
    1, 10, 100000, 100, 100, 10000000, 10000, 1000, 1000,  1000, 100000, 100000, 1000000 // cryptos
};

int32_t prices777_mindenomination(int32_t base)
{
    return(MINDENOMS[base]);
}

short Contract_base[NUM_COMBINED+1] = { 7, 7, 7, 7, 3, 1, 4, 5, 5, 0, 1, 3, 4, 0, 6, 1, 3, 4, 1, 1, 1, 1, 3, 3, 3, 0, 4, 4, 0,1,2,3,4,5,6,7, 8 };// Contract_base };
short  Contract_rel[NUM_COMBINED+1] = { 0, 6, 5, 2, 7, 7, 7, 2, 6, 5, 5, 5, 5, 6, 2, 6, 6, 6, 0, 4, 2, 3, 0, 2, 4, 2, 2, 0, 0,1,2,3,4,5,6,7,8 };// Contract_rel

short Baserel_contractnum[NUM_CURRENCIES+1][NUM_CURRENCIES+1] =
{
	{ 28, 18, 25, 22, 27,  9, 13,  0, 36 },
	{ 18, 29, 20, 21, 19, 10, 15,  5, 37 },
	{ 25, 20, 30, 23, 26,  7, 14,  3, -1 },
	{ 22, 21, 23, 31, 24, 11, 16,  4, 38 },
	{ 27, 19, 26, 24, 32, 12, 17,  6, 39 },
	{  9, 10,  7, 11, 12, 33,  8,  2, -1 },
	{ 13, 15, 14, 16, 17,  8, 34,  1, 40 },
	{  0,  5,  3,  4,  6,  2,  1, 35, -1 },
	{ 36, 37, -1, 38, 39, -1, 40, -1, 74 },
};

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

short Currency_contractdirs[NUM_CURRENCIES+1][NUM_CURRENCIES] =
{
	{ -1,  1,  1, -1, -1,  1, -1,  1 },
	{  1,  1,  1,  1,  1,  1,  1,  1 },
	{ -1, -1, -1, -1, -1, -1, -1,  1 },
	{  1,  1,  1, -1,  1,  1,  1,  1 },
	{  1,  1,  1, -1, -1,  1,  1,  1 },
	{ -1,  1,  1, -1, -1, -1, -1,  1 },
	{ -1, -1, -1,  1, -1, -1, -1,  1 },
	{  1,  1,  1,  1, -1, -1, -1,  1 },
	{  1,  1,  1,  1,  1,  1,  1,  1 },
};
char *Yahoo_metals[] = { "XAU", "XAG", "XPT", "XPD" };


#define dto64(x) ((int64_t)((x) * (double)SATOSHIDEN * SATOSHIDEN))
#define dto32(x) ((int32_t)((x) * (double)SATOSHIDEN))
#define i64tod(x) ((double)(x) / ((double)SATOSHIDEN * SATOSHIDEN))
#define i32tod(x) ((double)(x) / (double)SATOSHIDEN)
#define _extrapolate_spline64(spline64,gap) ((double)i64tod((spline64)[0]) + ((gap) * ((double)i64tod(.001*.001*(spline64)[1]) + ((gap) * ((double)i64tod(.001*.001*.001*.001*(spline64)[2]) + ((gap) * (double)i64tod(.001*.001*.001*.001*.001*.001*(spline64)[3])))))))
#define _extrapolate_spline32(spline32,gap) ((double)i32tod((spline32)[0]) + ((gap) * ((double)i32tod(.001*.001*(spline32)[1]) + ((gap) * ((double)i32tod(.001*.001*.001*.001*(spline32)[2]) + ((gap) * (double)i32tod(.001*.001*.001*.001*.001*.001*(spline32)[3])))))))

double prices777_splineval(struct prices777_spline *spline,uint32_t timestamp,int32_t lookahead)
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

double prices777_calcspline(struct prices777_spline *spline,double *outputs,double *slopes,int32_t dispwidth,uint32_t *utc32,double *splinevals,int32_t num)
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
                if ( (yval3 = prices777_splineval(spline,gap32 + spline->utc32[i],MAX_LOOKAHEAD*spline->dispincr)) != 0 )
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

int32_t prices777_genspline(struct prices777_spline *spline,int32_t splineid,char *name,uint32_t *utc32,double *splinevals,int32_t maxsplines,double *refvals)
{
    int32_t i; double output[2048],slopes[2048],origvals[MAX_SPLINES];
    memset(spline,0,sizeof(*spline)), memset(output,0,sizeof(output)), memset(slopes,0,sizeof(slopes));
    spline->dispincr = 3600, spline->basenum = splineid, strcpy(spline->name,name);
    memcpy(origvals,splinevals,sizeof(*splinevals) * MAX_SPLINES);
    spline->lastval = prices777_calcspline(spline,output,slopes,sizeof(output)/sizeof(*output),utc32,splinevals,maxsplines);
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

double prices777_baseprice(uint32_t timestamp,int32_t basenum)
{
    double btc,btcd,btcdusd,usdval;
    btc = 1000. * _pairaved(prices777_splineval(&BUNDLE.splines[MAX_CURRENCIES+0],timestamp,0),prices777_splineval(&BUNDLE.splines[MAX_CURRENCIES+1],timestamp,0));
    btcd = .01 * prices777_splineval(&BUNDLE.splines[MAX_CURRENCIES+2],timestamp,0);
    if ( btc != 0. && btcd != 0. )
    {
        btcdusd = (btc * btcd);
        usdval = prices777_splineval(&BUNDLE.splines[USD],timestamp,0);
        if ( basenum == USD )
            return(1. / btcdusd);
        else return(prices777_splineval(&BUNDLE.splines[basenum],timestamp,0) / (btcdusd * usdval));
    }
    return(0.);
}

int32_t prices777_ispair(char *base,char *rel,char *contract)
{
    int32_t i,j;
    base[0] = rel[0] = 0;
    for (i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
    {
        if ( strncmp(CURRENCIES[i],contract,strlen(CURRENCIES[i])) == 0 )
        {
            for (j=0; j<sizeof(CURRENCIES)/sizeof(*CURRENCIES); j++)
                if ( strcmp(CURRENCIES[j],contract+strlen(CURRENCIES[i])) == 0 )
                {
                    strcpy(base,CURRENCIES[i]);
                    strcpy(rel,CURRENCIES[j]);
                    /*USDCNY 6.209700 -> 0.655564
                     USDCNY 6.204146 -> 0.652686
                     USDHKD 7.753400 -> 0.749321
                     USDHKD 7.746396 -> 0.746445
                     USDZAR 12.694000 -> 1.101688
                     USDZAR 12.682408 -> 1.098811
                     USDTRY 2.779700 -> 0.341327
                     EURTRY 3.048500 -> 0.386351
                     TRYJPY 44.724000 -> 0.690171
                     TRYJPY 44.679966 -> 0.687290
                     USDSGD 1.375200 -> 0.239415*/
                    //if ( strcmp(contract,"USDCNY") == 0 || strcmp(contract,"TRYJPY") == 0 || strcmp(contract,"USDZAR") == 0 )
                    //    printf("i.%d j.%d base.%s rel.%s\n",i,j,base,rel);
                    return((i<<8) | j);
                }
            break;
        }
    }
    return(-1);
}

int32_t prices777_basenum(char *base)
{
    int32_t i,j;
    if ( 1 )
    {
        for (i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
            for (j=0; j<sizeof(CURRENCIES)/sizeof(*CURRENCIES); j++)
                if ( i != j && strcmp(CURRENCIES[i],CURRENCIES[j]) == 0 )
                    printf("duplicate.(%s)\n",CURRENCIES[i]);//, getchar();
    }
    for (i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
        if ( strcmp(CURRENCIES[i],base) == 0 )
            return(i);
    return(-1);
}

int32_t prices777_contractnum(char *base,char *rel)
{
    int32_t i,j,c; char contractstr[16],*contract = 0;
    if ( 0 )
    {
        for (i=0; i<sizeof(CONTRACTS)/sizeof(*CONTRACTS); i++)
            for (j=0; j<sizeof(CONTRACTS)/sizeof(*CONTRACTS); j++)
                if ( i != j && strcmp(CONTRACTS[i],CONTRACTS[j]) == 0 )
                    printf("duplicate.(%s)\n",CONTRACTS[i]);//, getchar();
    }
    if ( base != 0 && base[0] != 0 && rel != 0 && rel[0] != 0 )
    {
        for (i=0; i<NUM_CURRENCIES; i++)
            if ( strcmp(base,CURRENCIES[i]) == 0 )
            {
                for (j=0; j<NUM_CURRENCIES; j++)
                    if ( strcmp(rel,CURRENCIES[j]) == 0 )
                        return(Baserel_contractnum[i][j]);
                break;
            }
        sprintf(contractstr,"%s%s",base,rel);
        contract = contractstr;
    } else contract = base;
    if ( contract != 0 && contract[0] != 0 )
    {
        for (c=0; c<sizeof(CONTRACTS)/sizeof(*CONTRACTS); c++)
            if ( strcmp(CONTRACTS[c],contract) == 0 )
                return(c);
    }
    return(-1);
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
				printf("%s.%9.6f | ",CONTRACTS[base+28],_pairaved(bids[base+28],asks[base+28]));
			printf("%07llx\n",(long long)nonzmask);
		}
	}
	return(0);
}

double prices777_getprice(char *retbuf,char *base,char *rel,char *contract)
{
    int32_t i,c,basenum,relnum,n = 0; double yprice,daily,revdaily,price,bid,ask;
    struct prices777 *prices; struct prices777_data *dp = &BUNDLE.data;
    price = yprice = daily = revdaily = 0.;
    prices777_ispair(base,rel,contract);
    if ( base[0] != 0 && rel[0] != 0 )
    {
        basenum = prices777_basenum(base), relnum = prices777_basenum(rel);
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
    for (i=0; i<BUNDLE.num; i++)
    {
        if ( (prices= BUNDLE.ptrs[i]) != 0 )
        {
            //printf("(%s) (%s) (%s)\n",prices->contract,prices->base,prices->rel);
            if ( strcmp(contract,prices->contract) == 0 && (bid= prices->lastbid) != 0 && (ask= prices->lastask) != 0 )
            {
                price += (bid + ask), n += 2;
                printf("%s add %f %f -> %f [%f]\n",prices->exchange,bid,ask,price,price/n);
                sprintf(retbuf+strlen(retbuf),",\"%s\":{\"bid\":%.8f,\"ask\":%.8f}",prices->exchange,bid,ask);
            }
        }
    }
    if ( (c= prices777_contractnum(contract,0)) >= 0 )
    {
        if ( dp->tbids[c] != 0. && dp->tasks[c] != 0. )
        {
            price += (dp->tbids[c] + dp->tasks[c]), n += 2;
            sprintf(retbuf+strlen(retbuf),",\"truefx\":{\"millistamp\":\"%llu\",\"bid\":%.8f,\"ask\":%.8f,\"open\":%.8f,\"high\":%.8f,\"low\":%.8f}",(long long)dp->tmillistamps[c],dp->tbids[c],dp->tasks[c],dp->topens[c],dp->thighs[c],dp->tlows[c]);
        }
        if ( dp->fbids[c] != 0. && dp->fasks[c] != 0. )
        {
            price += (dp->fbids[c] + dp->fasks[c]), n += 2;
            sprintf(retbuf+strlen(retbuf),",\"fxcm\":{\"bid\":%.8f,\"ask\":%.8f,\"high\":%.8f,\"low\":%.8f}",dp->fbids[c],dp->fasks[c],dp->fhighs[c],dp->flows[c]);
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

struct prices777 *prices777_initpair(int32_t needfunc,char *exchange,char *_base,char *_rel,double decay,char *_name,uint64_t baseid,uint64_t relid,int32_t basketsize)
{
    static long allocated;
    int32_t i,rellen; char basebuf[64],relbuf[64],base[64],rel[64],name[64]; struct exchange_info *exchangeptr;
    struct prices777 *prices;
    safecopy(base,_base,sizeof(base));
    safecopy(rel,_rel,sizeof(rel));
    safecopy(name,_name,sizeof(name));
    if ( needfunc < 0 )
    {
        for (i=0; i<sizeof(funcs)/sizeof(*funcs); i++)
        {
            if ( (exchangeptr= find_exchange(0,funcs[i].exchange)) != 0 )
            {
                printf("%p %s set supports.%p %p coinbalance.%p\n",exchangeptr,funcs[i].exchange,funcs[i].supports,funcs[i].trade,funcs[i].parsebalance);
                exchangeptr->issue = funcs[i];
            }
        }
        return(0);
    }
    //printf("init.(%s/%s) name.(%s) %llu %llu\n",base,rel,name,(long long)baseid,(long long)relid);
    if ( strcmp(exchange,"nxtae") == 0 || strcmp(exchange,"unconf") == 0 )//|| strcmp(exchange,"InstantDEX") == 0 )
    {
        if ( strcmp(base,"NXT") == 0 || baseid == NXT_ASSETID )
        {
            strcpy(base,rel), baseid = relid;
            strcpy(rel,"NXT"), relid = NXT_ASSETID;
            printf("flip.(%s/%s) %llu %llu\n",base,rel,(long long)baseid,(long long)relid);
        }
    }
    for (i=0; i<BUNDLE.num; i++)
    {
        if ( strcmp(BUNDLE.ptrs[i]->exchange,exchange) == 0 )
        {
            if ( baseid != 0 && relid != 0 && BUNDLE.ptrs[i]->baseid == baseid && BUNDLE.ptrs[i]->relid == relid )
                return(BUNDLE.ptrs[i]);
            if ( strcmp(BUNDLE.ptrs[i]->origbase,base) == 0 && strcmp(BUNDLE.ptrs[i]->origrel,rel) == 0 )
                return(BUNDLE.ptrs[i]);
        }
    }
    printf("cant find (%s) (%llu) (%llu) (%s) (%s)\n",exchange,(long long)baseid,(long long)relid,base,rel);
    prices = calloc(1,sizeof(*prices) + basketsize*sizeof(*prices->basket));
   // printf("new prices %ld\n",sizeof(*prices));
    strcpy(prices->exchange,exchange), strcpy(prices->contract,name), strcpy(prices->base,base), strcpy(prices->rel,rel);
    prices->baseid = baseid, prices->relid = relid;
    prices->contractnum = InstantDEX_name(prices->key,&prices->keysize,exchange,prices->contract,prices->base,&prices->baseid,prices->rel,&prices->relid);
    portable_mutex_init(&prices->mutex);
    strcpy(prices->origbase,base);
    if ( rel[0] != 0 )
        strcpy(prices->origrel,rel);
    allocated += sizeof(*prices);
    safecopy(prices->exchange,exchange,sizeof(prices->exchange));
    if ( strcmp(exchange,"nxtae") == 0 || strcmp(exchange,"unconf") == 0 || strcmp(exchange,INSTANTDEX_NAME) == 0 )
    {
        char tmp[16];
        _set_assetname(&prices->basemult,tmp,0,prices->baseid);
        _set_assetname(&prices->relmult,tmp,0,prices->relid);
        if ( (prices->relid != NXT_ASSETID && prices->relid < (1LL << (5*8))) || (prices->baseid != NXT_ASSETID && prices->baseid == (1LL << (5*8))) )
        {
            printf("illegal baseid.%llu or relid.%llu\n",(long long)prices->baseid,(long long)prices->relid);
            free(prices);
            return(0);
        }
        //prices->nxtbooks = calloc(1,sizeof(*prices->nxtbooks));
        safecopy(prices->lbase,base,sizeof(prices->lbase)), tolowercase(prices->lbase);
        safecopy(prices->lrel,rel,sizeof(prices->lrel)), tolowercase(prices->lrel);
        rellen = (int32_t)(strlen(prices->rel) + 1);
        tmp[0] = 0;
        prices->type = _set_assetname(&prices->ap_mult,tmp,0,prices->baseid);
        printf("nxtbook.(%s) -> NXT %s %llu/%llu vs (%s) mult.%llu (%llu/%llu)\n",base,prices->contract,(long long)prices->baseid,(long long)prices->relid,tmp,(long long)prices->ap_mult,(long long)prices->basemult,(long long)prices->relmult);
    }
    else
    {
        prices->basemult = prices->relmult = 1;
        safecopy(prices->base,base,sizeof(prices->base)), touppercase(prices->base);
        safecopy(prices->lbase,base,sizeof(prices->lbase)), tolowercase(prices->lbase);
        if ( rel[0] == 0 && prices777_ispair(basebuf,relbuf,base) >= 0 )
        {
            strcpy(base,basebuf), strcpy(rel,relbuf);
            //printf("(%s) is a pair (%s)+(%s)\n",base,basebuf,relbuf);
        }
        if ( rel[0] != 0 )
        {
            rellen = (int32_t)(strlen(rel) + 1);
            safecopy(prices->rel,rel,sizeof(prices->rel)), touppercase(prices->rel);
            safecopy(prices->lrel,rel,sizeof(prices->lrel)), tolowercase(prices->lrel);
            if ( prices->contract[0] == 0 )
            {
                strcpy(prices->contract,prices->base);
                if ( strcmp(prices->rel,&prices->contract[strlen(prices->contract)-3]) != 0 )
                    strcat(prices->contract,"/"), strcat(prices->contract,prices->rel);
            }
            //printf("create base.(%s) rel.(%s)\n",prices->base,prices->rel);
        }
        else
        {
            if ( prices->contract[0] == 0 )
                strcpy(prices->contract,base);
        }
    }
    char str[65]; printf("%s init_pair.(%s) (%s)(%s).%llu -> (%s) keysize.%d crc.%u (baseid.%llu relid.%llu)\n",mbstr(str,allocated),exchange,base,rel,(long long)prices->contractnum,prices->contract,prices->keysize,calc_crc32(0,(void *)prices->key,prices->keysize),(long long)prices->baseid,(long long)prices->relid);
    prices->decay = decay, prices->oppodecay = (1. - decay);
    prices->RTflag = 1;
    if ( (exchangeptr= find_exchange(0,exchange)) != 0 )
    {
        if ( prices->commission == 0. )
            prices->commission = exchangeptr->commission;
        prices->exchangeid = exchangeptr->exchangeid;
        if ( exchangeptr->issue.update == 0 )
        {
            for (i=0; i<sizeof(funcs)/sizeof(*funcs); i++)
            {
                if ( strcmp(exchange,funcs[i].exchange) == 0 )
                {
                    exchangeptr->issue = funcs[i];
                    //printf("return prices.%p\n",prices);
                }
            }
        }
        if ( exchangeptr->refcount == 0 )
        {
            printf("incr refcount.%s from %d\n",exchangeptr->name,exchangeptr->refcount);
            exchangeptr->refcount++;
        }
        return(prices);
    }
    //printf("initialized.(%s).%lld\n",prices->contract,(long long)prices->contractnum);
    return(prices);
}

int32_t is_pair(char *base,char *rel,char *refbase,char *refrel)
{
    if ( strcmp(base,refbase) == 0 && strcmp(rel,refrel) == 0 )
        return(1);
    else if ( strcmp(rel,refbase) == 0 && strcmp(base,refrel) == 0 )
        return(-1);
    return(0);
}

struct prices777 *prices777_poll(char *_exchangestr,char *_name,char *_base,uint64_t refbaseid,char *_rel,uint64_t refrelid)
{
    char exchangestr[64],base[64],rel[64],name[64],key[1024]; uint64_t baseid,relid;
    int32_t keysize,exchangeid,valid; struct exchange_info *exchange; struct prices777 *prices;
    baseid = refbaseid, relid = refrelid;
    strcpy(exchangestr,_exchangestr), strcpy(base,_base), strcpy(rel,_rel), strcpy(name,_name);
    if ( (strcmp(exchangestr,"huobi") == 0 && is_pair(base,rel,"BTC","CNY") == 0 && is_pair(base,rel,"LTC","CNY") == 0) ||
        ((strcmp(exchangestr,"bityes") == 0 || strcmp(exchangestr,"okcoin") == 0) && is_pair(base,rel,"BTC","USD") == 0 && is_pair(base,rel,"LTC","USD") == 0) ||
        ((strcmp(exchangestr,"bitstamp") == 0 || strcmp(exchangestr,"coinbase") == 0) && is_pair(base,rel,"BTC","USD") == 0) ||
        (strcmp(exchangestr,"lakebtc") == 0 && is_pair(base,rel,"BTC","CNY") == 0 && is_pair(base,rel,"BTC","USD") == 0) ||
        (strcmp(exchangestr,"quadriga") == 0 && is_pair(base,rel,"BTC","CAD") == 0 && is_pair(base,rel,"BTC","USD") == 0) ||
        0 )
    {
        printf("%s (%s/%s) is not a supported trading pair\n",exchangestr,base,rel);
        return(0);
    }
    InstantDEX_name(key,&keysize,exchangestr,name,base,&baseid,rel,&relid);
//printf("call addbundle\n");
    if ( (prices= prices777_addbundle(&valid,0,0,exchangestr,baseid,relid)) != 0 )
    {
        printf("found (%s/%s).%s %llu %llu in slot-> %p\n",base,rel,exchangestr,(long long)baseid,(long long)relid,prices);
        return(prices);
    }
//printf("call find_exchange\n");
    if ( (exchange= find_exchange(&exchangeid,exchangestr)) == 0 )
    {
        printf("cant add exchange.(%s)\n",exchangestr);
        return(0);
    }
    if ( strcmp(exchangestr,"nxtae") == 0 || strcmp(exchangestr,"unconf") == 0 )
    {
        if ( strcmp(base,"NXT") != 0 && strcmp(rel,"NXT") != 0 )
        {
            printf("nxtae/unconf needs to be relative to NXT (%s/%s) %llu/%llu\n",base,rel,(long long)baseid,(long long)relid);
            return(0);
        }
    }
    if ( (prices= prices777_initpair(1,exchangestr,base,rel,0.,name,baseid,relid,0)) != 0 )
    {
        //printf("call addbundle after initpair\n");
        prices777_addbundle(&valid,1,prices,0,0,0);
    }
    return(prices);
}

int32_t prices777_propagate(struct prices777 *prices)
{
    int32_t i,n = 0;
    for (i=0; i<prices->numdependents; i++)
    {
        n++;
        if ( (*prices->dependents[i]) < 0xff )
            (*prices->dependents[i])++;
        if ( Debuglevel > 2 )
            printf("numdependents.%d of %d %p %d\n",i,prices->numdependents,prices->dependents[i],*prices->dependents[i]);
    }
    return(n);
}

int32_t prices777_updated;
void prices777_basketsloop(void *ptr)
{
    extern int32_t prices777_NXTBLOCK;
    int32_t i,n; uint32_t updated; struct prices777 *prices;
    while ( 1 )
    {
        for (i=n=0; i<BUNDLE.num; i++)
        {
            updated = (uint32_t)time(NULL);
            if ( (prices= BUNDLE.ptrs[i]) != 0 && prices->disabled == 0 && prices->basketsize != 0 )
            {
                if ( prices->changed != 0 )
                {
                    if ( Debuglevel > 2 )
                            printf("%s updating basket(%s) lastprice %.8f changed.%p %d\n",prices->exchange,prices->contract,prices->lastprice,&prices->changed,prices->changed);
                    prices->pollnxtblock = prices777_NXTBLOCK;
                    n++;
                    prices->lastupdate = updated;
                    if ( (prices->lastprice= prices777_basket(prices,MAX_DEPTH)) != 0. )
                    {
                        if ( prices->O.numbids > 0 || prices->O.numasks > 0 )
                        {
                            prices777_jsonstrs(prices,&prices->O);
                            prices777_updated += prices777_propagate(prices);
                        }
                    }
                    prices->changed = 0;
                }
            }
        }
        if ( n == 0 )
            usleep(250000);
        else usleep(10000);
    }
}

void prices777_exchangeloop(void *ptr)
{
    extern int32_t prices777_NXTBLOCK;
    struct prices777 *prices; int32_t i,n,pollflag,isnxtae = 0; double updated = 0.; struct exchange_info *exchange = ptr;
    if ( strcmp(exchange->name,"nxtae") == 0 || strcmp(exchange->name,"unconf") == 0 )
        isnxtae = 1;
    printf("POLL.(%s)\n",exchange->name);
    while ( 1 )
    {
        for (i=n=0; i<BUNDLE.num; i++)
        {
            if ( (prices= BUNDLE.ptrs[i]) != 0 && prices->disabled == 0 && prices->basketsize == 0 && prices->exchangeid == exchange->exchangeid )
            {
                if ( prices->exchangeid == INSTANTDEX_EXCHANGEID && prices->dirty != 0 )
                    pollflag = 1;
                else if ( isnxtae == 0 )
                    pollflag = milliseconds() > (exchange->lastupdate + exchange->pollgap*1000) && milliseconds() > (prices->lastupdate + 1000*IGUANA_EXCHANGEIDLE);
                else if ( (strcmp(exchange->name,"unconf") == 0 && milliseconds() > prices->lastupdate + 5000) || prices->pollnxtblock < prices777_NXTBLOCK || milliseconds() > prices->lastupdate + 1000*IGUANA_EXCHANGEIDLE )
                    pollflag = 1;
                else continue;
                //printf("(%s) pollflag.%d %p\n",exchange->name,pollflag,exchange->issue.update);
                if ( pollflag != 0 && exchange->issue.update != 0 )
                {
                    portable_mutex_lock(&exchange->mutex);
                    prices->lastprice = (*exchange->issue.update)(prices,MAX_DEPTH);
                    portable_mutex_unlock(&exchange->mutex);
                    updated = exchange->lastupdate = milliseconds(), prices->lastupdate = milliseconds();
                    if ( prices->lastprice != 0. )
                    {
                        if ( Debuglevel > 2 && strcmp(exchange->name,"unconf") != 0 )
                            printf("%-8s %8s (%8s %8s) %llu %llu isnxtae.%d poll %u -> %u %.8f hbla %.8f %.8f\n",prices->exchange,prices->contract,prices->base,prices->rel,(long long)prices->baseid,(long long)prices->relid,isnxtae,prices->pollnxtblock,prices777_NXTBLOCK,prices->lastprice,prices->lastbid,prices->lastask);
                        prices777_propagate(prices);
                    }
                    prices->pollnxtblock = prices777_NXTBLOCK;
                    prices->dirty = 0;
                    n++;
                }
                /*if ( 0 && exchange->issue.trade != 0 && exchange->apikey[0] != 0 && exchange->exchangeid >= FIRST_EXTERNAL && time(NULL) > exchange->lastbalancetime+300 )
                {
                    if ( (json= (*exchange->issue.balances)(exchange)) != 0 )
                    {
                        if ( exchange->balancejson != 0 )
                            free_json(exchange->balancejson);
                        exchange->balancejson = json;
                    }
                    exchange->lastbalancetime = (uint32_t)time(NULL);
                }*/
            }
        }
        if ( n == 0 )
            sleep(3);
        else sleep(1);
    }
}

int32_t prices777_init(char *jsonstr,int32_t peggyflag)
{
    static int32_t didinit;
    char *btcdexchanges[] = { "poloniex", "bittrex" };//, "bter" };
    char *btcusdexchanges[] = { "bityes", "bitfinex", "bitstamp", "okcoin", "coinbase", "btce", "lakebtc", "kraken" };
    cJSON *json=0,*item,*exchanges; int32_t i,n; char *exchange,*base,*rel,*contract; struct exchange_info *exchangeptr=0; struct destbuf tmp;
    if ( didinit != 0 )
        return(0);
    didinit = 1;
    if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"unconf","BTC","NXT",0,"BTC/NXT",calc_nxt64bits("12659653638116877017"),NXT_ASSETID,0)) != 0 )
        BUNDLE.num++;
    if ( peggyflag != 0 )
    {
        if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"huobi","BTC","USD",0.,0,0,0,0)) != 0 )
            BUNDLE.num++;
        if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"btc38","CNY","NXT",0.,0,0,0,0)) != 0 )
            BUNDLE.num++;
        if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"okcoin","LTC","BTC",0.,0,0,0,0)) != 0 )
            BUNDLE.num++;
        if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"poloniex","LTC","BTC",0.,0,0,0,0)) != 0 )
            BUNDLE.num++;
        if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"poloniex","XMR","BTC",0.,0,0,0,0)) != 0 )
            BUNDLE.num++;
        if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"poloniex","BTS","BTC",0.,0,0,0,0)) != 0 )
            BUNDLE.num++;
        if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"poloniex","XCP","BTC",0.,0,0,0,0)) != 0 )
            BUNDLE.num++;
        for (i=0; i<sizeof(btcdexchanges)/sizeof(*btcdexchanges); i++)
            if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,btcusdexchanges[i],"BTC","USD",0.,0,0,0,0)) != 0 )
                BUNDLE.num++;
        for (i=0; i<sizeof(btcdexchanges)/sizeof(*btcdexchanges); i++)
            if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,btcdexchanges[i],"BTCD","BTC",0.,0,0,0,0)) != 0 )
                BUNDLE.num++;
    }
    if ( (json= cJSON_Parse(jsonstr)) != 0 && (exchanges= jarray(&n,json,"prices")) != 0 )
    {
        printf("prices has %d items\n",n);
        for (i=0; i<n; i++)
        {
            item = jitem(exchanges,i);
            exchange = jstr(item,"exchange"), base = jstr(item,"base"), rel = jstr(item,"rel");
            if ( (base == 0 || rel == 0) && (contract= jstr(item,"contract")) != 0 )
                rel = 0, base = contract;
            else contract = 0;
            //printf("PRICES[%d] %p %p %p\n",i,exchange,base,rel);
            if ( exchange != 0 && (strcmp(exchange,"bter") == 0 || strcmp(exchange,"exmo") == 0) )
                continue;
            if ( exchange != 0 && (exchangeptr= find_exchange(0,exchange)) != 0 )
            {
                exchangeptr->pollgap = get_API_int(cJSON_GetObjectItem(item,"pollgap"),IGUANA_EXCHANGEIDLE);
                extract_cJSON_str(exchangeptr->apikey,sizeof(exchangeptr->apikey),item,"key");
                if ( exchangeptr->apikey[0] == 0 )
                    extract_cJSON_str(exchangeptr->apikey,sizeof(exchangeptr->apikey),item,"apikey");
                extract_cJSON_str(exchangeptr->userid,sizeof(exchangeptr->userid),item,"userid");
                extract_cJSON_str(exchangeptr->apisecret,sizeof(exchangeptr->apisecret),item,"secret");
                if ( exchangeptr->apisecret[0] == 0 )
                    extract_cJSON_str(exchangeptr->apisecret,sizeof(exchangeptr->apisecret),item,"apisecret");
                if ( exchangeptr->commission == 0. )
                    exchangeptr->commission = jdouble(item,"commission");
                printf("%p ADDEXCHANGE.(%s) [%s, %s, %s] commission %.3f%%\n",exchangeptr,exchange,exchangeptr->apikey,exchangeptr->userid,exchangeptr->apisecret,exchangeptr->commission * 100);
            } else printf(" exchangeptr.%p for (%p)\n",exchangeptr,exchange);
            if ( exchange != 0 && strcmp(exchange,"truefx") == 0 )
            {
                copy_cJSON(&tmp,jobj(item,"truefxuser")), safecopy(BUNDLE.truefxuser,tmp.buf,sizeof(BUNDLE.truefxuser));
                copy_cJSON(&tmp,jobj(item,"truefxpass")), safecopy(BUNDLE.truefxpass,tmp.buf,sizeof(BUNDLE.truefxpass));;
                printf("truefx.(%s %s)\n",BUNDLE.truefxuser,BUNDLE.truefxpass);
            }
            else if ( base != 0 && rel != 0 && base[0] != 0 && rel[0] != 0 && (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,exchange,base,rel,jdouble(item,"decay"),contract,stringbits(base),stringbits(rel),0)) != 0 )
            {
                if ( exchangeptr != 0 && (BUNDLE.ptrs[BUNDLE.num]->commission= jdouble(item,"commission")) == 0. )
                    BUNDLE.ptrs[BUNDLE.num]->commission = exchangeptr->commission;
                printf("SET COMMISSION.%s %f for %s/%s\n",exchange,exchangeptr!=0?exchangeptr->commission:0,base,rel);
                BUNDLE.num++;
            }
        }
    } else printf("(%s) has no prices[]\n",jsonstr);
    if ( json != 0 )
        free_json(json);
    for (i=0; i<MAX_EXCHANGES; i++)
    {
        exchangeptr = &Exchanges[i];
        if ( (exchangeptr->refcount > 0 || strcmp(exchangeptr->name,"unconf") == 0) )//&& strcmp(exchangeptr->name,"pangea") != 0 && strcmp(exchangeptr->name,"jumblr") != 0 )
            iguana_launch(0,"exchangeloop",(void *)prices777_exchangeloop,exchangeptr,IGUANA_EXCHANGETHREAD);
    }
    return(0);
}

double prices777_yahoo(char *metal)
{
    // http://finance.yahoo.com/webservice/v1/symbols/allcurrencies/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XAU=X/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XAG=X/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XPT=X/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XPD=X/quote?format=json
    char url[1024],*jsonstr; cJSON *json,*obj,*robj,*item,*field; double price = 0.;
    sprintf(url,"http://finance.yahoo.com/webservice/v1/symbols/%s=X/quote?format=json",metal);
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        //printf("(%s)\n",jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (obj= jobj(json,"list")) != 0 && (robj= jobj(obj,"resources")) != 0 && (item= jitem(robj,0)) != 0 )
            {
                if ( (robj= jobj(item,"resource")) != 0 && (field= jobj(robj,"fields")) != 0 && (price= jdouble(field,"price")) != 0 )
                    price = 1. / price;
            }
            free_json(json);
        }
        free(jsonstr);
    }
    if ( Debuglevel > 2 )
        printf("(%s %f) ",metal,price);
    return(price);
}

cJSON *url_json(char *url)
{
    char *jsonstr; cJSON *json = 0;
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        //printf("(%s) -> (%s)\n",url,jsonstr);
        json = cJSON_Parse(jsonstr);
        free(jsonstr);
    }
    return(json);
}

cJSON *url_json2(char *url)
{
    char *jsonstr; cJSON *json = 0;
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        //printf("(%s) -> (%s)\n",url,jsonstr);
        json = cJSON_Parse(jsonstr);
        free(jsonstr);
    }
    return(json);
}

void PAX_btcprices(int32_t enddatenum,int32_t numdates)
{
    int32_t i,n,year,month,day,seconds,datenum; char url[1024],date[64],*dstr,*str; uint32_t timestamp,utc32[MAX_SPLINES];
    cJSON *coindesk,*quandl,*btcdhist,*bpi,*array,*item;
    double btcddaily[MAX_SPLINES],cdaily[MAX_SPLINES],qdaily[MAX_SPLINES],ask,high,low,bid,close,vol,quotevol,open,price = 0.;
    coindesk = url_json("http://api.coindesk.com/v1/bpi/historical/close.json");
    sprintf(url,"https://poloniex.com/public?command=returnChartData&currencyPair=BTC_BTCD&start=%ld&end=9999999999&period=86400",(long)(time(NULL)-numdates*3600*24));
    if ( (bpi= jobj(coindesk,"bpi")) != 0 )
    {
        datenum = enddatenum;
        memset(utc32,0,sizeof(utc32));
        memset(cdaily,0,sizeof(cdaily));
        if ( datenum == 0 )
        {
            datenum = OS_conv_unixtime(&seconds,(uint32_t)time(NULL));
            printf("got datenum.%d %d %d %d\n",datenum,seconds/3600,(seconds/60)%24,seconds%60);
        }
        for (i=0; i<numdates; i++)
        {
            expand_datenum(date,datenum);
            if ( (price= jdouble(bpi,date)) != 0 )
            {
                utc32[numdates - 1 - i] = OS_conv_datenum(datenum,12,0,0);
                cdaily[numdates - 1 - i] = price * .001;
                //printf("(%s %u %f) ",date,utc32[numdates - 1 - i],price);
            }
            datenum = ecb_decrdate(&year,&month,&day,date,datenum);
        }
        prices777_genspline(&BUNDLE.splines[MAX_CURRENCIES],MAX_CURRENCIES,"coindesk",utc32,cdaily,numdates,cdaily);
        
    } else printf("no bpi\n");
    quandl = url_json("https://www.quandl.com/api/v1/datasets/BAVERAGE/USD.json?rows=64");
    if ( (str= jstr(quandl,"updated_at")) != 0 && (datenum= conv_date(&seconds,str)) > 0 && (array= jarray(&n,quandl,"data")) != 0 )
    {
        printf("datenum.%d data.%d %d\n",datenum,n,cJSON_GetArraySize(array));
        memset(utc32,0,sizeof(utc32)), memset(qdaily,0,sizeof(qdaily));
        for (i=0; i<n&&i<MAX_SPLINES; i++)
        {
            // ["Date","24h Average","Ask","Bid","Last","Total Volume"]
            // ["2015-07-25",289.27,288.84,288.68,288.87,44978.61]
            item = jitem(array,i);
            if ( Debuglevel > 2 )
                printf("(%s) ",cJSON_Print(item));
            if ( (dstr= jstr(jitem(item,0),0)) != 0 && (datenum= conv_date(&seconds,dstr)) > 0 )
            {
                price = jdouble(jitem(item,1),0), ask = jdouble(jitem(item,2),0), bid = jdouble(jitem(item,3),0);
                close = jdouble(jitem(item,4),0), vol = jdouble(jitem(item,5),0);
                if ( Debuglevel > 2 )
                    fprintf(stderr,"%d.[%d %f %f %f %f %f].%d ",i,datenum,price,ask,bid,close,vol,n);
                utc32[numdates - 1 - i] = OS_conv_datenum(datenum,12,0,0), qdaily[numdates - 1 - i] = price * .001;
            }
        }
        prices777_genspline(&BUNDLE.splines[MAX_CURRENCIES+1],MAX_CURRENCIES+1,"quandl",utc32,qdaily,n<MAX_SPLINES?n:MAX_SPLINES,qdaily);
    }
    btcdhist = url_json(url);
    //{"date":1406160000,"high":0.01,"low":0.00125,"open":0.01,"close":0.001375,"volume":1.50179994,"quoteVolume":903.58818412,"weightedAverage":0.00166204},
    if ( (array= jarray(&n,btcdhist,0)) != 0 )
    {
        memset(utc32,0,sizeof(utc32)), memset(btcddaily,0,sizeof(btcddaily));
        //printf("GOT.(%s)\n",cJSON_Print(array));
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            timestamp = juint(item,"date"), high = jdouble(item,"high"), low = jdouble(item,"low"), open = jdouble(item,"open");
            close = jdouble(item,"close"), vol = jdouble(item,"volume"), quotevol = jdouble(item,"quoteVolume"), price = jdouble(item,"weightedAverage");
            //printf("[%u %f %f %f %f %f %f %f]",timestamp,high,low,open,close,vol,quotevol,price);
            if ( Debuglevel > 2 )
                printf("[%u %d %f]",timestamp,OS_conv_unixtime(&seconds,timestamp),price);
            utc32[i] = timestamp - 12*3600, btcddaily[i] = price * 100.;
        }
        if ( Debuglevel > 2 )
            printf("poloniex.%d\n",n);
        prices777_genspline(&BUNDLE.splines[MAX_CURRENCIES+2],MAX_CURRENCIES+2,"btcdhist",utc32,btcddaily,n<MAX_SPLINES?n:MAX_SPLINES,btcddaily);
    }
    // https://poloniex.com/public?command=returnChartData&currencyPair=BTC_BTCD&start=1405699200&end=9999999999&period=86400
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

int32_t prices777_ecbparse(char *date,double *prices,char *url,int32_t basenum)
{
    char *jsonstr,*relstr,*basestr; int32_t count=0,i,relnum; cJSON *json,*ratesobj,*item; struct destbuf tmp;
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        //if ( Debuglevel > 2 )
            printf("(%s)\n",jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            copy_cJSON(&tmp,jobj(json,"date")), safecopy(date,tmp.buf,64);
            if ( (basestr= jstr(json,"base")) != 0 && strcmp(basestr,CURRENCIES[basenum]) == 0 && (ratesobj= jobj(json,"rates")) != 0 && (item= ratesobj->child) != 0 )
            {
                while ( item != 0 )
                {
                    if ( (relstr= get_cJSON_fieldname(item)) != 0 && (relnum= prices777_basenum(relstr)) >= 0 )
                    {
                        i = basenum*MAX_CURRENCIES + relnum;
                        prices[i] = item->valuedouble;
                        //if ( basenum == JPYNUM )
                        //    prices[i] *= 100.;
                        // else if ( relnum == JPYNUM )
                        //     prices[i] /= 100.;
                        count++;
                        //if ( Debuglevel > 2 )
                            printf("(%02d:%02d %f) ",basenum,relnum,prices[i]);
                    } else printf("cant find.(%s)\n",relstr);//, getchar();
                    item = item->next;
                }
            }
            free_json(json);
        }
        free(jsonstr);
    }
    return(count);
}

int32_t prices777_ecb(char *date,double *prices,int32_t year,int32_t month,int32_t day)
{
    // http://api.fixer.io/latest?base=CNH
    // http://api.fixer.io/2000-01-03?base=USD
    // "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD"
    char baseurl[512],tmpdate[64],url[512],checkdate[16]; int32_t basenum,count,i,iter,nonz;
    checkdate[0] = 0;
    if ( year == 0 )
        strcpy(baseurl,"http://api.fixer.io/latest?base=");
    else
    {
        sprintf(checkdate,"%d-%02d-%02d",year,month,day);
        sprintf(baseurl,"http://api.fixer.io/%s?base=",checkdate);
    }
    count = 0;
    for (iter=0; iter<2; iter++)
    {
        for (basenum=0; basenum<sizeof(CURRENCIES)/sizeof(*CURRENCIES); basenum++)
        {
            if ( strcmp(CURRENCIES[basenum],"XAU") == 0 )
                break;
            if ( iter == 0 )
            {
                sprintf(url,"%s%s",baseurl,CURRENCIES[basenum]);
                count += prices777_ecbparse(basenum == 0 ? date : tmpdate,prices,url,basenum);
                if ( (basenum != 0 && strcmp(tmpdate,date) != 0) || (checkdate[0] != 0 && strcmp(checkdate,date) != 0) )
                {
                    printf("date mismatch (%s) != (%s) or checkdate.(%s)\n",tmpdate,date,checkdate);
                    return(-1);
                }
            }
            else
            {
                for (nonz=i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
                {
                    if ( strcmp(CURRENCIES[i],"XAU") == 0 )
                        break;
                    if ( prices[MAX_CURRENCIES*basenum + i] != 0. )
                        nonz++;
                    //if ( Debuglevel > 2 )
                        printf("%8.5f ",prices[MAX_CURRENCIES*basenum + i]);
                }
                //if ( Debuglevel > 2 )
                    printf("%s.%d %d\n",CURRENCIES[basenum],basenum,nonz);
            }
        }
    }
    return(count);
}

int32_t ecb_matrix(double matrix[32][32],char *date)
{
    FILE *fp=0; int32_t n=0,datenum,year=0,seconds,month=0,day=0,loaded = 0; char fname[64],_date[64];
    if ( date == 0 )
        date = _date, memset(_date,0,sizeof(_date));
    sprintf(fname,"ECB/%s",date), iguana_compatible_path(fname);
    if ( date[0] != 0 && (fp= fopen(fname,"rb")) != 0 )
    {
        if ( fread(matrix,1,sizeof(matrix[0][0])*32*32,fp) == sizeof(matrix[0][0])*32*32 )
            loaded = 1;
        else printf("fread error\n");
        fclose(fp);
    } else printf("ecb_matrix.(%s) load error fp.%p\n",fname,fp);
    if ( loaded == 0 )
    {
        datenum = conv_date(&seconds,date);
        year = datenum / 10000, month = (datenum / 100) % 100, day = (datenum % 100);
        if ( (n= prices777_ecb(date,&matrix[0][0],year,month,day)) > 0 )
        {
            sprintf(fname,"ECB/%s",date), iguana_compatible_path(fname);
            if ( (fp= fopen(fname,"wb")) != 0 )
            {
                if ( fwrite(matrix,1,sizeof(matrix[0][0])*32*32,fp) == sizeof(matrix[0][0])*32*32 )
                    loaded = 1;
                fclose(fp);
            }
        } else printf("peggy_matrix error loading %d.%d.%d\n",year,month,day);
    }
    if ( loaded == 0 && n == 0 )
    {
        printf("peggy_matrix couldnt process loaded.%d n.%d\n",loaded,n);
        return(-1);
    }
    //"2000-01-03"
    if ( (datenum= conv_date(&seconds,date)) < 0 )
        return(-1);
    printf("loaded.(%s) nonz.%d (%d %d %d) datenum.%d\n",date,n,year,month,day,datenum);
    return(datenum);
}

void price777_update(double *btcusdp,double *btcdbtcp)
{
    int32_t i,n,seconds,datenum; uint32_t timestamp; char url[1024],*dstr,*str;
    double btcddaily=0.,btcusd=0.,ask,high,low,bid,close,vol,quotevol,open,price = 0.;
    //cJSON *btcdtrades,*btcdtrades2,*,*bitcoincharts,;
    cJSON *quandl,*btcdhist,*array,*item,*bitcoinave,*blockchaininfo,*coindesk=0;
    //btcdtrades = url_json("https://poloniex.com/public?command=returnTradeHistory&currencyPair=BTC_BTCD");
    //btcdtrades2 = url_json("https://bittrex.com/api/v1.1/public/getmarkethistory?market=BTC-BTCD&count=50");
    bitcoinave = url_json("https://api.bitcoinaverage.com/ticker/USD/");
    //bitcoincharts = url_json("http://api.bitcoincharts.com/v1/weighted_prices.json");
    blockchaininfo = url_json("https://blockchain.info/ticker");
    coindesk = url_json("http://api.coindesk.com/v1/bpi/historical/close.json");
    sprintf(url,"https://poloniex.com/public?command=returnChartData&currencyPair=BTC_BTCD&start=%ld&end=9999999999&period=86400",(long)(time(NULL)-2*3600*24));
    quandl = url_json("https://www.quandl.com/api/v1/datasets/BAVERAGE/USD.json?rows=1");
    if ( quandl != 0 && (str= jstr(quandl,"updated_at")) != 0 && (datenum= conv_date(&seconds,str)) > 0 && (array= jarray(&n,quandl,"data")) != 0 )
    {
        //printf("datenum.%d data.%d %d\n",datenum,n,cJSON_GetArraySize(array));
        for (i=0; i<1; i++)
        {
            // ["Date","24h Average","Ask","Bid","Last","Total Volume"]
            // ["2015-07-25",289.27,288.84,288.68,288.87,44978.61]
            item = jitem(array,i);
            if ( (dstr= jstr(jitem(item,0),0)) != 0 && (datenum= conv_date(&seconds,dstr)) > 0 )
            {
                btcusd = price = jdouble(jitem(item,1),0), ask = jdouble(jitem(item,2),0), bid = jdouble(jitem(item,3),0);
                close = jdouble(jitem(item,4),0), vol = jdouble(jitem(item,5),0);
                //fprintf(stderr,"%d.[%d %f %f %f %f %f].%d ",i,datenum,price,ask,bid,close,vol,n);
            }
        }
    }
    price = 0.;
    for (i=n=0; i<BUNDLE.num; i++)
    {
        if ( strcmp(BUNDLE.ptrs[i]->lbase,"btcd") == 0 && strcmp(BUNDLE.ptrs[i]->lrel,"btc") == 0 && BUNDLE.ptrs[i]->lastprice != 0. )
        {
            price += BUNDLE.ptrs[i]->lastprice;
            n++;
        }
    }
    if ( n != 0 )
    {
        price /= n;
        *btcdbtcp = price;
        //printf("set BTCD price %f\n",price);
        BUNDLE.btcdbtc = price;
    }
    else
    {
        btcdhist = url_json(url);
        //{"date":1406160000,"high":0.01,"low":0.00125,"open":0.01,"close":0.001375,"volume":1.50179994,"quoteVolume":903.58818412,"weightedAverage":0.00166204},
        if ( btcdhist != 0 && (array= jarray(&n,btcdhist,0)) != 0 )
        {
            //printf("GOT.(%s)\n",cJSON_Print(array));
            for (i=0; i<1; i++)
            {
                item = jitem(array,i);
                timestamp = juint(item,"date"), high = jdouble(item,"high"), low = jdouble(item,"low"), open = jdouble(item,"open");
                close = jdouble(item,"close"), vol = jdouble(item,"volume"), quotevol = jdouble(item,"quoteVolume"), price = jdouble(item,"weightedAverage");
                //printf("[%u %f %f %f %f %f %f %f]",timestamp,high,low,open,close,vol,quotevol,price);
                //printf("[%u %d %f]",timestamp,OS_conv_unixtime(&seconds,timestamp),price);
                btcddaily = price;
                if ( btcddaily != 0 )
                    BUNDLE.btcdbtc = *btcdbtcp = btcddaily;
            }
            //printf("poloniex.%d\n",n);
        }
        if ( btcdhist != 0 )
            free_json(btcdhist);
    }
    // https://blockchain.info/ticker
    /*
     {
     "USD" : {"15m" : 288.22, "last" : 288.22, "buy" : 288.54, "sell" : 288.57,  "symbol" : "$"},
     "ISK" : {"15m" : 38765.88, "last" : 38765.88, "buy" : 38808.92, "sell" : 38812.95,  "symbol" : "kr"},
     "HKD" : {"15m" : 2234, "last" : 2234, "buy" : 2236.48, "sell" : 2236.71,  "symbol" : "$"},
     "TWD" : {"15m" : 9034.19, "last" : 9034.19, "buy" : 9044.22, "sell" : 9045.16,  "symbol" : "NT$"},
     "CHF" : {"15m" : 276.39, "last" : 276.39, "buy" : 276.69, "sell" : 276.72,  "symbol" : "CHF"},
     "EUR" : {"15m" : 262.46, "last" : 262.46, "buy" : 262.75, "sell" : 262.78,  "symbol" : "€"},
     "DKK" : {"15m" : 1958.92, "last" : 1958.92, "buy" : 1961.1, "sell" : 1961.3,  "symbol" : "kr"},
     "CLP" : {"15m" : 189160.6, "last" : 189160.6, "buy" : 189370.62, "sell" : 189390.31,  "symbol" : "$"},
     "CAD" : {"15m" : 375.45, "last" : 375.45, "buy" : 375.87, "sell" : 375.91,  "symbol" : "$"},
     "CNY" : {"15m" : 1783.67, "last" : 1783.67, "buy" : 1785.65, "sell" : 1785.83,  "symbol" : "¥"},
     "THB" : {"15m" : 10046.98, "last" : 10046.98, "buy" : 10058.14, "sell" : 10059.18,  "symbol" : "฿"},
     "AUD" : {"15m" : 394.77, "last" : 394.77, "buy" : 395.2, "sell" : 395.25,  "symbol" : "$"},
     "SGD" : {"15m" : 395.08, "last" : 395.08, "buy" : 395.52, "sell" : 395.56,  "symbol" : "$"},
     "KRW" : {"15m" : 335991.51, "last" : 335991.51, "buy" : 336364.55, "sell" : 336399.52,  "symbol" : "₩"},
     "JPY" : {"15m" : 35711.99, "last" : 35711.99, "buy" : 35751.64, "sell" : 35755.35,  "symbol" : "¥"},
     "PLN" : {"15m" : 1082.74, "last" : 1082.74, "buy" : 1083.94, "sell" : 1084.06,  "symbol" : "zł"},
     "GBP" : {"15m" : 185.84, "last" : 185.84, "buy" : 186.04, "sell" : 186.06,  "symbol" : "£"},
     "SEK" : {"15m" : 2471.02, "last" : 2471.02, "buy" : 2473.76, "sell" : 2474.02,  "symbol" : "kr"},
     "NZD" : {"15m" : 436.89, "last" : 436.89, "buy" : 437.37, "sell" : 437.42,  "symbol" : "$"},
     "BRL" : {"15m" : 944.91, "last" : 944.91, "buy" : 945.95, "sell" : 946.05,  "symbol" : "R$"},
     "RUB" : {"15m" : 16695.05, "last" : 16695.05, "buy" : 16713.58, "sell" : 16715.32,  "symbol" : "RUB"}
     }*/
     /*{
        "24h_avg": 281.22,
        "ask": 280.12,
        "bid": 279.33,
        "last": 279.58,
        "timestamp": "Sun, 02 Aug 2015 09:36:34 -0000",
        "total_vol": 39625.8
    }*/
  
    if ( bitcoinave != 0 )
    {
        if ( (price= jdouble(bitcoinave,"24h_avg")) > SMALLVAL )
        {
            //printf("bitcoinave %f %f\n",btcusd,price);
            dxblend(&btcusd,price,0.5);
        }
        free_json(bitcoinave);
    }
    if ( quandl != 0 )
        free_json(quandl);
    if ( coindesk != 0 )
        free_json(coindesk);
    if ( blockchaininfo != 0 )
    {
        if ( (item= jobj(blockchaininfo,"USD")) != 0 && item != 0 && (price= jdouble(item,"15m")) > SMALLVAL )
        {
            //printf("blockchaininfo %f %f\n",btcusd,price);
            dxblend(&btcusd,price,0.5);
        }
        free_json(blockchaininfo);
    }
    if ( btcusd != 0 )
        BUNDLE.btcusd = *btcusdp = btcusd;
    
    
    // https://poloniex.com/public?command=returnChartData&currencyPair=BTC_BTCD&start=1405699200&end=9999999999&period=86400

    // https://poloniex.com/public?command=returnTradeHistory&currencyPair=BTC_BTCD
    //https://bittrex.com/api/v1.1/public/getmarkethistory?market=BTC-BTCD&count=50
    /*{"success":true,"message":"","result":[{"Id":8551089,"TimeStamp":"2015-07-25T16:00:41.597","Quantity":59.60917089,"Price":0.00642371,"Total":0.38291202,"FillType":"FILL","OrderType":"BUY"},{"Id":8551088,"TimeStamp":"2015-07-25T16:00:41.597","Quantity":7.00000000,"Price":0.00639680,"Total":0.04477760,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8551087,"TimeStamp":"2015-07-25T16:00:41.597","Quantity":6.51000000,"Price":0.00639679,"Total":0.04164310,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8551086,"TimeStamp":"2015-07-25T16:00:41.597","Quantity":6.00000000,"Price":0.00633300,"Total":0.03799800,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8551085,"TimeStamp":"2015-07-25T16:00:41.593","Quantity":4.76833955,"Price":0.00623300,"Total":0.02972106,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8551084,"TimeStamp":"2015-07-25T16:00:41.593","Quantity":5.00000000,"Price":0.00620860,"Total":0.03104300,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8551083,"TimeStamp":"2015-07-25T16:00:41.593","Quantity":4.91803279,"Price":0.00620134,"Total":0.03049839,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8551082,"TimeStamp":"2015-07-25T16:00:41.593","Quantity":4.45166432,"Price":0.00619316,"Total":0.02756986,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8551081,"TimeStamp":"2015-07-25T16:00:41.59","Quantity":2.00000000,"Price":0.00619315,"Total":0.01238630,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547525,"TimeStamp":"2015-07-25T06:20:43.69","Quantity":1.23166045,"Price":0.00623300,"Total":0.00767693,"FillType":"FILL","OrderType":"BUY"},{"Id":8547524,"TimeStamp":"2015-07-25T06:20:43.69","Quantity":5.00000000,"Price":0.00613300,"Total":0.03066500,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547523,"TimeStamp":"2015-07-25T06:20:43.687","Quantity":10.00000000,"Price":0.00609990,"Total":0.06099900,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547522,"TimeStamp":"2015-07-25T06:20:43.687","Quantity":0.12326502,"Price":0.00609989,"Total":0.00075190,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547521,"TimeStamp":"2015-07-25T06:20:43.687","Quantity":3.29000000,"Price":0.00609989,"Total":0.02006863,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547520,"TimeStamp":"2015-07-25T06:20:43.687","Quantity":5.00000000,"Price":0.00604400,"Total":0.03022000,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547519,"TimeStamp":"2015-07-25T06:20:43.683","Quantity":12.80164947,"Price":0.00603915,"Total":0.07731108,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547518,"TimeStamp":"2015-07-25T06:20:43.683","Quantity":10.00000000,"Price":0.00602715,"Total":0.06027150,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547517,"TimeStamp":"2015-07-25T06:20:43.683","Quantity":4.29037397,"Price":0.00600000,"Total":0.02574224,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547516,"TimeStamp":"2015-07-25T06:20:43.683","Quantity":77.55994092,"Price":0.00598921,"Total":0.46452277,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547515,"TimeStamp":"2015-07-25T06:20:43.68","Quantity":0.08645064,"Price":0.00598492,"Total":0.00051740,"FillType":"PARTIAL_FILL","OrderType":"BUY"}]}
     */
    
    // https://api.bitcoinaverage.com/ticker/global/all
    /* {
     "AED": {
     "ask": 1063.28,
     "bid": 1062.1,
     "last": 1062.29,
     "timestamp": "Sat, 25 Jul 2015 17:13:14 -0000",
     "volume_btc": 0.0,
     "volume_percent": 0.0
     },*/
    
    // http://api.bitcoincharts.com/v1/weighted_prices.json
    // {"USD": {"7d": "279.79", "30d": "276.05", "24h": "288.55"}, "IDR": {"7d": "3750799.88", "30d": "3636926.02", "24h": "3860769.92"}, "ILS": {"7d": "1033.34", "30d": "1031.58", "24h": "1092.36"}, "GBP": {"7d": "179.51", "30d": "175.30", "24h": "185.74"}, "DKK": {"30d": "1758.61"}, "CAD": {"7d": "364.04", "30d": "351.27", "24h": "376.12"}, "MXN": {"30d": "4369.33"}, "XRP": {"7d": "35491.70", "30d": "29257.39", "24h": "36979.02"}, "SEK": {"7d": "2484.50", "30d": "2270.94"}, "SGD": {"7d": "381.93", "30d": "373.69", "24h": "393.94"}, "HKD": {"7d": "2167.99", "30d": "2115.77", "24h": "2232.12"}, "AUD": {"7d": "379.42", "30d": "365.85", "24h": "394.93"}, "CHF": {"30d": "250.61"}, "timestamp": 1437844509, "CNY": {"7d": "1724.99", "30d": "1702.32", "24h": "1779.48"}, "LTC": {"7d": "67.46", "30d": "51.97", "24h": "61.61"}, "NZD": {"7d": "425.01", "30d": "409.33", "24h": "437.86"}, "THB": {"30d": "8632.82"}, "EUR": {"7d": "257.32", "30d": "249.88", "24h": "263.42"}, "ARS": {"30d": "3271.98"}, "NOK": {"30d": "2227.54"}, "RUB": {"7d": "16032.32", "30d": "15600.38", "24h": "16443.39"}, "INR": {"30d": "16601.17"}, "JPY": {"7d": "34685.73", "30d": "33617.77", "24h": "35652.79"}, "CZK": {"30d": "6442.13"}, "BRL": {"7d": "946.76", "30d": "900.77", "24h": "964.09"}, "NMC": {"7d": "454.06", "30d": "370.39", "24h": "436.71"}, "PLN": {"7d": "1041.81", "30d": "1024.96", "24h": "1072.49"}, "ZAR": {"30d": "3805.55"}}
}

double blend_price(double *volp,double wtA,cJSON *jsonA,double wtB,cJSON *jsonB)
{
    //A.{"ticker":{"base":"BTS","target":"CNY","price":"0.02958291","volume":"3128008.39295500","change":"0.00019513","markets":[{"market":"BTC38","price":"0.02960000","volume":3051650.682955},{"market":"Bter","price":"0.02890000","volume":76357.71}]},"timestamp":1438490881,"success":true,"error":""}
    // B.{"id":"bts\/cny","price":"0.02940000","price_before_24h":"0.02990000","volume_first":"3048457.6857147217","volume_second":"90629.45859575272","volume_btc":"52.74","best_market":"btc38","latest_trade":"2015-08-02 03:57:38","coin1":"BitShares","coin2":"CNY","markets":[{"market":"btc38","price":"0.02940000","volume":"3048457.6857147217","volume_btc":"52.738317962865"},{"market":"bter","price":"0.04350000","volume":"0","volume_btc":"0"}]}
    double priceA,priceB,priceB24,price,volA,volB; cJSON *obj;
    priceA = priceB = priceB24= price = volA = volB = 0.;
    if ( jsonA != 0 && (obj= jobj(jsonA,"ticker")) != 0 )
    {
        priceA = jdouble(obj,"price");
        volA = jdouble(obj,"volume");
    }
    if ( jsonB != 0 )
    {
        priceB = jdouble(jsonB,"price");
        priceB24 = jdouble(jsonB,"price_before_24h");
        volB = jdouble(jsonB,"volume_first");
    }
    //printf("priceA %f volA %f, priceB %f %f volB %f\n",priceA,volA,priceB,priceB24,volB);
    if ( priceB > SMALLVAL && priceB24 > SMALLVAL )
        priceB = (priceB * .1) + (priceB24 * .9);
    else if ( priceB < SMALLVAL )
        priceB = priceB24;
    if ( priceA*volA < SMALLVAL )
        price = priceB;
    else if ( priceB*volB < SMALLVAL )
        price = priceA;
    else price = (wtA * priceA) + (wtB * priceB);
    *volp = (volA + volB);
    return(price);
}

void _crypto_update(double cryptovols[2][8][2],struct prices777_data *dp,int32_t selector,int32_t peggyflag)
{
    char *cryptonatorA = "https://www.cryptonator.com/api/full/%s-%s"; //unity-btc
    char *cryptocoinchartsB = "http://api.cryptocoincharts.info/tradingPair/%s_%s"; //bts_btc
    char *cryptostrs[9] = { "btc", "nxt", "unity", "eth", "ltc", "xmr", "bts", "xcp", "etc" };
    int32_t iter,i,j; double btcusd,btcdbtc,cnyusd,prices[8][2],volumes[8][2];
    char base[16],rel[16],url[512],*str; cJSON *jsonA,*jsonB;
    if ( peggyflag != 0 )
    {
        cnyusd = BUNDLE.cnyusd;
        btcusd = BUNDLE.btcusd;
        btcdbtc = BUNDLE.btcdbtc;
        //printf("update with btcusd %f btcd %f cnyusd %f cnybtc %f\n",btcusd,btcdbtc,cnyusd,cnyusd/btcusd);
        if ( btcusd < SMALLVAL || btcdbtc < SMALLVAL )
        {
            price777_update(&btcusd,&btcdbtc);
            printf("price777_update with btcusd %f btcd %f\n",btcusd,btcdbtc);
        }
        memset(prices,0,sizeof(prices));
        memset(volumes,0,sizeof(volumes));
        for (j=0; j<sizeof(cryptostrs)/sizeof(*cryptostrs); j++)
        {
            str = cryptostrs[j];
            if ( strcmp(str,"etc") == 0 )
            {
                if ( prices[3][0] > SMALLVAL )
                    break;
                i = 3;
            } else i = j;
            for (iter=0; iter<1; iter++)
            {
                if ( i == 0 && iter == 0 )
                    strcpy(base,"btcd"), strcpy(rel,"btc");
                else strcpy(base,str), strcpy(rel,iter==0?"btc":"cny");
                //if ( selector == 0 )
                {
                    sprintf(url,cryptonatorA,base,rel);
                    jsonA = url_json(url);
                }
                //else
                {
                    sprintf(url,cryptocoinchartsB,base,rel);
                    jsonB = url_json(url);
                }
                prices[i][iter] = blend_price(&volumes[i][iter],0.4,jsonA,0.6,jsonB);
                if ( iter == 1 )
                {
                    if ( btcusd > SMALLVAL )
                    {
                        prices[i][iter] *= cnyusd / btcusd;
                        volumes[i][iter] *= cnyusd / btcusd;
                    } else prices[i][iter] = volumes[i][iter] = 0.;
                }
                cryptovols[0][i][iter] = _pairaved(cryptovols[0][i][iter],prices[i][iter]);
                cryptovols[1][i][iter] = _pairaved(cryptovols[1][i][iter],volumes[i][iter]);
                if ( Debuglevel > 2 )
                    printf("(%f %f).%d:%d ",cryptovols[0][i][iter],cryptovols[1][i][iter],i,iter);
                //if ( cnyusd < SMALLVAL || btcusd < SMALLVAL )
                //    break;
            }
        }
    }
}

void crypto_update(int32_t peggyflag)
{
    _crypto_update(BUNDLE.cryptovols,&BUNDLE.data,1,peggyflag);
    while ( 1 )
    {
        _crypto_update(BUNDLE.cryptovols,&BUNDLE.data,1,peggyflag);
        sleep(100);
    }
}

void prices777_RTupdate(double cryptovols[2][8][2],double RTmetals[4],double *RTprices,struct prices777_data *dp)
{
    char *cryptostrs[8] = { "btc", "nxt", "unity", "eth", "ltc", "xmr", "bts", "xcp" };
    int32_t iter,i,c,baserel,basenum,relnum; double cnyusd,btcusd,btcdbtc,bid,ask,price,vol,prices[8][2],volumes[8][2];
    char base[16],rel[16];
    price777_update(&btcusd,&btcdbtc);
    memset(prices,0,sizeof(prices));
    memset(volumes,0,sizeof(volumes));
    for (i=0; i<sizeof(cryptostrs)/sizeof(*cryptostrs); i++)
        for (iter=0; iter<2; iter++)
            prices[i][iter] = cryptovols[0][i][iter], volumes[i][iter] = cryptovols[1][i][iter];
    if ( prices[0][0] > SMALLVAL )
        dxblend(&btcdbtc,prices[0][0],.9);
    dxblend(&dp->btcdbtc,btcdbtc,.995);
    if ( BUNDLE.btcdbtc < SMALLVAL )
        BUNDLE.btcdbtc = dp->btcdbtc;
    if ( (cnyusd= BUNDLE.cnyusd) > SMALLVAL )
    {
        if ( prices[0][1] > SMALLVAL )
        {
            //printf("cnyusd %f, btccny %f -> btcusd %f %f\n",cnyusd,prices[0][1],prices[0][1]*cnyusd,btcusd);
            btcusd = prices[0][1] * cnyusd;
            if ( dp->btcusd < SMALLVAL )
                dp->btcusd = btcusd;
            else dxblend(&dp->btcusd,btcusd,.995);
            if ( BUNDLE.btcusd < SMALLVAL )
                BUNDLE.btcusd = dp->btcusd;
            if ( BUNDLE.data.btcusd < SMALLVAL )
                BUNDLE.data.btcusd = dp->btcusd;
            printf("cnyusd %f, btccny %f -> btcusd %f %f -> %f %f %f\n",cnyusd,prices[0][1],prices[0][1]*cnyusd,btcusd,dp->btcusd,BUNDLE.btcusd,BUNDLE.data.btcusd);
        }
    }
    for (i=1; i<sizeof(cryptostrs)/sizeof(*cryptostrs); i++)
    {
        if ( (vol= volumes[i][0]+volumes[i][1]) > SMALLVAL )
        {
            price = ((prices[i][0] * volumes[i][0]) + (prices[i][1] * volumes[i][1])) / vol;
            if ( Debuglevel > 2 )
                printf("%s %f v%f + %f v%f -> %f %f\n",cryptostrs[i],prices[i][0],volumes[i][0],prices[i][1],volumes[i][1],price,dp->cryptos[i]);
            dxblend(&dp->cryptos[i],price,.995);
        }
    }
    btcusd = BUNDLE.btcusd;
    btcdbtc = BUNDLE.btcdbtc;
    if ( Debuglevel > 2 )
        printf("    update with btcusd %f btcd %f\n",btcusd,btcdbtc);
    if ( btcusd < SMALLVAL || btcdbtc < SMALLVAL )
    {
        price777_update(&btcusd,&btcdbtc);
        if ( Debuglevel > 2 )
            printf("     price777_update with btcusd %f btcd %f\n",btcusd,btcdbtc);
    } else BUNDLE.btcusd = btcusd, BUNDLE.btcdbtc = btcdbtc;
    for (c=0; c<sizeof(CONTRACTS)/sizeof(*CONTRACTS); c++)
    {
        for (iter=0; iter<3; iter++)
        {
            switch ( iter )
            {
                case 0: bid = dp->tbids[c], ask = dp->tasks[c]; break;
                case 1: bid = dp->fbids[c], ask = dp->fasks[c]; break;
                case 2: bid = dp->ibids[c], ask = dp->iasks[c]; break;
            }
             if ( (price= _pairaved(bid,ask)) > SMALLVAL )
            {
                if ( Debuglevel > 2 )
                    printf("%.6f ",price);
                dxblend(&RTprices[c],price,.995);
                if ( 0 && (baserel= prices777_ispair(base,rel,CONTRACTS[c])) >= 0 )
                {
                    basenum = (baserel >> 8) & 0xff, relnum = baserel & 0xff;
                    if ( basenum < 32 && relnum < 32 )
                    {
                        //printf("%s.%d %f <- %f\n",CONTRACTS[c],c,RTmatrix[basenum][relnum],RTprices[c]);
                        //dxblend(&RTmatrix[basenum][relnum],RTprices[c],.999);
                    }
                }
                if ( strcmp(CONTRACTS[c],"XAUUSD") == 0 )
                    dxblend(&RTmetals[0],price,.995);
            }
        }
    }
    for (i=0; i<sizeof(Yahoo_metals)/sizeof(*Yahoo_metals); i++)
        if ( BUNDLE.data.metals[i] != 0 )
            dxblend(&RTmetals[i],BUNDLE.data.metals[i],.995);
}

int32_t prices777_getmatrix(double *basevals,double *btcusdp,double *btcdbtcp,double Hmatrix[32][32],double *RTprices,char *contracts[],int32_t num,uint32_t timestamp)
{
    int32_t i,j,c; char name[16]; double btcusd,btcdbtc;
    memcpy(Hmatrix,BUNDLE.data.ecbmatrix,sizeof(BUNDLE.data.ecbmatrix));
    prices777_calcmatrix(Hmatrix);
    /*for (i=0; i<32; i++)
    {
        for (j=0; j<32; j++)
            printf("%.6f ",Hmatrix[i][j]);
        printf("%s\n",CURRENCIES[i]);
    }*/
    btcusd = BUNDLE.btcusd;
    btcdbtc = BUNDLE.btcdbtc;
    if ( btcusd > SMALLVAL )
        dxblend(btcusdp,btcusd,.9);
    if ( btcdbtc > SMALLVAL )
        dxblend(btcdbtcp,btcdbtc,.9);
    // char *cryptostrs[8] = { "btc", "nxt", "unity", "eth", "ltc", "xmr", "bts", "xcp" };
    // "BTCUSD", "NXTBTC", "SuperNET", "ETHBTC", "LTCBTC", "XMRBTC", "BTSBTC", "XCPBTC",  // BTC priced
    for (i=0; i<num; i++)
    {
        if ( contracts[i] == 0 )
            continue;
        if ( i == num-1 && strcmp(contracts[i],"BTCUSD") == 0 )
        {
            RTprices[i] = *btcusdp;
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
            RTprices[i] = BUNDLE.data.cryptos[1];
        else if ( strcmp(contracts[i],"SuperNET") == 0 )
            RTprices[i] = BUNDLE.data.cryptos[2];
        else if ( strcmp(contracts[i],"ETHBTC") == 0 )
            RTprices[i] = BUNDLE.data.cryptos[3];
        else if ( strcmp(contracts[i],"LTCBTC") == 0 )
            RTprices[i] = BUNDLE.data.cryptos[4];
        else if ( strcmp(contracts[i],"XMRBTC") == 0 )
            RTprices[i] = BUNDLE.data.cryptos[5];
        else if ( strcmp(contracts[i],"BTSBTC") == 0 )
            RTprices[i] = BUNDLE.data.cryptos[6];
        else if ( strcmp(contracts[i],"XCPBTC") == 0 )
            RTprices[i] = BUNDLE.data.cryptos[7];
        else if ( i < 32 )
        {
            basevals[i] = Hmatrix[i][i];
            if ( Debuglevel > 2 )
                printf("(%s %f).%d ",CURRENCIES[i],basevals[i],i);
        }
        else if ( (c= prices777_contractnum(contracts[i],0)) >= 0 )
        {
            RTprices[i] = BUNDLE.data.RTprices[c];
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
                    RTprices[i] = BUNDLE.data.RTmetals[j];
                    break;
                }
            }
        }
        if ( Debuglevel > 2 )
            printf("(%f %f) i.%d num.%d %s %f\n",*btcusdp,*btcdbtcp,i,num,contracts[i],RTprices[i]);
        //printf("RT.(%s %f) ",contracts[i],RTprices[i]);
    }
    return(BUNDLE.data.ecbdatenum);
}

int32_t prices_idle(int32_t peggyflag,int32_t idlegap)
{
    static double lastupdate,lastdayupdate; static int32_t didinit; static portable_mutex_t mutex;
    int32_t i,datenum; struct prices777_data *dp = &BUNDLE.tmp;
    *dp = BUNDLE.data;
    if ( didinit == 0 )
    {
        portable_mutex_init(&mutex);
        prices777_init(BUNDLE.jsonstr,peggyflag);
        didinit = 1;
        if ( peggyflag != 0 )
        {
            int32_t opreturns_init(uint32_t blocknum,uint32_t blocktimestamp,char *path);
            opreturns_init(0,(uint32_t)time(NULL),"peggy");
        }
    }
    if ( peggyflag != 0 && milliseconds() > lastupdate + (1000*idlegap) )
    {
        lastupdate = milliseconds();
        if ( milliseconds() > lastdayupdate + 60000*60 )
        {
            lastdayupdate = milliseconds();
            if ( (datenum= ecb_matrix(dp->ecbmatrix,dp->edate)) > 0 )
            {
                dp->ecbdatenum = datenum;
                dp->ecbyear = dp->ecbdatenum / 10000,  dp->ecbmonth = (dp->ecbdatenum / 100) % 100,  dp->ecbday = (dp->ecbdatenum % 100);
                expand_datenum(dp->edate,datenum);
                memcpy(dp->RTmatrix,dp->ecbmatrix,sizeof(dp->RTmatrix));
            }
        }
        for (i=0; i<sizeof(Yahoo_metals)/sizeof(*Yahoo_metals); i++)
            BUNDLE.data.metals[i] = prices777_yahoo(Yahoo_metals[i]);
        BUNDLE.truefxidnum = prices777_truefx(dp->tmillistamps,dp->tbids,dp->tasks,dp->topens,dp->thighs,dp->tlows,BUNDLE.truefxuser,BUNDLE.truefxpass,(uint32_t)BUNDLE.truefxidnum);
        prices777_fxcm(dp->flhlogmatrix,dp->flogmatrix,dp->fbids,dp->fasks,dp->fhighs,dp->flows);
        prices777_instaforex(dp->ilogmatrix,dp->itimestamps,dp->ibids,dp->iasks);
        double btcdbtc,btcusd;
        price777_update(&btcusd,&btcdbtc);
        if ( btcusd > SMALLVAL )
            dxblend(&dp->btcusd,btcusd,0.99);
        if ( btcdbtc > SMALLVAL )
            dxblend(&dp->btcdbtc,btcdbtc,0.99);
        if ( BUNDLE.data.btcusd == 0 )
            BUNDLE.data.btcusd = dp->btcusd;
        if ( BUNDLE.data.btcdbtc == 0 )
            BUNDLE.data.btcdbtc = dp->btcdbtc;
        if ( dp->ecbmatrix[USD][USD] > SMALLVAL && dp->ecbmatrix[CNY][CNY] > SMALLVAL )
            BUNDLE.cnyusd = (dp->ecbmatrix[CNY][CNY] / dp->ecbmatrix[USD][USD]);
        portable_mutex_lock(&mutex);
        BUNDLE.data = *dp;
        portable_mutex_unlock(&mutex);
        //kv777_write(BUNDLE.kv,"data",5,&BUNDLE.data,sizeof(BUNDLE.data));
        prices777_RTupdate(BUNDLE.cryptovols,BUNDLE.data.RTmetals,BUNDLE.data.RTprices,&BUNDLE.data);
        //printf("update finished\n");
        void peggy();
        peggy();
        didinit = 1;
    }
    return(0);
}

void prices777_sim(uint32_t now,int32_t numiters)
{
    double btca,btcb,btcd,btc,btcdusd,basevals[MAX_CURRENCIES],btcdprices[MAX_CURRENCIES+1];
    int32_t i,j,datenum,seconds; uint32_t timestamp,starttime = (uint32_t)time(NULL);
    for (i=0; i<numiters; i++)
    {
        timestamp = now - (rand() % (3600*24*64));
        btca = 1000. * prices777_splineval(&BUNDLE.splines[MAX_CURRENCIES+0],timestamp,0);
        btcb = 1000. * prices777_splineval(&BUNDLE.splines[MAX_CURRENCIES+1],timestamp,0);
        btc = _pairaved(btca,btcb);
        btcd = .01 * prices777_splineval(&BUNDLE.splines[MAX_CURRENCIES+2],timestamp,0);
        btcdusd = (btc * btcd);
        datenum = OS_conv_unixtime(&seconds,timestamp);
        for (j=0; j<MAX_CURRENCIES; j++)
        {
            basevals[j] = prices777_splineval(&BUNDLE.splines[j],timestamp,0);
            btcdprices[j] = basevals[j] / (btcdusd * basevals[USD]);
        }
        if ( (i % 100000) == 0 )
        {
            printf("%d:%02d:%02d %.8f %.8f -> USD %.8f (EURUSD %.8f %.8f) ",datenum,seconds/3600,(seconds%3600)/60,btc,btcd,btcdusd,btcdprices[EUR]/btcdprices[USD],basevals[EUR]/basevals[USD]);
            for (j=0; j<MAX_CURRENCIES; j++)
                printf("%.8f ",btcdprices[j]);
            printf("\n");
        }
    }
    printf("sim took %ld seconds\n",(long)(time(NULL) - starttime));
}

void prices777_getlist(char *retbuf)
{
    int32_t i,j; struct prices777 *prices; char pair[16],*jsonstr; cJSON *json,*array,*item;
    json = cJSON_CreateObject();
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
        cJSON_AddItemToArray(array,cJSON_CreateString(CURRENCIES[i]));
    cJSON_AddItemToObject(json,"currency",array);
    array = cJSON_CreateArray();
    for (i=0; i<32; i++)
        for (j=0; j<32; j++)
        {
            if ( i != j )
            {
                sprintf(pair,"%s%s",CURRENCIES[i],CURRENCIES[j]);
                cJSON_AddItemToArray(array,cJSON_CreateString(pair));
            }
        }
    cJSON_AddItemToObject(json,"pairs",array);
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(CONTRACTS)/sizeof(*CONTRACTS); i++)
        cJSON_AddItemToArray(array,cJSON_CreateString(CONTRACTS[i]));
    cJSON_AddItemToObject(json,"contract",array);
    array = cJSON_CreateArray();
    for (i=0; i<BUNDLE.num; i++)
    {
        if ( (prices= BUNDLE.ptrs[i]) != 0 )
        {
            item = cJSON_CreateObject();
            cJSON_AddItemToObject(item,prices->exchange,cJSON_CreateString(prices->contract));
            cJSON_AddItemToObject(item,"base",cJSON_CreateString(prices->base));
            if ( prices->rel[0] != 0 )
                cJSON_AddItemToObject(item,"rel",cJSON_CreateString(prices->rel));
            //printf("(%s) (%s) (%s)\n",prices->contract,prices->base,prices->rel);
            cJSON_AddItemToArray(array,item);
        }
    }
    cJSON_AddItemToObject(json,"result",cJSON_CreateString("success"));
    cJSON_AddItemToObject(json,"list",array);
    jsonstr = cJSON_Print(json), _stripwhite(jsonstr,' '), free_json(json);
    strcpy(retbuf,jsonstr), free(jsonstr);
    printf("list -> (%s)\n",retbuf);
}

