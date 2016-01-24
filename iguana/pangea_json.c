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

#include "pangea777.h"

cJSON *pangea_tablejson(struct game_info *gp)
{
    char ipaddr[64],str[64]; struct tai t; int32_t seconds; cJSON *json = cJSON_CreateObject();
    jaddbits256(json,"tablehash",gp->tablehash);
    expand_ipbits(ipaddr,gp->hostipbits);
    jaddstr(json,"host",ipaddr);
    jaddnum(json,"minbuyin",dstr(gp->minbuyin));
    jaddnum(json,"maxbuyin",dstr(gp->maxbuyin));
    jaddnum(json,"minplayers",gp->minplayers);
    jaddnum(json,"maxplayers",gp->maxplayers);
    jaddnum(json,"M",gp->M);
    jaddnum(json,"N",gp->N);
    jaddnum(json,"numcards",gp->numcards);
    jaddnum(json,"rake",(double)gp->rakemillis/10.);
    jaddnum(json,"maxrake",dstr(gp->maxrake));
    jaddnum(json,"hostrake",dstr(gp->hostrake));
    jaddnum(json,"pangearake",dstr(gp->pangearake));
    jaddnum(json,"bigblind",dstr(gp->bigblind));
    jaddnum(json,"ante",dstr(gp->ante));
    if ( gp->opentime != 0 )
    {
        OS_conv_unixtime(&t,&seconds,gp->opentime);
        jaddstr(json,"opentime",utc_str(str,t));
        if ( gp->started != 0 )
        {
            OS_conv_unixtime(&t,&seconds,gp->started);
            jaddstr(json,"started",utc_str(str,t));
            if ( gp->finished != 0 )
            {
                OS_conv_unixtime(&t,&seconds,gp->finished);
                jaddstr(json,"finished",utc_str(str,t));
            }
        }
    }
    return(json);
}

void pangea_gamecreate(struct game_info *gp,uint32_t timestamp,bits256 tablehash,cJSON *json)
{
    gp->gamehash = calc_categoryhashes(0,"pangea",0);
    gp->tablehash = tablehash;
    gp->hostipbits = calc_ipbits(jstr(json,"myipaddr"));
    gp->minbuyin = jdouble(json,"minbuyin") * SATOSHIDEN;
    gp->maxbuyin = jdouble(json,"maxbuyin") * SATOSHIDEN;
    gp->minplayers = juint(json,"minplayers");
    gp->maxplayers = juint(json,"maxplayers");
    if ( (gp->N= juint(json,"N")) < gp->minplayers )
        gp->N = gp->minplayers;
    if ( (gp->M= juint(json,"M")) > gp->N )
        gp->M = gp->N;
    if ( (gp->numcards= juint(json,"numcards")) != 52 )
        gp->numcards = 52;
    gp->rakemillis = jdouble(json,"rake") * 10.;
    gp->maxrake = jdouble(json,"maxrake") * SATOSHIDEN;
    gp->hostrake = jdouble(json,"hostrake") * SATOSHIDEN;
    gp->pangearake = jdouble(json,"pangearake") * SATOSHIDEN;
    gp->bigblind = jdouble(json,"bigblind") * SATOSHIDEN;
    gp->ante = jdouble(json,"ante") * SATOSHIDEN;
    gp->opentime = timestamp;
}

int32_t pangea_opentable(struct game_info *gp)
{
    if ( gp->opentime != 0 && gp->started == 0 )
        return(1);
    else if ( gp->finished != 0 )
        return(0);
    else return(-1);
}

cJSON *pangea_lobbyjson(struct supernet_info *myinfo)
{
    struct category_info *cat,*sub,*tmp; struct table_info *tp; cJSON *array,*retjson;
    retjson = cJSON_CreateObject();
    array = cJSON_CreateArray();
    if ( (cat= category_find(calc_categoryhashes(0,"pangea",0),GENESIS_PUBKEY)) != 0 )
    {
        HASH_ITER(hh,cat->sub,sub,tmp)
        {
            if ( (tp= sub->info) != 0 && pangea_opentable(&tp->G) > 0 )
                jaddi(array,pangea_tablejson(&tp->G));
        }
    }
    jadd(retjson,"tables",array);
    return(retjson);
}

int32_t pangea_playerparse(struct player_info *p,cJSON *json)
{
    char *handle,*ipaddr;
    if ( (handle= jstr(json,"handle")) != 0 && strlen(handle) < sizeof(p->handle)-1 )
        strcpy(p->handle,handle);
    p->playerpub = jbits256(json,"playerpub");
    if ( (ipaddr= jstr(json,"myipaddr")) != 0 && is_ipaddr(ipaddr) > 0 )
    {
        p->ipbits = calc_ipbits(ipaddr);
        return(0);
    }
    return(-1);
}

cJSON *pangea_handjson(struct hand_info *hand,uint8_t *holecards,int32_t isbot)
{
    int32_t i,card; char cardAstr[8],cardBstr[8],pairstr[18],cstr[128]; cJSON *array,*json = cJSON_CreateObject();
    array = cJSON_CreateArray();
    cstr[0] = 0;
    for (i=0; i<5; i++)
    {
        if ( (card= hand->community[i]) != 0xff )
        {
            jaddinum(array,card);
            cardstr(&cstr[strlen(cstr)],card);
            strcat(cstr," ");
        }
    }
    jaddstr(json,"community",cstr);
    jadd(json,"cards",array);
    if ( (card= holecards[0]) != 0xff )
    {
        jaddnum(json,"cardA",card);
        cardstr(cardAstr,holecards[0]);
    } else cardAstr[0] = 0;
    if ( (card= holecards[1]) != 0xff )
    {
        jaddnum(json,"cardB",card);
        cardstr(cardBstr,holecards[1]);
    } else cardBstr[0] = 0;
    sprintf(pairstr,"%s %s",cardAstr,cardBstr);
    jaddstr(json,"holecards",pairstr);
    jaddnum(json,"betsize",dstr(hand->betsize));
    jaddnum(json,"lastraise",dstr(hand->lastraise));
    jaddnum(json,"lastbettor",hand->lastbettor);
    jaddnum(json,"numactions",hand->numactions);
    jaddnum(json,"undergun",hand->undergun);
    jaddnum(json,"isbot",isbot);
    jaddnum(json,"cardi",hand->cardi);
    return(json);
}

char *pangea_statusstr(int32_t status)
{
    if ( status == CARDS777_FOLD )
        return("folded");
    else if ( status == CARDS777_ALLIN )
        return("ALLin");
    else return("active");
}

int32_t pangea_countdown(struct table_info *tp,struct player_info *p)
{
    struct hand_info *hand = &tp->hand;
    if ( p != 0 && hand->undergun == p->ind && hand->userinput_starttime != 0 )
        return((int32_t)(hand->userinput_starttime + PANGEA_USERTIMEOUT - time(NULL)));
    else return(-1);
}

cJSON *pangea_tablestatus(struct supernet_info *myinfo,struct table_info *tp)
{
    int64_t sidepots[CARDS777_MAXPLAYERS][CARDS777_MAXPLAYERS],totals[CARDS777_MAXPLAYERS],sum;
    struct player_info *p; int32_t i,n,N,j,countdown,iter; cJSON *item,*array,*json;
    int64_t won[CARDS777_MAXPLAYERS],snapshot[CARDS777_MAXPLAYERS],bets[CARDS777_MAXPLAYERS];
    int64_t total,val; char *handhist,*str; struct game_info *gp; struct hand_info *hand;
    hand = &tp->hand, gp = &tp->G, N = tp->numactive;
    json = cJSON_CreateObject();
    jaddbits256(json,"tablehash",gp->tablehash);
    jadd64bits(json,"myind",tp->priv.myind);
    jaddnum(json,"minbuyin",gp->minbuyin);
    jaddnum(json,"maxbuyin",gp->maxbuyin);
    jaddnum(json,"button",tp->hand.button);
    jaddnum(json,"M",gp->M);
    jaddnum(json,"N",tp->numactive);
    jaddnum(json,"numcards",gp->numcards);
    jaddnum(json,"numhands",tp->numhands);
    jaddnum(json,"rake",(double)gp->rakemillis/10.);
    jaddnum(json,"maxrake",dstr(gp->maxrake));
    jaddnum(json,"hostrake",dstr(gp->hostrake));
    jaddnum(json,"pangearake",dstr(gp->pangearake));
    jaddnum(json,"bigblind",dstr(gp->bigblind));
    jaddnum(json,"ante",dstr(gp->ante));
    array = cJSON_CreateArray();
    for (i=0; i<tp->numactive; i++)
        jaddi64bits(array,tp->active[i]!=0?tp->active[i]->nxt64bits:0);
    jadd(json,"addrs",array);
    total = 0;
    for (iter=0; iter<6; iter++)
    {
        array = cJSON_CreateArray();
        for (i=0; i<tp->numactive; i++)
        {
            val = 0;
            if ( (p= tp->active[i]) != 0 )
            {
                switch ( iter )
                {
                    case 0: val = p->turni; str = "turns"; break;
                    case 1: val = p->balance; str = "balances"; break;
                    case 2: val = p->snapshot; str = "snapshot"; break;
                    case 3: val = p->betstatus; str = "status"; break;
                    case 4: val = p->bets; str = "bets"; break;
                    case 5: val = p->won; str = "won"; break;
                }
            }
            if ( iter == 5 )
                won[i] = val;
            else
            {
            if ( iter == 3 )
                jaddistr(array,pangea_statusstr((int32_t)val));
            else
            {
                if ( iter == 4 )
                    total += val, bets[i] = val;
                else if ( iter == 2 )
                    snapshot[i] = val;
                jaddinum(array,val);
            }
            }
        }
        jadd(json,str,array);
    }
    jaddnum(json,"totalbets",dstr(total));
    for (iter=0; iter<2; iter++)
        if ( (n= pangea_sidepots(myinfo,tp,0,sidepots,iter == 0 ? snapshot : bets)) > 0 && n < N )
        {
            array = cJSON_CreateArray();
            for (i=0; i<n; i++)
            {
                item = cJSON_CreateArray();
                for (sum=j=0; j<N; j++)
                    jaddinum(item,dstr(sidepots[i][j])), sum += sidepots[i][j];
                totals[i] = sum;
                jaddi(array,item);
            }
            jadd(json,iter == 0 ? "pots" : "RTpots",array);
            item = cJSON_CreateArray();
            for (sum=i=0; i<n; i++)
                jaddinum(item,dstr(totals[i])), sum += totals[i];
            jadd(json,iter == 0 ? "potTotals" : "RTpotTotals",item);
            jaddnum(json,iter == 0 ? "sum" : "RTsum",dstr(sum));
        }
    jadd64bits(json,"automuck",tp->priv.automuck);
    jadd64bits(json,"autofold",tp->priv.autofold);
    jadd(json,"hand",pangea_handjson(hand,tp->priv.hole,0));
    if ( (handhist= pangea_dispsummary(myinfo,tp,0,tp->summary,tp->summarysize,tp->G.tablehash,tp->numhands-1,N)) != 0 )
    {
        if ( (item= cJSON_Parse(handhist)) != 0 )
            jadd(json,"actions",item);
        free(handhist);
    }
    if ( (countdown= pangea_countdown(tp,tp->active[tp->priv.myind])) >= 0 )
        jaddnum(json,"timeleft",countdown);
    if ( hand->finished != 0 )
    {
        item = cJSON_CreateObject();
        jaddnum(item,"hostrake",dstr(tp->G.hostrake));
        jaddnum(item,"pangearake",dstr(tp->G.pangearake));
        array = cJSON_CreateArray();
        for (i=0; i<N; i++)
            jaddinum(array,dstr(won[i]));
        jadd(item,"won",array);
        jadd(json,"summary",item);
    }
    return(json);
}

void pangea_playerprint(struct supernet_info *myinfo,struct table_info *tp,int32_t i,int32_t myind)
{
    int32_t countdown; char str[8]; struct player_info *p;
    if ( (p= tp->active[i]) != 0 )
    {
        if ( (countdown= pangea_countdown(tp,tp->active[tp->priv.myind])) >= 0 )
            sprintf(str,"%2d",countdown);
        else str[0] = 0;
        printf("%d: %6s %12.8f %2s  | %12.8f %s\n",i,pangea_statusstr(p->betstatus),dstr(p->bets),str,dstr(p->balance),i == myind ? "<<<<<<<<<<<": "");
    }
}

void pangea_statusprint(struct supernet_info *myinfo,struct table_info *tp,int32_t myind)
{
    int32_t i,N; char handstr[64]; uint8_t handvals[7]; struct hand_info *hand = &tp->hand;
    N = tp->numactive;
    for (i=0; i<N; i++)
        pangea_playerprint(myinfo,tp,i,myind);
    handstr[0] = 0;
    if ( hand->community[0] != hand->community[1] )
    {
        for (i=0; i<5; i++)
            if ( (handvals[i]= hand->community[i]) == 0xff )
                break;
        if ( i == 5 )
        {
            if ( (handvals[5]= tp->priv.hole[0]) != 0xff && (handvals[6]= tp->priv.hole[1]) != 0xff )
                set_handstr(handstr,handvals,1);
        }
    }
    printf("%s\n",handstr);
}


