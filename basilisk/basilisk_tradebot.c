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

// included from basilisk.c

uint32_t basilisk_requestid(struct basilisk_request *rp)
{
    struct basilisk_request R;
    R = *rp;
    R.requestid = R.quoteid = R.quotetime = 0;
    R.destamount = 0;
    R.relaybits = 0;
    memset(R.desthash.bytes,0,sizeof(R.desthash.bytes));
    if ( 0 )
    {
        int32_t i;
        for (i=0; i<sizeof(R); i++)
            printf("%02x",((uint8_t *)&R)[i]);
        printf(" <- crc.%u\n",calc_crc32(0,(void *)&R,sizeof(R)));
        char str[65],str2[65]; printf("B REQUESTID: t.%u r.%u q.%u %s %.8f %s -> %s %.8f %s crc.%u\n",R.timestamp,R.requestid,R.quoteid,R.src,dstr(R.srcamount),bits256_str(str,R.hash),R.dest,dstr(R.destamount),bits256_str(str2,R.desthash),calc_crc32(0,(void *)&R,sizeof(R)));
    }
    return(calc_crc32(0,(void *)&R,sizeof(R)));
}

uint32_t basilisk_quoteid(struct basilisk_request *rp)
{
    struct basilisk_request R;
    R = *rp;
    R.requestid = R.quoteid = R.relaybits = 0;
    return(calc_crc32(0,(void *)&R,sizeof(R)));
}

struct basilisk_request *basilisk_parsejson(struct basilisk_request *rp,cJSON *reqjson)
{
    uint32_t requestid,quoteid;
    memset(rp,0,sizeof(*rp));
    rp->hash = jbits256(reqjson,"hash");
    rp->desthash = jbits256(reqjson,"desthash");
    rp->srcamount = j64bits(reqjson,"srcamount");
    rp->minamount = j64bits(reqjson,"minamount");
    rp->destamount = j64bits(reqjson,"destamount");
    requestid = juint(reqjson,"requestid");
    quoteid = juint(reqjson,"quoteid");
    if ( jstr(reqjson,"relay") != 0 )
        rp->relaybits = (uint32_t)calc_ipbits(jstr(reqjson,"relay"));
    rp->timestamp = juint(reqjson,"timestamp");
    rp->quotetime = juint(reqjson,"quotetime");
    safecopy(rp->src,jstr(reqjson,"src"),sizeof(rp->src));
    safecopy(rp->dest,jstr(reqjson,"dest"),sizeof(rp->dest));
    if ( quoteid != 0 )
    {
        rp->quoteid = basilisk_quoteid(rp);
        if ( quoteid != rp->quoteid )
            printf("basilisk_parsejson quoteid.%u != %u error\n",quoteid,rp->quoteid);
    }
    rp->requestid = basilisk_requestid(rp);
    if ( requestid != rp->requestid )
        printf("basilisk_parsejson requestid.%u != %u error\n",requestid,rp->requestid);
    return(rp);
}

void basilisk_swap_balancingtrade(struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t iambob)
{
    // update balance, compare to target balance, issue balancing trade via central exchanges, if needed 
    if ( iambob != 0 )
    {
        
    }
    else
    {
        
    }
}


struct basilisk_swap *basilisk_request_started(struct supernet_info *myinfo,uint32_t requestid)
{
    int32_t i; struct basilisk_swap *active = 0;
    portable_mutex_lock(&myinfo->DEX_swapmutex);
    for (i=0; i<myinfo->numswaps; i++)
        if ( myinfo->swaps[i]->req.requestid == requestid )
        {
            //printf("REQUEST STARTED.[%d] <- req.%u\n",i,requestid);
            active = myinfo->swaps[i];
            break;
        }
    portable_mutex_unlock(&myinfo->DEX_swapmutex);
    return(active);
}

int32_t basilisk_request_cmpref(struct basilisk_request *ref,struct basilisk_request *rp)
{
    if ( bits256_cmp(rp->hash,ref->hash) != 0 || memcmp(rp->src,ref->src,sizeof(ref->src)) != 0 || memcmp(rp->dest,ref->dest,sizeof(ref->dest)) != 0 || rp->srcamount != ref->srcamount || rp->timestamp != ref->timestamp )
    {
        printf("basilisk_request_listprocess mismatched hash\n");
        return(-1);
    } else return(0);
}

double basilisk_request_listprocess(struct supernet_info *myinfo,struct basilisk_request *issueR,struct basilisk_request *list,int32_t n)
{
    int32_t i,noquoteflag=0,havequoteflag=0,myrequest=0,maxi=-1; uint64_t destamount,minamount = 0,maxamount = 0; uint32_t pendingid=0; struct basilisk_swap *active; double metric = 0.;
    memset(issueR,0,sizeof(*issueR));
    minamount = list[0].minamount;
    //printf("need to verify null quoteid is list[0] requestid.%u quoteid.%u\n",list[0].requestid,list[0].quoteid);
    if ( (active= basilisk_request_started(myinfo,list[0].requestid)) != 0 )
        pendingid = active->req.quoteid;
    if ( bits256_cmp(myinfo->myaddr.persistent,list[0].hash) == 0 ) // my request
        myrequest = 1;
    for (i=0; i<n; i++)
    {
        if ( basilisk_request_cmpref(&list[0],&list[i]) != 0 )
            return(-1);
        if ( list[i].quoteid != 0 )
        {
            if ( bits256_cmp(myinfo->myaddr.persistent,list[i].desthash) == 0 ) // my quoteid
                myrequest |= 2;
            havequoteflag++;
            if ( pendingid == 0 )
            {
                if ( list[i].destamount > maxamount )
                {
                    maxamount = list[i].destamount;
                    maxi = i;
                }
            }
            else if ( active != 0 && pendingid == list[i].quoteid )
            {
            }
        } else noquoteflag++;
    }
    //printf("myrequest.%d pendingid.%u noquoteflag.%d havequoteflag.%d maxi.%d %.8f\n",myrequest,pendingid,noquoteflag,havequoteflag,maxi,dstr(maxamount));
    if ( myrequest == 0 && pendingid == 0 && noquoteflag != 0 )
    {
        double retvals[4],aveprice;
        aveprice = instantdex_avehbla(myinfo,retvals,list[0].src,list[0].dest,1.3 * dstr(list[0].srcamount));
        destamount = 0.99 * aveprice * list[0].srcamount;
        printf("destamount %.8f aveprice %.8f minamount %.8f\n",dstr(destamount),aveprice,dstr(minamount));
        if ( destamount > 0 && destamount >= maxamount && destamount >= minamount )
        {
            metric = 1.;
            *issueR = list[0];
            issueR->desthash = myinfo->myaddr.persistent;
            issueR->destamount = destamount;
            issueR->quotetime = (uint32_t)time(NULL);
        }
    }
    else if ( myrequest != 0 && pendingid == 0 && maxi >= 0 ) // automatch best quote
    {
        if ( minamount != 0 && maxamount > minamount && time(NULL) > BASILISK_DEXDURATION/2 )
        {
            printf("automatch quoteid.%u triggered %.8f > %.8f\n",list[maxi].quoteid,dstr(maxamount),dstr(minamount));
            *issueR = list[maxi];
            if ( minamount > 0 )
                metric = (dstr(maxamount) / dstr(minamount)) - 1.;
            else metric = 1.;
        }
    }
    return(metric);
}

double basilisk_process_results(struct supernet_info *myinfo,struct basilisk_request *issueR,cJSON *retjson,double hwm)
{
    cJSON *array,*item; int32_t i,n,m; struct basilisk_request tmpR,R,refR,list[BASILISK_MAXRELAYS]; double metric=0.;
    if ( (array= jarray(&n,retjson,"result")) != 0 )
    {
        for (i=m=0; i<n; i++)
        {
            item = jitem(array,i);
            if ( i != 0 )
            {
                basilisk_parsejson(&R,item);
                if ( refR.requestid == R.requestid )
                    list[m++] = R;
                else
                {
                    if ( (metric= basilisk_request_listprocess(myinfo,&tmpR,list,m)) > hwm )
                        *issueR = tmpR, hwm = metric;
                    m = 0;
                }
            }
            if ( m < sizeof(list)/sizeof(*list) )
                basilisk_parsejson(&list[m++],item);
        }
        if ( m > 0 && m < sizeof(list)/sizeof(*list) )
            if ( (metric= basilisk_request_listprocess(myinfo,&tmpR,list,m)) > hwm )
                *issueR = tmpR, hwm = metric;
    }
    return(hwm);
}
