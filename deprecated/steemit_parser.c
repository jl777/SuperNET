/******************************************************************************
 * Copyright © 2016 jl777                                                     *
 * ALL RIGHTS RESERVED                                                        *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

int32_t init_startheight(int32_t startheight)
{
    long filesize; int32_t height; char *heightstr;
    if ( (heightstr= OS_filestr(&filesize,TRADEBOT_NAME)) != 0 )
    {
        height = atoi(heightstr);
        free(heightstr);
        if ( height > 0 && height < startheight )
            startheight = height;
    }
    return(startheight);
}

void steemit_history_limitorder(int32_t ind,char *acount,cJSON *opitem)
{
    // hwm.12081 flag.1 limit_order_create ({"owner":"taker","orderid":1469136578,"amount_to_sell":"24.346 SBD","min_to_receive":"7.770 STEEM","fill_or_kill":false,"expiration":"2016-07-24T23:21:24"})
}

void steemit_update_inventory(double *SBD,double *SBDVOL,double *STEEMVOL,double *STEEM,double myvol,char *mycoin,char *other,double othervol,char *othercoin)
{
    if ( strcmp(mycoin,"SBD") == 0 && strcmp(othercoin,"STEEM") == 0 )
    {
        *SBD -= myvol;
        *SBDVOL += myvol;
        *STEEM += othervol;
        *STEEMVOL += othervol;
    }
    else if ( strcmp(mycoin,"STEEM") == 0 && strcmp(othercoin,"SBD") == 0 )
    {
        *STEEM -= myvol;
        *STEEMVOL += myvol;
        *SBD += othervol;
        *SBDVOL += othervol;
    } else printf("steemit_update_inventory: unexpected pair (%s) (%s)\n",mycoin,othercoin);
}

void steemit_history_fillorder(int32_t ind,char *account,cJSON *opitem)
{
    static double SBD,STEEM,SBDVOL,STEEMVOL;
    char *taker,*maker,*takercoin,*makercoin; uint64_t openorderid,fillorderid; double takervol,makervol;
    taker = jstr(opitem,"current_owner");
    fillorderid = j64bits(opitem,"current_orderid");
    takercoin = jstr(opitem,"current_pays");
    maker = jstr(opitem,"open_owner");
    openorderid = j64bits(opitem,"open_orderid");
    makercoin = jstr(opitem,"open_pays");
    if ( taker != 0 && maker != 0 && takercoin != 0 && makercoin != 0 && (strcmp(account,taker) == 0 || strcmp(maker,account) == 0) )
    {
        takervol = atof(takercoin);
        while ( *takercoin != 0 && *takercoin != ' ' )
            takercoin++;
        makervol = atof(makercoin);
        while ( *makercoin != 0 && *makercoin != ' ' )
            makercoin++;
        if ( strcmp(taker,account) == 0 )
        {
            steemit_update_inventory(&SBD,&SBDVOL,&STEEMVOL,&STEEM,takervol,takercoin+1,maker,makervol,makercoin+1);
            printf("%6d %s.(%.6f%s) <-> %s.(%.6f%s) SBD %.6f STEEM %.6f | VOL SBD %.6f STEEM %.6f-> %.6f\n",ind,taker,takervol,takercoin,maker,makervol,makercoin,SBD,STEEM,SBDVOL,STEEMVOL,SBD/STEEM);
        }
        else
        {
            steemit_update_inventory(&SBD,&SBDVOL,&STEEMVOL,&STEEM,takervol,takercoin+1,maker,makervol,makercoin+1);
            printf("%6d %s.(%.6f%s) <-> %s.(%.6f%s) SBD %.6f STEEM %.6f | VOL SBD %.6f STEEM %.6f-> %.6f\n",ind,maker,makervol,makercoin,taker,takervol,takercoin,SBD,STEEM,SBDVOL,STEEMVOL,SBD/STEEM);
        }
    }
    //hwm.12077 flag.1 fill_order ({"current_owner":"enki","current_orderid":3402053187,"current_pays":"19.613 SBD","open_owner":"taker","open_orderid":1469136521,"open_pays":"5.792 STEEM"})
    
}

void steemit_tradehistory(char *account)
{
    int32_t j,n,m,ind,flag = 1,hwm = 0; cJSON *retjson,*result,*item,*oparray,*opitem; char *opstr,*retstr;
    while ( flag != 0 )
    {
        flag = 0;
        if ( (retstr= STEEM_gethistory(account,hwm+1,1)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( (result= jarray(&n,retjson,"result")) != 0 )
                {
                    for (j=0; j<n; j++)
                    {
                        item = jitem(result,j);
                        if ( is_cJSON_Array(item) != 0 && cJSON_GetArraySize(item) == 2 )
                        {
                            ind = jdouble(jitem(item,0),0);
                            //printf("ind.%d from %s\n",ind,jprint(jitem(item,0),0));
                            if ( ind == hwm )
                            {
                                if ( (oparray= jarray(&m,jitem(item,1),"op")) != 0 && m == 2 )
                                {
                                    opstr = jstr(jitem(oparray,0),0);
                                    opitem = jitem(oparray,1);
                                    if ( strcmp(opstr,"limit_order_create") == 0 )
                                        steemit_history_limitorder(hwm,account,opitem);
                                    else if ( strcmp(opstr,"fill_order") == 0 )
                                        steemit_history_fillorder(hwm,account,opitem);
                                    else printf("hwm.%d flag.%d %s (%s)\n",hwm,flag,opstr,jprint(opitem,0));
                                } else printf("unexpected oparray item.%d j.%d (%s)\n",hwm,j,jprint(jitem(item,1),0));
                                hwm++;
                                flag++;
                            } else printf("skip ind.%d when hwm.%d\n",ind,hwm);
                        } else printf("unexpected item.%d j.%d (%s)\n",hwm,j,jprint(item,0));
                    }
                } else printf("no result in (%s)\n",retstr);
                free(retjson);
            } else printf("error.(%s)\n",retstr);
            free(retstr);
        } else printf("null return for hwm.%d\n",hwm);
    }
}

void steemit_pow(int32_t height,int32_t ind,int32_t j,cJSON *json)
{
    // 3417584.1: limit_order_create.({"owner":"taker","orderid":1469129923,"amount_to_sell":"7.770 STEEM","min_to_receive":"25.367 SBD","fill_or_kill":false,"expiration":"2016-07-23T14:20:23"})
}

void steemit_transfer(int32_t height,int32_t ind,int32_t j,cJSON *json)
{
    // 3417584.0: transfer.({"from":"lukestokes","to":"benslayton","amount":"100.000 SBD","memo":"Dude, you're awesome. No need to give back as your rewards are all you. You worked hard on your post and it was perfectly timed. You deserve every bit of the reward you got! :)"})
}

void steemit_limitorder(int32_t height,int32_t ind,int32_t j,cJSON *json)
{
    // 3417584.1: limit_order_create.({"owner":"taker","orderid":1469129923,"amount_to_sell":"7.770 STEEM","min_to_receive":"25.367 SBD","fill_or_kill":false,"expiration":"2016-07-23T14:20:23"})
}

void steemit_cancelorder(int32_t height,int32_t ind,int32_t j,cJSON *json)
{
    // 3418230.1.0: limit_order_cancel.({"owner":"kujira","orderid":1469194992})
}

void steemit_accountupdate(int32_t height,int32_t ind,int32_t j,cJSON *json)
{
    // 3417791.3: account_update.({"account":"hello","owner":{"weight_threshold":2,"account_auths":[["xeroc", 1]],"key_auths":[["STM8GkRiob5ErhxZgaVv7a3tCGUy14Kp2D3zL69LcpHpgnLxDoTTi", 1]]},"active":{"weight_threshold":1,"account_auths":[["xeroc", 1]],"key_auths":[["STM7WkgYMEfMrteCD1e5VyPGu6VbgYa95Q9xRjdQs8M8PgJ1QdQie", 1]]},"posting":{"weight_threshold":1,"account_auths":[["xeroc", 1]],"key_auths":[["STM6YMtZfg7AsiXdxHjZu7CpYBveLjSKQKgw9bcSUsePuWSMk1xTb", 1]]},"memo_key":"STM8MhWjF83aovRRyMVmFeSbiSXfWEyqMhxocvDoSri8MxAdTojWZ","json_metadata":""})
}

void steemit_convert(int32_t height,int32_t ind,int32_t j,cJSON *json)
{
    // 3418042.8.0: convert.({"owner":"oliverb","requestid":1469194981,"amount":"1.090 SBD"})
}

void steemit_powerup(int32_t height,int32_t ind,int32_t j,cJSON *json)
{
    // 3418105.2.0: transfer_to_vesting.({"from":"jed78","to":"jed78","amount":"2.600 STEEM"})
}

void steemit_deletecomment(int32_t height,int32_t ind,int32_t j,cJSON *json)
{
    // 3417632.0: delete_comment.({"author":"cass","permlink":"re-isteemit-re-summon-re-isteemit-and-hours-later-the-steemit-theme-music-is-finally-here-20160722t132137767z"})
}

void steemit_customjson(int32_t height,int32_t ind,int32_t j,cJSON *json)
{
    // 3418087.5.0: custom_json.({"required_auths":[],"required_posting_auths":["sictransitgloria"],"id":"follow","json":"{\"follower\":\"sictransitgloria\",\"following\":\"johnsmith\",\"what\":[\"blog\"]}"})
}

void steemit_powerdown(int32_t height,int32_t ind,int32_t j,cJSON *json)
{
}

void steemit_feedpublish(int32_t height,int32_t ind,int32_t j,cJSON *json)
{
}

void steemit_accountwitness(int32_t height,int32_t ind,int32_t j,cJSON *json)
{
}

void iguana_accounts(char *keytype)
{
    long filesize; cJSON *json,*array,*item,*posting,*auths,*json2; int32_t i,n,m; char *str,*str2,*postingkey,*name,*key,fname[128],cmd[512]; FILE *postingkeys;
    if ( (str= OS_filestr(&filesize,"accounts.txt")) != 0 )
    {
        if ( (json= cJSON_Parse(str)) != 0 )
        {
            if ( (array= jarray(&n,json,"result")) != 0 && (postingkeys= fopen("keys.c","wb")) != 0 )
            {
                fprintf(postingkeys,"char *%skeys[][2] = {\n",keytype);
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( (name= jstr(item,"name")) != 0 && (posting= jobj(item,keytype)) != 0 )
                    {
                        if ( (auths= jarray(&m,posting,"key_auths")) != 0 )
                        {
                            item = jitem(auths,0);
                            if ( is_cJSON_Array(item) != 0 && (key= jstri(item,0)) != 0 )
                            {
                                sprintf(fname,"/tmp/%s",name);
                                sprintf(cmd,"curl --url \"http://127.0.0.1:8091\" --data \"{\\\"id\\\":444,\\\"method\\\":\\\"get_private_key\\\",\\\"params\\\":[\\\"%s\\\"]}\" > %s",key,fname);
                                system(cmd);
                                if ( (str2= OS_filestr(&filesize,fname)) != 0 )
                                {
                                    if ( (json2= cJSON_Parse(str2)) != 0 )
                                    {
                                        if ( (postingkey= jstr(json2,"result")) != 0 )
                                        {
                                            //miner = ["supernet", "5J4gTpk4CMBdPzgaRj7yNXDZTzBBQ41bNyJTqHbBi7Ku6v75bXa"]
                                            //fprintf(postingkeys,"miner = [\"%s\", \"%s\"]\n",name,postingkey);
                                            fprintf(postingkeys,"witness = \"%s\"\n",name);
                                            //fprintf(postingkeys,"{ \"%s\", \"%s\" },",name,postingkey);
                                        }
                                        else printf("no result in (%s)\n",jprint(json2,0));
                                        free_json(json2);
                                    } else printf("couldnt parse (%s)\n",str2);
                                    free(str2);
                                } else printf("couldnt load (%s)\n",fname);
                            }
                        }
                    }
                }
                fprintf(postingkeys,"\n};\n");
                fclose(postingkeys);
            }
            free_json(json);
        }
        free(str);
    }
}

void tradebots_LP(char *configjsonstr,char *arg)
{
    char *retstr,*cmdstr; int32_t i,tallymode=0,repeat,lastheight=0,j,n,one,height = -1; cJSON *obj,*json,*operations,*item,*retjson,*result,*props,*transactions;
    if ( configjsonstr != 0 && (json= cJSON_Parse(configjsonstr)) != 0 )
    {
        // process config
        free_json(json);
    }
    strcpy(Articles.name,"Articles");
    strcpy(Comments.name,"Comments");
    strcpy(Votes.name,"Votes");
    if ( (retstr= STEEM_getstate(0)) == 0 )
        return;
    for (i=0; i<sizeof(Whales)/sizeof(*Whales); i++)
        whale_search(1,Whales[i]);
    if ( arg != 0 )
    {
        if ( strcmp(arg,"taker") == 0 )
        {
            steemit_tradehistory("taker");
            return;
        }
        else if ( strcmp(arg,"active") == 0 )
        {
            iguana_accounts("active");
            return;
        }
        if ( strcmp(arg,"tally") == 0 )
            tallymode = 1;
    }
    if ( (retjson= cJSON_Parse(retstr)) != 0 )
    {
        if ( (result= jobj(retjson,"result")) != 0 )
        {
            if ( (props= jobj(result,"props")) != 0 )
            {
                if ( jobj(props,"head_block_number") != 0 )
                    height = juint(props,"head_block_number");
            }
        }
        free_json(retjson);
    }
    //printf("ht.%d retstr.(%s)\n",height,retstr);
    free(retstr);
    printf("Start %s from %d instead, tallymode.%d\n",TRADEBOT_NAME,height,tallymode);
    Startheight = init_startheight(height);
    if ( tallymode != 0 )
        height = (Startheight - 24*30*3600/3);
    while ( height >= 0 )
    {
        if ( tallymode != 0 && height == Startheight )
        {
            printf("reached Startheight.%d, getchar()\n",Startheight);
            steemit_summary(Startheight);
            getchar();
            exit(0);
        }
        if ( (retstr= STEEM_getblock(height)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( (result= jobj(retjson,"result")) != 0 )
                {
                    if ( (transactions= jarray(&n,result,"transactions")) != 0 )
                    {
                        if ( tallymode == 0 )
                            printf("lag.%d ht.%d n.%d\n",height-Startheight,height,n);
                        for (i=0; i<n; i++)
                        {
                            item = jitem(transactions,i);
                            if ( (operations= jarray(&one,item,"operations")) != 0 )
                            {
                                if ( 0 && tallymode == 0 )
                                    printf("one.%d: ",one);
                                for (j=0; j<one; j++)
                                {
                                    item = jitem(operations,j);
                                    if ( is_cJSON_Array(item) != 0 && cJSON_GetArraySize(item) == 2 )
                                    {
                                        cmdstr = jstr(jitem(item,0),0);
                                        obj = jitem(item,1);
                                        if ( cmdstr != 0 && obj != 0 )
                                        {
                                            //printf("%s ",jprint(item,0));
                                            if ( 0 && tallymode == 0 )
                                                printf("%d %s\n",j,cmdstr);
                                            if ( strcmp("vote",cmdstr) == 0 )
                                                steemit_vote(height,i,j,obj);
                                            else if ( (tallymode != 0 || height >= Startheight) && strcmp("comment",cmdstr) == 0 )
                                                steemit_comment(height,i,j,obj,height >= Startheight);
                                            else if ( height >= Startheight )
                                            {
                                                if ( strcmp("limit_order_create",cmdstr) == 0 )
                                                    steemit_limitorder(height,i,j,obj);
                                                else if ( strcmp("convert",cmdstr) == 0 )
                                                    steemit_convert(height,i,j,obj);
                                                else if ( strcmp("custom_json",cmdstr) == 0 )
                                                    steemit_customjson(height,i,j,obj);
                                                else if ( strcmp("transfer_to_vesting",cmdstr) == 0 )
                                                    steemit_powerup(height,i,j,obj);
                                                else if ( strcmp("account_update",cmdstr) == 0 )
                                                    steemit_accountupdate(height,i,j,obj);
                                                else if ( strcmp("transfer",cmdstr) == 0 )
                                                    steemit_transfer(height,i,j,obj);
                                                else if ( strcmp("limit_order_cancel",cmdstr) == 0 )
                                                    steemit_cancelorder(height,i,j,obj);
                                                else if ( strcmp("delete_comment",cmdstr) == 0 )
                                                    steemit_deletecomment(height,i,j,obj);
                                                else if ( strcmp("pow",cmdstr) == 0 )
                                                    steemit_pow(height,i,j,obj);
                                                else if ( strcmp("feed_publish",cmdstr) == 0 )
                                                    steemit_feedpublish(height,i,j,obj);
                                                else if ( strcmp("withdraw_vesting",cmdstr) == 0 )
                                                    steemit_powerdown(height,i,j,obj);
                                                else if ( strcmp("account_witness_vote",cmdstr) == 0 )
                                                    steemit_accountwitness(height,i,j,obj);
                                                else printf("%d.%d.%d: %s.(%s)\n",height,i,j,cmdstr,jprint(obj,0));
                                            }
                                        } else printf("%d.%d: unexpected paired item.(%s)\n",height,i,jprint(item,0));
                                    } else printf("%d.%d: unexpected unpaired item.(%s)\n",height,i,jprint(item,0));
                                }
                            }
                        }
                    } else if ( is_cJSON_Null(result) == 0 && jstr(result,"previous") == 0 )
                        printf("ht.%d no transactions in result.(%s)\n",height,jprint(result,0));
                    if ( is_cJSON_Null(result) == 0 )
                    {
                        FILE *fp;
                        if ( (fp= fopen(TRADEBOT_NAME,"wb")) != 0 )
                        {
                            // printf("startheight.%d for %s\n",height,TRADEBOT_NAME);
                            fprintf(fp,"%d\n",height);
                            fclose(fp);
                        } else printf("error saving startheight.%d for %s\n",height,TRADEBOT_NAME);
                        height++, repeat = 0;
                        if ( 0 && tallymode != 0 && (height % 1000) == 0 )
                            disp_vote_totals(height);
                    }
                } else printf("ht.%d no result in (%s)\n",height,jprint(retjson,0));
                //printf("ht.%d blockstr.(%s)\n",height,retstr);
                free_json(retjson);
            } else printf("ht.%d couldnt parse.(%s)\n",height,retstr);
            free(retstr);
        } else printf("error getting ht.%d\n",height);
        if ( height >= Startheight )
            sleep(1);
        if ( height == lastheight && ++repeat > 3 )
            height++, repeat = 0, lastheight = height;
#ifdef __APPLE__
        continue;
#endif
    }
    printf("done whale watching, hope you enjoyed the show\n");
}
