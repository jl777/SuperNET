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

#define MAX_ELECTIONS 64

struct vote_info
{
    bits256 commit,vote;
    uint64_t stake,repstake;
    int32_t repid;
    uint8_t sig[74],siglen;
    uint8_t pubkey[33],rmd160[20];
};

struct election_info
{
    bits256 hash;
    char name[64];
    uint32_t expiration,duration,numcandidates,numvotes;
    cJSON *ballot;
    struct vote_info *votes;
} Elections[MAX_ELECTIONS];

int64_t basilisk_voter_stake(struct supernet_info *myinfo,uint8_t *rmd160,struct iguana_info *coin,uint8_t *pubkey)
{
    char coinaddr[64]; int64_t stake = 1;
    calc_rmd160_sha256(rmd160,pubkey,33);
    bitcoin_address(coinaddr,coin->chain->pubtype,pubkey,33);
    // get stake of address
    return(stake);
}

int32_t basilisk_voter_process(struct supernet_info *myinfo,uint8_t *rmd160,struct iguana_info *coin,struct election_info *ep,struct vote_info *vp)
{
    int32_t i;
    if ( vp->stake == 0 )
        vp->stake = 1;
    if ( bits256_nonz(vp->vote) != 0 )
    {
        for (i=1; i<8; i++)
            if ( vp->vote.uints[i] != 0 )
                break;
        if ( i == 8 )
            return(vp->vote.uints[0]);
        else
        {
            for (i=0; i<20; i++)
                rmd160[i] = vp->vote.bytes[i + 4];
            return(ep->numcandidates);
        }
    }
    return(-1);
}

int32_t basilisk_election_process(struct supernet_info *myinfo,int64_t *tally,struct iguana_info *coin,struct election_info *ep)
{
    int32_t i,j,pending = 0; struct vote_info *vp; uint8_t rmd160[20];
    for (i=0; i<ep->numvotes; i++)
        ep->votes[i].repstake = 0;
    for (i=0; i<ep->numvotes; i++)
    {
        vp = &ep->votes[i];
        if ( basilisk_voter_process(myinfo,rmd160,coin,ep,vp) == ep->numcandidates && vp->repid < 0 )
        {
            for (j=0; j<ep->numvotes; j++)
            {
                if ( i != j && memcmp(rmd160,ep->votes[j].rmd160,20) == 0 )
                {
                    vp->repid = j;
                    ep->votes[j].repstake += vp->stake;
                    break;
                }
            }
        }
    }
    if ( tally != 0 )
    {
        memset(tally,0,ep->numcandidates*sizeof(*tally));
        for (i=0; i<ep->numvotes; i++)
        {
            vp = &ep->votes[i];
            if ( vp->repid < 0 && vp->vote.uints[0] > 0 && vp->vote.uints[0] <= ep->numcandidates )
                tally[vp->vote.uints[0]] += (vp->stake + vp->repstake);
            else if ( vp->repid < 0 )
                pending++;
        }
    }
    return(pending);
}

cJSON *basilisk_voterjson(struct supernet_info *myinfo,struct iguana_info *coin,struct election_info *ep,struct vote_info *vp)
{
    char coinaddr[64],sigstr[74*2+1]; int32_t i; uint8_t rmd160[20]; cJSON *item;
    item = cJSON_CreateObject();
    basilisk_voter_process(myinfo,rmd160,coin,ep,vp);
    bitcoin_address(coinaddr,5,vp->pubkey,sizeof(vp->pubkey));
    jaddstr(item,"coinaddr",coinaddr);
    jaddnum(item,"stake",dstr(vp->stake));
    if ( vp->repstake != 0 )
        jaddnum(item,"repstake",dstr(vp->repstake));
    if ( bits256_nonz(vp->vote) != 0 )
    {
        for (i=1; i<8; i++)
            if ( vp->vote.uints[i] != 0 )
                break;
        if ( i == 8 )
        {
            if ( vp->vote.uints[0] <= ep->numcandidates )
                jaddnum(item,"vote",vp->vote.uints[0]);
            else jaddstr(item,"error","illegal vote");
        }
        else
        {
            for (i=0; i<20; i++)
                rmd160[i] = vp->vote.bytes[i + 4];
            bitcoin_address(coinaddr,5,rmd160,20);
            jaddstr(item,"delegated",coinaddr);
        }
    }
    else if ( bits256_nonz(vp->commit) != 0 )
        jaddbits256(item,"commit",vp->commit);
    init_hexbytes_noT(sigstr,vp->sig,vp->siglen);
    jaddstr(item,"sig",sigstr);
    return(item);
}

cJSON *basilisk_electionjson(struct supernet_info *myinfo,struct iguana_info *coin,struct election_info *ep)
{
    int32_t i; cJSON *array,*obj = cJSON_CreateObject();
    jaddstr(obj,"name",ep->name);
    jaddbits256(obj,"hash",ep->hash);
    jaddnum(obj,"expiration",ep->expiration);
    jaddnum(obj,"numcandidates",ep->numcandidates);
    jaddnum(obj,"numvotes",ep->numvotes);
    jadd(obj,"ballot",jduplicate(ep->ballot));
    array = cJSON_CreateArray();
    for (i=0; i<ep->numvotes; i++)
        jaddi(array,basilisk_voterjson(myinfo,coin,ep,&ep->votes[i]));
    jadd(obj,"votes",array);
    return(obj);
}

int32_t basilisk_electionsave(struct election_info *ep)
{
    char fname[512],str[65],*ballotstr; int32_t n; FILE *fp;
    OS_ensure_directory("elections");
    sprintf(fname,"elections/%s",bits256_str(str,ep->hash));
    OS_compatible_path(fname);
    if ( (fp= fopen(fname,"wb")) != 0 )
    {
        if ( fwrite(ep,1,sizeof(*ep),fp) != sizeof(*ep) )
            printf("error saving election.(%s) to %s\n",ep->name,fname);
        else
        {
            if ( fwrite(&ep->numvotes,1,sizeof(ep->numvotes),fp) != sizeof(ep->numvotes) )
                printf("error saving numvotes.%d to %s\n",ep->numvotes,fname);
            else if ( ep->numvotes > 0 )
            {
                if ( fwrite(ep->votes,sizeof(*ep->votes),ep->numvotes,fp) != ep->numvotes )
                    printf("error saving votes.%d for %s to %s\n",ep->numvotes,ep->name,fname);
                else
                {
                    if ( (ballotstr= jprint(ep->ballot,0)) != 0 )
                    {
                        n = (int32_t)strlen(ballotstr) + 1;
                        if ( fwrite(&n,1,sizeof(n),fp) != sizeof(n) )
                            printf("error saving n.%d for (%s) to %s\n",n,ballotstr,fname);
                        else if ( fwrite(ballotstr,1,n,fp) != n )
                            printf("error saving election.(%s) to %s\n",ballotstr,fname);
                        free(ballotstr);
                    }
                }
            }
        }
        fclose(fp);
        return(0);
    }
    return(-1);
}

struct vote_info *basilisk_vote_find(struct election_info *ep,struct vote_info *vote)
{
    int32_t i;
    for (i=0; i<ep->numvotes; i++)
    {
        if ( memcmp(ep->votes[i].pubkey,vote->pubkey,33) == 0 )
            return(&ep->votes[i]);
    }
    return(0);
}

struct election_info *basilisk_election_find(int32_t createflag,bits256 hash)
{
    int32_t i; uint32_t now = (uint32_t)time(NULL);
    for (i=0; i<sizeof(Elections)/sizeof(*Elections); i++)
    {
        if ( Elections[i].expiration != 0 && now > Elections[i].expiration )
        {
            basilisk_electionsave(&Elections[i]);
            memset(&Elections[i],0,sizeof(Elections[i]));
        }
        if ( bits256_nonz(hash) != 0 )
        {
            if ( bits256_nonz(Elections[i].hash) == 0 )
                return(&Elections[i]);
            else if ( bits256_cmp(Elections[i].hash,hash) == 0 )
                return(0);
        }
    }
    return(0);
}

int32_t basilisk_vote_extract(struct supernet_info *myinfo,char *coinaddr,struct vote_info *vote,cJSON *item)
{
    char str[65],str2[65],str3[65]; uint8_t *sig,*pubkey; int32_t action,siglen,plen; bits256 data,hash;
    memset(vote,0,sizeof(*vote));
    if ( get_dataptr(0,&sig,&siglen,vote->sig,sizeof(vote->sig),jstr(item,"sig")) != 0 )
    {
        vote->siglen = siglen;
        action = juint(item,"action");
        if ( get_dataptr(0,&pubkey,&plen,vote->pubkey,sizeof(vote->pubkey),jstr(item,"pubkey")) != 0 )
        {
            bitcoin_address(coinaddr,5,pubkey,33);
            data = jbits256(item,"data");
            if ( bitcoin_verify(myinfo->ctx,vote->sig,vote->siglen,data,vote->pubkey,33) == 0 )
            {
                if ( (action & 0xff) == 'c' )
                {
                    vote->commit = data;
                    printf("%s commits to %s\n",coinaddr,bits256_str(str,data));
                    return(action);
                }
                else if ( (action & 0xff) == 'r' )
                {
                    if ( bits256_nonz(vote->commit) != 0 )
                    {
                        vcalc_sha256(0,hash.bytes,data.bytes,sizeof(data));
                        if ( bits256_cmp(hash,vote->commit) == 0 )
                        {
                            printf("%s vote %s -> %s matches commit %s\n",coinaddr,bits256_str(str,data),bits256_str(str2,hash),bits256_str(str3,vote->commit));
                            vote->vote = data;
                            // error check vote
                            return(action);
                        }
                        else
                        {
                            printf("%s vote %s -> %s doesnt match commit %s\n",coinaddr,bits256_str(str,data),bits256_str(str2,hash),bits256_str(str3,vote->commit));
                            return(-2);
                        }
                    }
                }
            } else return(-1);
        }
    }
    return(-1);
}

char *basilisk_respond_VOT(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    int32_t i,duration,winner,pending,action,numcandidates; char coinaddr[64],*symbol,*votemethod,*ballotstr; cJSON *item,*array,*electionobj,*ballot,*retjson; struct election_info *ep; struct vote_info vote,*vp; struct iguana_info *coin; int64_t *tally,max;
    retjson = cJSON_CreateObject();
    if ( (symbol= jstr(valsobj,"coin")) == 0 )
        symbol = "BTCD";
    coin = iguana_coinfind(symbol);
    if ( (votemethod= jstr(valsobj,"votemethod")) != 0 )
    {
        if ( strcmp(votemethod,"create") == 0 )
        {
            if ( (ballot= jarray(&numcandidates,valsobj,"ballot")) != 0 && numcandidates > 0 )
            {
                if ( (duration= juint(valsobj,"duration")) == 0 )
                    duration = 3600;
                ballotstr = jprint(ballot,0);
                vcalc_sha256(0,hash.bytes,(uint8_t *)ballotstr,(int32_t)strlen(ballotstr));
                free(ballotstr);
                if ( (ep= basilisk_election_find(1,hash)) != 0 )
                {
                    ep->hash = hash;
                    ep->duration = duration;
                    ep->expiration = (uint32_t)time(NULL) + duration;
                    ep->ballot = jduplicate(ballot);
                    ep->numcandidates = numcandidates;
                    safecopy(ep->name,jstr(valsobj,"name"),sizeof(ep->name));
                    if ( (electionobj= basilisk_electionjson(myinfo,coin,ep)) != 0 )
                    {
                        jaddstr(retjson,"result","success");
                        jadd(retjson,"election",electionobj);
                    } else jaddstr(retjson,"error","couldnt create election object");
                } else jaddstr(retjson,"error","couldnt allocate election slot");
            }
        }
        else if ( strcmp(votemethod,"list") == 0 )
        {
            array = cJSON_CreateArray();
            for (i=0; i<sizeof(Elections)/sizeof(*Elections); i++)
            {
                if ( bits256_nonz(Elections[i].hash) != 0 )
                {
                    item = cJSON_CreateObject();
                    jaddstr(item,"name",Elections[i].name);
                    jaddbits256(item,"hash",Elections[i].hash);
                    jaddi(array,item);
                }
            }
            jaddstr(retjson,"result","success");
            jadd(retjson,"elections",array);
        }
        if ( (ep= basilisk_election_find(0,hash)) != 0 )
        {
            if ( strcmp(votemethod,"info") == 0 )
            {
                jaddstr(retjson,"result","success");
                tally = calloc(ep->numcandidates+1,sizeof(*tally));
                pending = basilisk_election_process(myinfo,tally,coin,ep);
                if ( pending != 0 )
                    jaddnum(retjson,"pending",pending);
                jadd(retjson,"election",basilisk_electionjson(myinfo,coin,ep));
                array = cJSON_CreateArray();
                max = 0;
                winner = -1;
                for (i=1; i<=ep->numcandidates; i++)
                {
                    if ( tally[i] > max )
                    {
                        max = tally[i];
                        winner = i;
                    }
                    jaddinum(array,dstr(tally[i]));
                }
                jadd(retjson,"tally",array);
                if ( winner > 0 )
                {
                    item = jitem(ep->ballot,winner-1);
                    jadd(retjson,"winner",item);
                }
                free(tally);
            }
            else if ( strcmp(votemethod,"ratify") == 0 )
            {
                // record ratification of tally
            }
            else if ( (action= basilisk_vote_extract(myinfo,coinaddr,&vote,valsobj)) > 0 )
            {
                vp = basilisk_vote_find(ep,&vote);
                if ( strcmp(votemethod,"vote") == 0 )
                {
                    if ( vp == 0 )
                    {
                        ep->votes = realloc(ep->votes,sizeof(*ep->votes) + (ep->numvotes + 1));
                        vote.repid = -1;
                        vote.stake = basilisk_voter_stake(myinfo,vote.rmd160,coin,vote.pubkey);
                        ep->votes[ep->numvotes++] = vote;
                        jaddstr(retjson,"result","success");
                    }
                    else if ( action == 'c' )
                    {
                        *vp = vote;
                        jaddstr(retjson,"result","success");
                    }
                    else if ( action == 'r' )
                    {
                        *vp = vote;
                        jaddstr(retjson,"result","success");
                    } else jaddstr(retjson,"error","illegal vote action");
                }
                else if ( strcmp(votemethod,"verify") == 0 )
                {
                    if ( vp == 0 )
                        jaddstr(retjson,"error","cant find voter");
                    else if ( action == 'c' )
                    {
                        if ( bits256_cmp(vote.commit,vp->commit) == 0 )
                            jaddstr(retjson,"result","success");
                        else jaddstr(retjson,"error","mismatched commit");
                        jaddbits256(retjson,"oldcommit",vp->commit);
                        jaddbits256(retjson,"newcommit",vote.commit);
                    }
                    else if ( action == 'r' )
                    {
                        if ( bits256_cmp(vote.vote,vp->vote) == 0 )
                            jaddstr(retjson,"result","success");
                        else jaddstr(retjson,"error","mismatched vote");
                        jaddbits256(retjson,"oldvote",vp->vote);
                        jaddbits256(retjson,"newvote",vote.vote);
                    } else jaddstr(retjson,"error","illegal vote action");
                } else jaddstr(retjson,"error","illegal vote method");
            } else jaddstr(retjson,"error","couldnt extract vote info");
        }
    }
    return(jprint(retjson,1));
}


