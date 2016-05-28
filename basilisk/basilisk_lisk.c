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

char *basilisk_liskrawtx(struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,uint32_t basilisktag,cJSON **vinsp,uint32_t locktime,uint64_t satoshis,char *changeaddr,uint64_t txfee,cJSON *addresses,int32_t minconf,char *spendscriptstr,int32_t timeoutmillis)
{
    cJSON *hexjson,*valsobj; char *retstr = 0; struct basilisk_item *ptr;
    *vinsp = 0;
    if ( addresses != 0 )
    {
        valsobj = cJSON_CreateObject();
        jaddnum(valsobj,"basilisktag",basilisktag);
        jaddstr(valsobj,"coin",coin->symbol);
        jadd64bits(valsobj,"amount",satoshis);
        jadd64bits(valsobj,"txfee",txfee);
        jaddnum(valsobj,"minconf",minconf);
        jaddnum(valsobj,"locktime",locktime);
        hexjson = cJSON_CreateObject();
        jaddstr(hexjson,"changeaddr",changeaddr);
        jaddstr(hexjson,"spendscriptstr",spendscriptstr);
        jadd(hexjson,"addresses",jduplicate(addresses));
        jadd(hexjson,"vals",valsobj);
        jaddstr(hexjson,"agent","basilisk");
        jaddstr(hexjson,"method","rawtx");
        if ( (ptr= basilisk_issue(myinfo,hexjson,timeoutmillis,0,1,basilisktag)) != 0 )
            retstr = basilisk_finish(ptr,0);
        free_json(hexjson);
    }
    return(retstr);
}
