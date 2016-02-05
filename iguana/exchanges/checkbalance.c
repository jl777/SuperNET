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

int32_t CHECKBALANCE(char **retstrp,int32_t skipflag,struct exchange_info *exchange,int32_t dir,char *base,char *rel,double price,double volume,cJSON *argjson)
{
    cJSON *json; char *coinstr,*balancestr,*resultstr,*resultval; double balance; int32_t retval = -1;
    if ( skipflag == 0 )
    {
        coinstr = (dir > 0) ? rel : base;
        if ( (balancestr= PARSEBALANCE(exchange,&balance,coinstr,argjson)) != 0 )
        {
            json = cJSON_Parse(balancestr);
            free(balancestr);
            printf("%s balance.%s %f vs %f\n",exchange->name,coinstr,balance,dir > 0 ? volume : volume * price);
            if ( (dir > 0 && balance < volume) || (dir < 0 && balance < (volume * price)) )
            {
                resultstr = "error";
                resultval = "not enough balance";
            }
            else
            {
                resultval = "balance";
                resultstr = "success";
                retval = 0;
            }
            if ( retstrp != 0 )
            {
                if ( json == 0 )
                    json = cJSON_CreateObject();
                jaddstr(json,"coin",coinstr);
                jaddnum(json,"balance",balance);
                jaddnum(json,"required",volume * (dir < 0 ? price : 1.));
                jaddstr(json,resultstr,resultval);
                *retstrp = jprint(json,1);
            }
            else if ( json != 0 )
                free_json(json);
        }
    } else retval = 0;
    return(retval);
}
