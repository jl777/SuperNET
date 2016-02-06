/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
var exchanges="";
var saved_exchanges=false;

var show_resposnse=function(response){
    
 $('#Instandex_output_table').html(""); 
         response=JSON.parse(response);
         for(var i in response){
             if(i==='tag') continue;
             $('#Instandex_output_table').append("<tr><td align='center'>"+i+"</td><td align='center'>"+response[i]+"</td></tr>"); 
         }   
};

var setUeseridandAPIkeyPair=function(){
    
    setAPIkeyPair();
    
};

var setAPIkeyPair=function(){
    
    var exchange=$('#Instandex_exchange').val();
    var apikey=$('#Instandex_apikey').val();
    var passphrase=$('#Instandex_apipassphrase').val();

    var request='{"agent":"InstantDEX","method":"apikeypair","exchange":"'+exchange+'","apikey":"'+apikey+'","apisecret":"'+passphrase+'"}';
    SPNAPI.makeRequest(request, function(request,response){
        show_resposnse(response);   
    }
        );
    
};

/*
 * 
THREE_STRINGS(InstantDEX,setuserid,exchange,userid,tradepassword);
 */

var InstantDEX_setuserid=function(){
    var exchange=$('#Instandex_exchange').val();
    var userid=$('#Instandex_userid').val();
    var tradepassword=$('#Instandex_tradepassword').val();
       
    var request='{"agent":"InstantDEX","method":"setuserid","exchange":"'+exchange+'","userid":"'+userid+'","tradepassword":"'+tradepassword+'"}';
    SPNAPI.makeRequest(request, function(request,response){
        
         show_resposnse(response); 
         
    });
};



var ListAllExchanges=function(){
    if(!saved_exchanges){
    var request='{"agent":"InstantDEX","method":"allexchanges"}';
    SPNAPI.makeRequest(request, function(request,response){
        response=JSON.parse(response);
            if(response.result &&  response.result instanceof Array ){
                for(var i in response.result){
                    //$('#Instandex_exchange').append('<option value="'+response.result[i]+'">'+response.result[i]+'</option>');
                     exchanges=exchanges+'<option value="'+response.result[i]+'">'+response.result[i]+'</option>';
                    
                }
                
                 saved_exchanges=true;   
                
                
            }
            
    }
        );}
    
};

var InstantDEX_allpairs=function(){
    var exchange=$('#Instandex_exchange').val();
    var request='{"agent":"InstantDEX","method":"allpairs","exchange":"'+exchange+'"}';
    SPNAPI.makeRequest(request, function(request,response){
        response=JSON.parse(response);
         //show_resposnse(response); 
         if(response.result){
         for(var i in response.result){
             
             $('#Instandex_output_table').append("<tr><td align='center'>"+response.result[i][0]+"</td><td align='center'>"+response.result[i][1]+"</td></tr>"); 
         }} 
         
    });
};

//THREE_STRINGS_AND_THREE_INTS(InstantDEX,orderbook,exchange,base,rel,depth,allfields,invert);
var orderbook=function(){
  var exchange=$('#Instandex_exchange').val();
    var base=$('#Instandex_base').val();
    var rel=$('#Instandex_rel').val();
    var depth=$('#Instandex_orderbook_depth').val();
    var request='{"agent":"InstantDEX","method":"orderbook","exchange":"'+exchange+'","base":"'+base+'","rel":"'+rel+'","depth":'+depth+',"allfields":0,"invert":0}';
    SPNAPI.makeRequest(request, function(request,response){
       $('#Instandex_output_table').html(""); 
        /*
         * 
         * {"exchange":"btce","inverted":0,"base":"LTC","rel":"BTC","bids":[0.00814000, 0.00813000, 0.00812000, 0.00811000, 0.00810000, 0.00809000, 0.00808000, 0.00807000, 0.00806000, 0.00805000, 0.00804000, 0.00803000, 0.00802000, 0.00801000, 0.00800000, 0.00799000, 0.00798000, 0.00797000, 0.00796000, 0.00795000],"asks":[0.00816000, 0.00817000, 0.00818000, 0.00819000, 0.00820000, 0.00821000, 0.00822000, 0.00823000, 0.00824000, 0.00825000, 0.00826000, 0.00827000, 0.00828000, 0.00829000, 0.00830000, 0.00831000, 0.00832000, 0.00833000, 0.00834000, 0.00835000],"numbids":20,"numasks":20,"highbid":0.00814000,"lowask":0.00816000,"timestamp":1454329614,"time":"2016-02-01T12:26:54Z","maxdepth":20,"tag":"374388797247258721"}
         */
        $('#Instandex_output_table').append("<tr  class='row history-row'><th width='100px'>Bid price</th><th width='100px'>Ask price</th></tr>");  
         response=JSON.parse(response);
        for(var i=0;i<response.numbids;i++){
          $('#Instandex_output_table').append("<tr class='row history-row'><td align='center' >"+response.bids[i]+"</td><td align='center' >"+response.asks[i]+"</td></tr>");  
        }
    });


};

/*
 * 
THREE_STRINGS_AND_THREE_DOUBLES(InstantDEX,buy,exchange,base,rel,price,volume,dotrade);
THREE_STRINGS_AND_THREE_DOUBLES(InstantDEX,sell,exchange,base,rel,price,volume,dotrade);
THREE_STRINGS_AND_DOUBLE(InstantDEX,withdraw,exchange,base,destaddr,amount);
 */

var InstantDEXBuy=function(){
var exchange=$('#Instandex_exchange').val();
    var base=$('#Instandex_base').val();
    var rel=$('#Instandex_rel').val();
    var price=$('#Instandex_price').val();
    var volume=$('#Instandex_volume').val();
    
    var request='{"agent":"InstantDEX","method":"buy","exchange":"'+exchange+'","base":"'+base+'","rel":"'+rel+'","price":'+price+',"volume":'+volume+',"dotrade":1}';
    SPNAPI.makeRequest(request, function(request,response){
        
         show_resposnse(response);
    });
    
};

var InstantDEXSell=function(){
    
   var exchange=$('#Instandex_exchange').val();
    var base=$('#Instandex_base').val();
    var rel=$('#Instandex_rel').val();
    var price=$('#Instandex_price').val();
    var volume=$('#Instandex_volume').val();
    
    var request='{"agent":"InstantDEX","method":"sell","exchange":"'+exchange+'","base":"'+base+'","rel":"'+rel+'","price":'+price+',"volume":'+volume+',"dotrade":1}';
    SPNAPI.makeRequest(request, function(request,response){
        
                show_resposnse(response);
    });
 
    
};

var InstantDEXWithdaw=function(){
    var exchange=$('#Instandex_exchange').val();
    var base=$('#Instandex_base').val();
    var destinationaddr=$('#Instandex_destaddr').val();
    var amount=$('#Instandex_amount').val();
    
    var request='{"agent":"InstantDEX","method":"withdraw","exchange":"'+exchange+'","base":"'+base+'","destaddr":"'+destinationaddr+'","amount":'+amount+'}';
    console.log(request);
    SPNAPI.makeRequest(request, function(request,response){
        
                  show_resposnse(response);
    });
};


/*
 * 
THREE_STRINGS(InstantDEX,supports,exchange,base,rel);
 */
var InstantDEX_supports=function(){
    var exchange=$('#Instandex_exchange').val();
    var base=$('#Instandex_base').val();
    var rel=$('#Instandex_rel').val();
       
    var request='{"agent":"InstantDEX","method":"supports","exchange":"'+exchange+'","userid":"'+base+'","rel":"'+rel+'"}';
    SPNAPI.makeRequest(request, function(request,response){
         
                  show_resposnse(response);
        
    });
};

/*
 * 
 * 
 *  TWO_STRINGS(InstantDEX,balance,exchange,base); */

var InstantDEX_balance=function(){
    var exchange=$('#Instandex_exchange').val();
    var base=$('#Instandex_base').val();
       
    var request='{"agent":"InstantDEX","method":"balance","exchange":"'+exchange+'","base":"'+base+'"}';
    SPNAPI.makeRequest(request, function(request,response){
                  show_resposnse(response);
        
    });
};
/*
 * 
 * TWO_STRINGS(InstantDEX,orderstatus,exchange,orderid);
 */
var InstantDEX_orderstatus=function(){
    var exchange=$('#Instandex_exchange').val();
    var orderid=$('#Instandex_orderid').val();
       
    var request='{"agent":"InstantDEX","method":"orderstatus","exchange":"'+exchange+'","orderid":"'+orderid+'"}';
    SPNAPI.makeRequest(request, function(request,response){
          show_resposnse(response);
        
    });
};

/*
 * 
TWO_STRINGS(InstantDEX,cancelorder,exchange,orderid);
 * */
var InstantDEX_cancelorder=function(){
    var exchange=$('#Instandex_exchange').val();
    var orderid=$('#Instandex_orderid').val();
       
    var request='{"agent":"InstantDEX","method":"cancelorder","exchange":"'+exchange+'","orderid":"'+orderid+'"}';
    SPNAPI.makeRequest(request, function(request,response){
        
                  show_resposnse(response);
    });
};

/*
 * STRING_ARG(InstantDEX,openorders,exchange);
 */
var InstantDEX_openorders=function(){
    var exchange=$('#Instandex_exchange').val();
       
    var request='{"agent":"InstantDEX","method":"openorders","exchange":"'+exchange+'"}';
    SPNAPI.makeRequest(request, function(request,response){
        
                  show_resposnse(response); 
    });
};

/*
 * 
STRING_ARG(InstantDEX,tradehistory,exchange);
 * */

var InstantDEX_tradehistory=function(){
    var exchange=$('#Instandex_exchange').val();
       
    var request='{"agent":"InstantDEX","method":"tradehistory","exchange":"'+exchange+'"}';
    SPNAPI.makeRequest(request, function(request,response){
                  show_resposnse(response); 
        
    });
};

/*
 * STRING_AND_INT(InstantDEX,pollgap,exchange,pollgap);
 */
var InstantDEX_pollgap=function(){
    var exchange=$('#Instandex_exchange').val();
    var pollgap=$('#Instandex_pollgap').val();
    
    var request='{"agent":"InstantDEX","method":"pollgap","exchange":"'+exchange+'","pollgap":'+pollgap+'}';
    SPNAPI.makeRequest(request, function(request,response){
                 show_resposnse(response);
        
    });
};

var set_setuserid_table=function (){
var html='<tr><td align="center" > UserID:</td><td align="center" ><input type="text" id="Instandex_userid"/></td></tr><tr><td align="center" > Password:</td><td align="center" ><input type="text" id="Instandex_tradepassword"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Instandex_exchange" id="Instandex_exchange"></select></td></tr><tr><td colspan="2" align="center">  <button class="btn btn-primary instantdex_set_userid" >Set Userid</button></td></tr>';
    $('#Instandex_form_table').html(html);
    if(exchanges!==""){
    $('#Instandex_exchange').html(exchanges);}
};

var set_apikeypass_table=function (){
var html='<tr><td align="center" > Apikey:</td><td align="center" ><input size="40" type="text" id="Instandex_apikey"/></td></tr><tr><td align="center" > Passphrase:</td><td align="center" ><input size="40" type="text" id="Instandex_apipassphrase"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Instandex_exchange" id="Instandex_exchange"></select></td></tr><tr><td colspan="2" align="center">  <button class="btn btn-primary instantdex_set_keypair" >Set keypair</button></td></tr>';
    $('#Instandex_form_table').html(html);
    if(exchanges!==""){
    $('#Instandex_exchange').html(exchanges);}
};

var set_orderbook_table=function (){
var html='<tr><td align="center" >  Base:</td><td align="center" ><input type="text" id="Instandex_base"/></td></tr><tr><td align="center" >Rel:</td><td align="center" ><input type="text" id="Instandex_rel"/></td></tr><tr><td align="center" >Depth:</td><td align="center" ><input type="text" id="Instandex_orderbook_depth"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Instandex_exchange" id="Instandex_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary instantdex_orderbook" >orderbook</button></td></tr>';
    $('#Instandex_form_table').html(html);
    if(exchanges!==""){
    $('#Instandex_exchange').html(exchanges);}
};

var set_sell_table=function (){
var html='<tr><td align="center" >  Base:</td><td align="center" ><input type="text" id="Instandex_base"/></td></tr><tr><td align="center" >Rel:</td><td align="center" ><input type="text" id="Instandex_rel"/></td></tr><tr><td align="center" >Price:</td><td align="center" ><input type="text" id="Instandex_price"/></td></tr><tr><td align="center" >Volume:</td><td align="center" ><input type="text" id="Instandex_volume"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Instandex_exchange" id="Instandex_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary instantdex_sell" >Sell</button></td></tr>';
    $('#Instandex_form_table').html(html);
    if(exchanges!==""){
    $('#Instandex_exchange').html(exchanges);}
};

var set_buy_table=function (){
var html='<tr><td align="center" >  Base:</td><td align="center" ><input type="text" id="Instandex_base"/></td></tr><tr><td align="center" >Rel:</td><td align="center" ><input type="text" id="Instandex_rel"/></td></tr><tr><td align="center" >Price:</td><td align="center" ><input type="text" id="Instandex_price"/></td></tr><tr><td align="center" >Volume:</td><td align="center" ><input type="text" id="Instandex_volume"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Instandex_exchange" id="Instandex_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary instantdex_buy" >Buy</button></td></tr>';
    $('#Instandex_form_table').html(html);
    if(exchanges!==""){
    $('#Instandex_exchange').html(exchanges);}
};

var set_balance_table=function (){
var html='<tr><td align="center" >  Base:</td><td align="center" ><input type="text" id="Instandex_base"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Instandex_exchange" id="Instandex_exchange"></select></td></tr><tr><td colspan="2" align="center" > <button class="btn btn-primary instantdex_balance" >Check balance</button></td></tr>';
    $('#Instandex_form_table').html(html);
    if(exchanges!==""){
    $('#Instandex_exchange').html(exchanges);}
};


var set_support_table=function (){
var html='<tr><td align="center" >  Base:</td><td align="center" ><input type="text" id="Instandex_base"/></td></tr><tr><td align="center" >Rel:</td><td align="center" ><input type="text" id="Instandex_rel"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Instandex_exchange" id="Instandex_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary instantdex_support" >Check Support</button></td></tr>';
    $('#Instandex_form_table').html(html);
    if(exchanges!==""){
    $('#Instandex_exchange').html(exchanges);}
};


var set_withdraw_table=function (){
var html='<tr><td align="center" >  Base:</td><td align="center" ><input type="text" id="Instandex_base"/></td></tr><tr><td align="center" >Destination address:</td><td align="center" ><input type="text" id="Instandex_destaddr"/></td></tr><tr><td align="center" >Amount:</td><td align="center" ><input type="text" id="Instandex_amount"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Instandex_exchange" id="Instandex_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary instantdex_withdraw" >Withdraw</button></td></tr>';
    $('#Instandex_form_table').html(html);
    if(exchanges!==""){
    $('#Instandex_exchange').html(exchanges);}
};

var set_order_status_table=function (){
var html='<tr><td align="center" >  Order ID:</td><td align="center" ><input type="text" id="Instandex_orderid"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Instandex_exchange" id="Instandex_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary instantdex_order_status" >Check order status</button></td></tr>';
    $('#Instandex_form_table').html(html);
    if(exchanges!==""){
    $('#Instandex_exchange').html(exchanges);}
};


var set_open_order_table=function (){
var html='<tr><td align="center" >  Exchange:</td><td align="center" ><select name="Instandex_exchange" id="Instandex_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary instantdex_open_orders" >Open orders</button></td></tr>';
    $('#Instandex_form_table').html(html);
    if(exchanges!==""){
    $('#Instandex_exchange').html(exchanges);}
};


var set_trade_history_table=function (){
var html='<tr><td align="center" >  Exchange:</td><td align="center" ><select name="Instandex_exchange" id="Instandex_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary instantdex_trade_history" >See Trade History</button></td></tr>';
    $('#Instandex_form_table').html(html);
    if(exchanges!==""){
    $('#Instandex_exchange').html(exchanges);}
};

var set_order_cancel_table=function (){
var html='<tr><td align="center" >  Order ID:</td><td align="center" ><input type="text" id="Instandex_orderid"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Instandex_exchange" id="Instandex_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary instantdex_order_cancel" >Cancel order</button></td></tr>';
    $('#Instandex_form_table').html(html);
    if(exchanges!==""){
    $('#Instandex_exchange').html(exchanges);}
};

var set_pollgap_table=function (){
var html='<tr><td align="center" >  Pollgap:</td><td align="center" ><input type="text" id="Instandex_pollgap"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Instandex_exchange" id="Instandex_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary instantdex_pollgap" >Pollgap</button></td></tr>';
    $('#Instandex_form_table').html(html);
    if(exchanges!==""){
    $('#Instandex_exchange').html(exchanges);}
};

var set_allpair_table=function (){
var html='<tr><td align="center" >  Exchange:</td><td align="center" ><select name="Instandex_exchange" id="Instandex_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary instantdex_allpairs" >Get allpairs</button></td></tr>';
    $('#Instandex_form_table').html(html);
    if(exchanges!==""){
    $('#Instandex_exchange').html(exchanges);
}
};

var instantdex_set_method_table=function (method){
    
    if(method==="apikeypair"){
        set_apikeypass_table();
    }else if(method==="orderbook"){
        set_orderbook_table();
    }else if(method==="sell"){
        set_sell_table();
    }else if(method==="buy"){
        set_buy_table();
    }else if(method==="balance"){
        set_balance_table();
    }
    else if(method==="support"){
        set_support_table();
    }
    else if(method==="withdraw"){
        set_withdraw_table();
    }
    else if(method==="order_status"){
        set_order_status_table();
    }
    else if(method==="order_open"){
        set_open_order_table();
    }
    else if(method==="order_cancel"){
        set_order_cancel_table();
    }
    else if(method==="trade_history"){
        set_trade_history_table();
    }
    else if(method==="pollgap"){
        set_pollgap_table();
    }
    else if(method==="setuserid"){
        set_setuserid_table();
    }
    else if(method==="allpairs"){
        set_allpair_table();
    }
    
    else{
        console.log("wrong method value");
    }
       
    $('#Instandex_output_table').html("");
};