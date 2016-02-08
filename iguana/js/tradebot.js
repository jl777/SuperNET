
//THREE_STRINGS_AND_DOUBLE(tradebot,monitor,exchange,base,rel,commission);
var Tradebot_monitor_api=function(){
    var exchange=$('#Tradebot_exchange').val();
    var base=$('#Tradebot_base').val();
    var rel=$('#Tradebot_rel').val();
    var commission=$('#Tradebot_commission').val();
    
     var request='{"agent":"tradebot","method":"monitor","exchange":"'+exchange+'","base":"'+base+'","rel":"'+rel+'", "commission":'+commission+'}';
    SPNAPI.makeRequest(request, function(request,response){
        show_tradebot_resposnse(response);   
    }
        );
    //console.log("Monitor called");
};

var set_Tradebot_monitor_table=function(){
 var html='<tr><td align="center" >  Base:</td><td align="center" ><input type="text" id="Tradebot_base"/></td></tr><tr><td align="center" >Rel:</td><td align="center" ><input type="text" id="Tradebot_rel"/></td></tr><tr><td align="center" >Commission:</td><td align="center" ><input type="text" id="Tradebot_commission"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Tradebot_exchange" id="Tradebot_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary Tradebot_monitor" >Monitor Tradebot</button></td></tr>';
    $('#tradebot_input').html(html);
    if(exchanges!==""){
    $('#Tradebot_exchange').html(exchanges);
}   
    
};

//STRING_AND_DOUBLE(tradebot,monitorall,exchange,commission);
var Tradebot_monitorall_api=function(){
    var exchange=$('#Tradebot_exchange').val();
    var commission=$('#Tradebot_commission').val();
    
     var request='{"agent":"tradebot","method":"monitorall","exchange":"'+exchange+'","commission":'+commission+'}';
    SPNAPI.makeRequest(request, function(request,response){
        show_tradebot_resposnse(response);   
    }
        );
    
};

var set_Tradebot_monitorall_table=function(){
 var html='<tr><td align="center" >Commission:</td><td align="center" ><input type="text" id="Tradebot_commission"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Tradebot_exchange" id="Tradebot_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary Tradebot_monitorall" >Monitor all Exchanges</button></td></tr>';
    $('#tradebot_input').html(html);
    if(exchanges!==""){
    $('#Tradebot_exchange').html(exchanges);
    }   
    
};

//THREE_STRINGS(tradebot,unmonitor,exchange,base,rel);
var Tradebot_unmonitor_api=function(){
var exchange=$('#Tradebot_exchange').val();
    var base=$('#Tradebot_base').val();
    var rel=$('#Tradebot_rel').val();
    //var commission=$('#Tradebot_commission').val();
    
     var request='{"agent":"tradebot","method":"unmonitor","exchange":"'+exchange+'","base":"'+base+'","rel":"'+rel+'"}';
    SPNAPI.makeRequest(request, function(request,response){
        show_tradebot_resposnse(response);   
    }
        );
    //console.log("Monitor called");    
    
};

var set_Tradebot_unmonitor_table=function(){
    var html='<tr><td align="center" >  Base:</td><td align="center" ><input type="text" id="Tradebot_base"/></td></tr><tr><td align="center" >Rel:</td><td align="center" ><input type="text" id="Tradebot_rel"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Tradebot_exchange" id="Tradebot_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary Tradebot_unmonitor_api" >UnMonitor Tradebot</button></td></tr>';
    $('#tradebot_input').html(html);
    if(exchanges!==""){
    $('#Tradebot_exchange').html(exchanges);
}
    
};

//THREE_STRINGS_AND_THREE_DOUBLES(tradebot,accumulate,exchange,base,rel,price,volume,duration);
var Tradebot_accumulate_api=function(){
    var exchange=$('#Tradebot_exchange').val();
    var base=$('#Tradebot_base').val();
    var rel=$('#Tradebot_rel').val();
    var price=$('#Tradebot_price').val();
    var volume=$('#Tradebot_volume').val();
    var duration=$('#Tradebot_duration').val();
    
     var request='{"agent":"tradebot","method":"accumulate","exchange":"'+exchange+'","base":"'+base+'","rel":"'+rel+'", "price":'+price+',"volume":'+volume+',"duration":'+duration+'  }';
    SPNAPI.makeRequest(request, function(request,response){
        show_tradebot_resposnse(response);   
    }
        );
};

var set_Tradebot_accumulate_table=function(){
     var html='<tr><td align="center" >  Base:</td><td align="center" ><input type="text" id="Tradebot_base"/></td></tr><tr><td align="center" >Rel:</td><td align="center" ><input type="text" id="Tradebot_rel"/></td></tr><tr><td align="center" >Price:</td><td align="center" ><input type="text" id="Tradebot_price"/></td></tr><tr><td align="center" >Volume:</td><td align="center" ><input type="text" id="Tradebot_volume"/></td></tr><tr><td align="center" >Duration:</td><td align="center" ><input type="text" id="Tradebot_duration"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Tradebot_exchange" id="Tradebot_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary Tradebot_accumulate" >Accumulate Tradebot</button></td></tr>';
    $('#tradebot_input').html(html);
    if(exchanges!==""){
    $('#Tradebot_exchange').html(exchanges);
} 
};


//THREE_STRINGS_AND_THREE_DOUBLES(tradebot,divest,exchange,base,rel,price,volume,duration);
var Tradebot_divest_api=function(){
    
        var exchange=$('#Tradebot_exchange').val();
    var base=$('#Tradebot_base').val();
    var rel=$('#Tradebot_rel').val();
    var price=$('#Tradebot_price').val();
    var volume=$('#Tradebot_volume').val();
    var duration=$('#Tradebot_duration').val();
    
     var request='{"agent":"tradebot","method":"divest","exchange":"'+exchange+'","base":"'+base+'","rel":"'+rel+'", "price":'+price+',"volume":'+volume+',"duration":'+duration+'  }';
    SPNAPI.makeRequest(request, function(request,response){
        show_tradebot_resposnse(response);   
    }
        );

};

var set_Tradebot_divest_table=function(){
      var html='<tr><td align="center" >  Base:</td><td align="center" ><input type="text" id="Tradebot_base"/></td></tr><tr><td align="center" >Rel:</td><td align="center" ><input type="text" id="Tradebot_rel"/></td></tr><tr><td align="center" >Price:</td><td align="center" ><input type="text" id="Tradebot_price"/></td></tr><tr><td align="center" >Volume:</td><td align="center" ><input type="text" id="Tradebot_volume"/></td></tr><tr><td align="center" >Duration:</td><td align="center" ><input type="text" id="Tradebot_duration"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Tradebot_exchange" id="Tradebot_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary Tradebot_divest" >Divest Tradebot</button></td></tr>';
    $('#tradebot_input').html(html);
    if(exchanges!==""){
    $('#Tradebot_exchange').html(exchanges);
} 
   
    
};

//STRING_ARG(tradebot,activebots,exchange);
var Tradebot_activebots_api=function(){
    var exchange=$('#Tradebot_exchange').val();
    var request='{"agent":"tradebot","method":"activebots","exchange":"'+exchange+'"}';
    SPNAPI.makeRequest(request, function(request,response){
        show_tradebot_resposnse(response);   
    }
        );
    
};

var set_Tradebot_activebots_table=function(){
    var html='<tr><td align="center" >  Exchange:</td><td align="center" ><select name="Tradebot_exchange" id="Tradebot_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary Tradebot_activebots" >Get active Tradebot</button></td></tr>';
    $('#tradebot_input').html(html);
    if(exchanges!==""){
    $('#Tradebot_exchange').html(exchanges);
    }
};

//TWO_STRINGS(tradebot,status,exchange,botid);
var Tradebot_status_api=function(){
    var exchange=$('#Tradebot_exchange').val();
    var botid=$('#Tradebot_botid').val();
    
     var request='{"agent":"tradebot","method":"status","exchange":"'+exchange+'","botid":"'+botid+'"}';
    SPNAPI.makeRequest(request, function(request,response){
        show_tradebot_resposnse(response);   
    }
        );
};

var set_Tradebot_status_table=function(){
    var html='<tr><td align="center" >Botid:</td><td align="center" ><input type="text" id="Tradebot_botid"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Tradebot_exchange" id="Tradebot_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary Tradebot_status" >Check status of Tradebot</button></td></tr>';
    $('#tradebot_input').html(html);
    if(exchanges!==""){
    $('#Tradebot_exchange').html(exchanges);}   
    
    
    
};

//TWO_STRINGS(tradebot,pause,exchange,botid);
var Tradebot_pause_api=function(){
    
        var exchange=$('#Tradebot_exchange').val();
    var botid=$('#Tradebot_botid').val();
    
     var request='{"agent":"tradebot","method":"pause","exchange":"'+exchange+'","botid":"'+botid+'"}';
    SPNAPI.makeRequest(request, function(request,response){
        show_tradebot_resposnse(response);   
    }
        );

};

var set_Tradebot_pause_table=function(){
    var html='<tr><td align="center" >Botid:</td><td align="center" ><input type="text" id="Tradebot_botid"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Tradebot_exchange" id="Tradebot_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary Tradebot_pause" >Pause Tradebot</button></td></tr>';
    $('#tradebot_input').html(html);
    if(exchanges!==""){
    $('#Tradebot_exchange').html(exchanges);
}   
  
};

//TWO_STRINGS(tradebot,stop,exchange,botid);
var Tradebot_stop_api=function(){
            var exchange=$('#Tradebot_exchange').val();
    var botid=$('#Tradebot_botid').val();
    
     var request='{"agent":"tradebot","method":"stop","exchange":"'+exchange+'","botid":"'+botid+'"}';
    SPNAPI.makeRequest(request, function(request,response){
        show_tradebot_resposnse(response);   
    }
        );


};

var set_Tradebot_stop_table=function(){
         var html='<tr><td align="center" >Botid:</td><td align="center" ><input type="text" id="Tradebot_botid"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Tradebot_exchange" id="Tradebot_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary Tradebot_stop" >Stop Tradebot</button></td></tr>';
    $('#tradebot_input').html(html);
    if(exchanges!==""){
    $('#Tradebot_exchange').html(exchanges);
}
};

//TWO_STRINGS(tradebot,resume,exchange,botid);
var Tradebot_resume_api=function(){
    
            var exchange=$('#Tradebot_exchange').val();
    var botid=$('#Tradebot_botid').val();
    
     var request='{"agent":"tradebot","method":"resume","exchange":"'+exchange+'","botid":"'+botid+'"}';
    SPNAPI.makeRequest(request, function(request,response){
        show_tradebot_resposnse(response);   
    }
        );


};

var set_Tradebot_resume_table=function(){
    var html='<tr><td align="center" >Botid:</td><td align="center" ><input type="text" id="Tradebot_botid"/></td></tr><tr><td align="center" >  Exchange:</td><td align="center" ><select name="Tradebot_exchange" id="Tradebot_exchange"></select></td></tr><tr><td colspan="2" align="center"> <button class="btn btn-primary Tradebot_resume" >Resume Tradebot</button></td></tr>';
    $('#tradebot_input').html(html);
    if(exchanges!==""){
    $('#Tradebot_exchange').html(exchanges);
}

};



var tradebot_set_method_table=function (method){
    
    if(method==="monitor"){
        set_Tradebot_monitor_table();
    }else if(method==="monitorall"){
        set_Tradebot_monitorall_table();
    }else if(method==="unmonitor"){
        set_Tradebot_unmonitor_table();
    }else if(method==="accumulate"){
        set_Tradebot_accumulate_table();
    }else if(method==="divest"){
        set_Tradebot_divest_table();
    }
    else if(method==="activebots"){
        set_Tradebot_activebots_table();
    }
    else if(method==="status"){
        set_Tradebot_status_table();
    }
    else if(method==="pause"){
        set_Tradebot_pause_table();
    }
    else if(method==="stop"){
        set_Tradebot_stop_table();
    }
    else if(method==="resume"){
        set_Tradebot_resume_table();
    }    
    else{
        console.log("wrong method value");
    }
       
    $('#trade_output').html("");
};

var show_tradebot_resposnse=function(response){
    
 $('#trade_output').html(""); 
         response=JSON.parse(response);
         for(var i in response){
             if(i==='tag') continue;
             var value="";
             if(response[i] instanceof Array){
                 value=value+"<ul>";
                 for(var x in response[i]){
                    value=value+"<li>"+response[i][x]+"<li>";
                }
                value=value+"</ul>";
             }else{value=response[i];}
             $('#trade_output').append("<tr><td align='center'>"+i+"</td><td align='center'>"+value+"</td></tr>"); 
         }   
};