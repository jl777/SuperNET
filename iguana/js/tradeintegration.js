
/*
var base="NXT";
var rel="BTC";
var depth=20;
var exchange="poloniex";

var currentValues={"low":0,"high":0};
var valuesHistory=[];

var BalanceBaseHistory=[];
var BalanceRelHistory=[];

var timer=0;

var interval=5000; //5 sec

var decision_timelimit=1000*60; //1 min

var percentChange=5;

var volume=10;

var ordersHistory=[];

var loopcounter=-1;

var ranFirstTyme=true;

var ordernumber="";
var phase=0; // 0 means buy 1 means sell
var transactionCount=0;
*/
var IntegrationSettings={
    "phase":0,
    "currentValues":{"low":0,"high":0},
    "exchange":"poloniex",
    "base":"NXT",
    "rel":"BTC",
    "depth":20,
    "volume":10,
    "ordersHistory":[],
    "valuesHistory":[],
    "BalanceRelHistory":[],
    "BalanceBaseHistory":[],
    "timer":0,
    "decision_timelimit":1000*60,
    "interval":5000,
    "percentChange":5,
    "loopcounter":-1,
    "ranFirstTyme":true,
    "ordernumber":""
    
};

var start_integrationTest=function(){
    
    mainlogic();
};



var mainlogic=function(){
  IntegrationSettings.loopcounter=IntegrationSettings.loopcounter+1;
    get_current_min_max(); // step 1
    
};

var get_current_min_max=function(){
    
    var request='{"agent":"InstantDEX","method":"orderbook","exchange":"'+IntegrationSettings.exchange+'","base":"'+IntegrationSettings.base+'","rel":"'+IntegrationSettings.rel+'","depth":'+IntegrationSettings.depth+',"allfields":0,"invert":0}';
    
    SPNAPI.makeRequest(request, function(request,response){
       
        /*
         * 
         * {"exchange":"btce","inverted":0,"base":"LTC","rel":"BTC","bids":[0.00814000, 0.00813000, 0.00812000, 0.00811000, 0.00810000, 0.00809000, 0.00808000, 0.00807000, 0.00806000, 0.00805000, 0.00804000, 0.00803000, 0.00802000, 0.00801000, 0.00800000, 0.00799000, 0.00798000, 0.00797000, 0.00796000, 0.00795000],"asks":[0.00816000, 0.00817000, 0.00818000, 0.00819000, 0.00820000, 0.00821000, 0.00822000, 0.00823000, 0.00824000, 0.00825000, 0.00826000, 0.00827000, 0.00828000, 0.00829000, 0.00830000, 0.00831000, 0.00832000, 0.00833000, 0.00834000, 0.00835000],"numbids":20,"numasks":20,"highbid":0.00814000,"lowask":0.00816000,"timestamp":1454329614,"time":"2016-02-01T12:26:54Z","maxdepth":20,"tag":"374388797247258721"}
         */
        response=JSON.parse(response);
        if(response.lowask){
            IntegrationSettings.valuesHistory[IntegrationSettings.loopcounter]=IntegrationSettings.currentValues;
        IntegrationSettings.currentValues.low=response.lowask;
        IntegrationSettings.currentValues.high=response.highbid;
        console.log("current low: "+response.lowask+" current high:"+response.highbid);
            if(IntegrationSettings.ranFirstTyme){buyOrder();IntegrationSettings.ranFirstTyme=false;} // step 2
            else{
                if(IntegrationSettings.phase===0){
                checkifBuySuccessful();                     // step 3
                }else{
                    checkifSellSuccessful();                //step 4
                }

                
            }
        
        }else{
            get_current_min_max();
        }
    });
    
};

//http://127.0.0.1:7778/api/InstantDEX/buy?exchange={string}&base={string}&rel={string}&price={float}&volume={float}&dotrade={float}
var buyOrder=function(){
    console.log("trying to buy at current lowprice");
    IntegrationSettings.phase=0;
    var request='{"agent":"InstantDEX","method":"buy","exchange":"'+IntegrationSettings.exchange+'","base":"'+IntegrationSettings.base+'","rel":"'+IntegrationSettings.rel+'","price":'+IntegrationSettings.currentValues.low+',"volume":'+IntegrationSettings.volume+',"dotrade":1}';
    
    
    SPNAPI.makeRequest(request, function(request,response){
        
        response=JSON.parse(response);
        if(response.orderNumber){
            //transactionCount=transactionCount+1;
            IntegrationSettings.ordernumber=response.orderNumber;
            //response.count=transactionCount;
            response.today=new Date().today();
            response.now=new Date().timeNow();
            response.type="buy";
            IntegrationSettings.ordersHistory.push(response);
            // check if the order is open/not
            if(response.resultingTrades.length!==0){
                // check if it is completed
                attemptSell();
            }else{
                setTimeout(function () { mainlogic(); }, IntegrationSettings.decision_timelimit); 
                // execute after decision_timelimit
            }
        }
        
    });
};

//http://127.0.0.1:7778/api/InstantDEX/sell?exchange={string}&base={string}&rel={string}&price={float}&volume={float}&dotrade={float}

var sellOrder=function(){
    
    var request='{"agent":"InstantDEX","method":"sell","exchange":"'+IntegrationSettings.exchange+'","base":"'+IntegrationSettings.base+'","rel":"'+IntegrationSettings.rel+'","price":'+IntegrationSettings.price+',"volume":'+IntegrationSettings.volume+',"dotrade":1}';
    SPNAPI.makeRequest(request, function(request,response){
        
                show_resposnse(response);
    });
};

var checkOrderstatus=function(){
    
    var request='{"agent":"InstantDEX","method":"orderstatus","exchange":"'+IntegrationSettings.exchange+'","orderid":"'+IntegrationSettings.orderid+'"}';
    SPNAPI.makeRequest(request, function(request,response){
          
        
    });
};

var getTradeHistory=function(){
     var request='{"agent":"InstantDEX","method":"tradehistory","exchange":"'+IntegrationSettings.exchange+'"}';
    SPNAPI.makeRequest(request, function(request,response){
                 response=JSON.parse(response);
                 var othercurr="";
                 if(IntegrationSettings.rel!=="BTC"){othercurr=IntegrationSettings.rel;}
                 else{othercurr=IntegrationSettings.base;}
        if(response["BTC_"+othercurr]){
            // transaction is completed
            console.log("transaction is complete");
        }
    });
    
};

var checkifBuySuccessful=function (){
        console.log("checking if previus buy was successful");
    var request='{"agent":"InstantDEX","method":"openorders","exchange":"'+IntegrationSettings.exchange+'"}';
    SPNAPI.makeRequest(request, function(request,response){
         response=JSON.parse(response);
         var othercurr="";
         var unsuccessful=false;
                 if(IntegrationSettings.rel!=="BTC"){othercurr=IntegrationSettings.rel;}
                 else{othercurr=IntegrationSettings.base;}
         if(response["BTC_"+othercurr].length>0){
             for(var jsn in response["BTC_"+othercurr]){
                 if(jsn.orderNumber===IntegrationSettings.ordernumber && jsn.type==="buy"){
                     unsuccessful=true;
                     break;
                 }
             }
             if(unsuccessful){
                 cancelandReBuy();
             }else{
                 attemptSell(); 
             }
         
        }else{
            attemptSell();
        }
    });
    
};

var checkifSellSuccessful=function (){
    console.log("checking if previous sell was successful");
    var request='{"agent":"InstantDEX","method":"openorders","exchange":"'+IntegrationSettings.exchange+'"}';
    SPNAPI.makeRequest(request, function(request,response){
         response=JSON.parse(response);
         var othercurr="";
         var unsuccessful=false;
                 if(IntegrationSettings.rel!=="BTC"){othercurr=IntegrationSettings.rel;}
                 else{othercurr=IntegrationSettings.base;}
         if(response["BTC_"+othercurr].length>0){
             for(var jsn in response["BTC_"+othercurr]){
                 if(jsn.orderNumber===IntegrationSettings.ordernumber && jsn.type==="sell"){
                     unsuccessful=true;
                     break;
                 }
             }
             if(unsuccessful){
                 cancelandReSell();
             }else{
                 console.log("Finally we are done!");
                 // and we are done!!
             }
         
        }else{
            console.log("Finally we are done!");
            // and we are done!!
        }
    });
    
};


var cancelandReBuy=function(){
    cancelBuy();
    
    
};
var cancelandReSell=function(){
    cancelSell();
};


var reSell=function(){
    IntegrationSettings.phase=1;    // change phase to control the flow
    var newlow=0;
    if(IntegrationSettings.valuesHistory[IntegrationSettings.loopcounter].high===IntegrationSettings.currentValues.high){
        newlow=IntegrationSettings.currentValues.high-(IntegrationSettings.currentValues.high*IntegrationSettings.percentChange)/100; 
        console.log("selling at reduced high "+newlow);
    }else{
        
        newlow=IntegrationSettings.currentValues.high;
        console.log("selling at current high "+newlow);
    }
    var request='{"agent":"InstantDEX","method":"buy","exchange":"'+IntegrationSettings.exchange+'","base":"'+IntegrationSettings.base+'","rel":"'+IntegrationSettings.rel+'","price":'+newlow+',"volume":'+IntegrationSettings.volume+',"dotrade":1}';
    IntegrationSettings.totalBoughtRel=newlow;
    IntegrationSettings.totalBoughtBase=IntegrationSettings.volume;
    
    SPNAPI.makeRequest(request, function(request,response){
        
        response=JSON.parse(response);
        if(response.orderNumber){
            IntegrationSettings.ordernumber=response.orderNumber;
            response.today=new Date().today();
            response.now=new Date().timeNow();
            response.type="sell";
            IntegrationSettings.ordersHistory.push(response);
            // check if the order is open/not
            if(response.resultingTrades.length!==0){
                // check if it is completed
                attemptSell();
            }else{
                setTimeout(function () { mainlogic(); }, IntegrationSettings.decision_timelimit); 
                // execute after decision_timelimit
            }
        }
        
    });
};

var rebuy=function(){
    IntegrationSettings.phase=0;    // change phase to control the flow
    var newlow=0;
    if(IntegrationSettings.valuesHistory[IntegrationSettings.loopcounter].low===IntegrationSettings.currentValues.low){
        newlow=IntegrationSettings.currentValues.low+(IntegrationSettings.currentValues.low*IntegrationSettings.percentChange)/100; 
        newlow=IntegrationSettings.currentValues.low;
        console.log("buying at current low "+newlow);
    }else{
        newlow=IntegrationSettings.currentValues.low;
        console.log("buying at current low "+newlow);
        
    }
    var request='{"agent":"InstantDEX","method":"buy","exchange":"'+IntegrationSettings.exchange+'","base":"'+IntegrationSettings.base+'","rel":"'+IntegrationSettings.rel+'","price":'+newlow+',"volume":'+IntegrationSettings.volume+',"dotrade":1}';
    totalBoughtRel=newlow;
    totalBoughtBase=volume;
    
    SPNAPI.makeRequest(request, function(request,response){
        
        response=JSON.parse(response);
        if(response.orderNumber){
            //transactionCount=transactionCount+1;
            ordernumber=response.orderNumber;
            //response.count=transactionCount;
            response.today=new Date().today();
            response.now=new Date().timeNow();
            response.type="buy";
            IntegrationSettings.ordersHistory.push(response);
            // check if the order is open/not
            if(response.resultingTrades.length!==0){
                // check if it is completed
                attemptSell();
            }else{
                setTimeout(function () { mainlogic(); }, IntegrationSettings.decision_timelimit); 
                // execute after decision_timelimit
            }
        }
        
    });
};

var cancelBuy=function(){
    
    var request='{"agent":"InstantDEX","method":"cancelorder","exchange":"'+IntegrationSettings.exchange+'","orderid":"'+IntegrationSettings.ordernumber+'"}';
    SPNAPI.makeRequest(request, function(request,response){
        
                  response=JSON.parse(response);
                  if(response.success===1){
                      rebuy();
                  }else{
                      attemptSell();
                  }
    });
};


var cancelSell=function(){
    
    var request='{"agent":"InstantDEX","method":"cancelorder","exchange":"'+IntegrationSettings.exchange+'","orderid":"'+IntegrationSettings.ordernumber+'"}';
    SPNAPI.makeRequest(request, function(request,response){
        
                  response=JSON.parse(response);
                  if(response.success===1){
                      reSell();
                  }else{
                      console.log("Finally we are done!");
                      // and we are done!!
                  }
    });
};

var attemptSell=function(){
    IntegrationSettings.phase=1;
    var request='{"agent":"InstantDEX","method":"sell","exchange":"'+IntegrationSettings.exchange+'","base":"'+IntegrationSettings.base+'","rel":"'+IntegrationSettings.rel+'","price":'+IntegrationSettings.currentValues.high+',"volume":'+IntegrationSettings.volume+',"dotrade":1}';
    SPNAPI.makeRequest(request, function(request,response){
        response=JSON.parse(response);
        if(response.orderNumber){
            IntegrationSettings.transactionCount=IntegrationSettings.transactionCount+1;
            ordernumber=response.orderNumber;
            response.count=IntegrationSettings.transactionCount;
            response.today=new Date().today();
            response.now=new Date().timeNow();
            response.type="sell";
            IntegrationSettings.ordersHistory.push(response);
            // check if the order is open/not
            if(response.resultingTrades.length!==0){
                // check if it is completed
                console.log("Finally we are done!");
            }else{
                setTimeout(function () { mainlogic(); }, IntegrationSettings.decision_timelimit); 
                // execute after decision_timelimit
            }
        }
    });
};



Date.prototype.today = function () { 
    return ((this.getDate() < 10)?"0":"") + this.getDate() +"/"+(((this.getMonth()+1) < 10)?"0":"") + (this.getMonth()+1) +"/"+ this.getFullYear();
};

// For the time now
Date.prototype.timeNow = function () {
     return ((this.getHours() < 10)?"0":"") + this.getHours() +":"+ ((this.getMinutes() < 10)?"0":"") + this.getMinutes() +":"+ ((this.getSeconds() < 10)?"0":"") + this.getSeconds();
};