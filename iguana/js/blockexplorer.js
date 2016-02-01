/*
 * 
 * Variables to store values:
 * 
 */

var BlockHash="";
var Block="";
var checkExternalBlock=0;

/*
 * 
 * @returns {undefined}
 * the function sets output to show radio buttons
 * And then select between coins to start RPC calls
 * 
 */

var setCoinRadio=function(){
    
  var html="";
for (var index = 0; index < coinManagement.Coins.length; index++) {
    var coin=coinManagement.Coins[index].Symbol;
    html=html+'<label class="radio-inline"><input class="coinRPCactive" type="radio" name="blockEXPcoin" data-value="'+coin+'">'+coin+'</label>';
        
    }
   
document.getElementById('BlockExpCoin').innerHTML = html; 

};

/*
 * 
 * @param {type} coin
 * @returns {undefined}
 * called when user click on one of radio buttons
 * to start RPC for particular coin
 */

var callBlockEXPRPC=function(coin){
    
    var request="{\"agent\":\"SuperNET\",\"method\":\"bitcoinrpc\",\"setcoin\":\""+coin+"\"}";
    
    SPNAPI.makeRequest(request, function(request,response){
        response=JSON.parse(response);
        if(response.result && response.result==='set bitcoin RPC coin'){
            document.getElementById('Blockhashbutton').innerHTML='<button class="btn btn-raised btn-success btn-xs getBlockHashActionButton" data-height="0">Get blockhash</button>';
        }
    });
};

/*
 * 
 * @param {type} height
 * @returns {undefined}
 * Function gets the blockhash when called and is stored in global variable
 * (initially height is set to zero)
 * 
 */
var getBlockhash= function(height){
    
    var request="{\"agent\":\"ramchain\",\"method\":\"getblockhash\",\"height\":\""+height+"\"}";
    
    SPNAPI.makeRequest(request, function(request,response){
            response=JSON.parse(response);
            if(response.result){
                BlockHash=response.result;
                //Blockhashoutput
                document.getElementById('Blockhashoutput').innerHTML='Blockhash is: '+BlockHash;
                document.getElementById('Blockbutton').innerHTML='<button class="btn btn-raised btn-success btn-xs getBlockActionButton" data-hash="'+BlockHash+'">Get block</button>';
        
                }
        });
    
};

/*
 * 
 * @param {type} hash
 * @returns {undefined}
 * Function gets Block for a paritculat blockhash
 * and store inside global varianle
 * 
 */
var getBlock= function(hash){
    
    var request="{\"agent\":\"ramchain\",\"method\":\"getblock\",\"blockhash\":\""+hash+"\",\"remoteonly\":\""+checkExternalBlock+"\"}";
    
    SPNAPI.makeRequest(request, function(request,response){
            response=JSON.parse(response);
            if(response.result){
                document.getElementById('Blockoutput').innerHTML=response.result;
                Block=response.result;
                document.getElementById('transactionButton').innerHTML='<button class="btn btn-raised btn-success btn-xs getTrancationActionButton" data-hash="'+Block+'">Get transaction</button>';
        
                }
        });
    
};

/*
 * 
 * @param {type} Hash
 * @returns {undefined}
 * Function implements getrawtransaction API call to get raw transaction
 * 
 */
// Example Txids used
//0b9cf7e23c07dc02e31392548e743605df8f90acacfd749ae6aaa0457d62d08a
//081ed782fdcf940de229e89336247e1bcce3599613af26d9c47a8eb18d6a3bb7
//e7386986f14c994d6c70e8eb60753ea1fe2dc2a58567e6269dc6b04ef5310693
//5f7edfb417855f80b7c12e1a9c040f8b496db23c82c90e4de905b8cff8139f03
var getRawTransaction=function(Hash){
    var request="{\"agent\":\"ramchain\",\"method\":\"getrawtransaction\",\"txid\":\"5f7edfb417855f80b7c12e1a9c040f8b496db23c82c90e4de905b8cff8139f03\",\"verbose\":1}";
    SPNAPI.makeRequest(request, function(request,response){
            /*response=JSON.parse(response);
            if(response.result){
                document.getElementById('Blockoutput').innerHTML=response.result;
                //document.getElementById('Blockbutton').innerHTML='<button class="btn btn-raised btn-success btn-xs getBlockActionButton" data-hash="'+BlockHash+'">Get block</button>';
        
                }*/
        });
};

/*
 * 
 * called initially
 * 
 */
var startBlockExplorer=function(){
    
    setCoinRadio();

};

