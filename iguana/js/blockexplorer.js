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
            
        blockExp_input_table();
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

var filterInt = function (value) {
  if(/^(\-|\+)?([0-9]+|Infinity)$/.test(value))
    return Number(value);
  return "NaN";
};

var getBlockhash= function(height){
    
    var height=($('#BlockExp_height').val());
    /*
    if (height === "NaN" || height ==='Infinity') {
     height=0;
    }*/
    var request="{\"agent\":\"ramchain\",\"method\":\"getblockhash\",\"height\":\""+height+"\"}";
    
    SPNAPI.makeRequest(request, function(request,response){
            response=JSON.parse(response);
            if(response.result){
                BlockHash=response.result;
                //Blockhashoutput
                document.getElementById('block_output_table').innerHTML='<tr><td >'+'Blockhash is:</td><td  width="300px"> '+BlockHash+'</td></tr>';
                $('#BlockExp_blockhash').val(BlockHash);
        
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
    var inputhash=$('#BlockExp_blockhash').val();
    if(inputhash!==hash){
        hash=inputhash;
    }
    var request="{\"agent\":\"ramchain\",\"method\":\"getblock\",\"blockhash\":\""+hash+"\",\"remoteonly\":\""+checkExternalBlock+"\"}";
    
    SPNAPI.makeRequest(request, function(request,response){
            response=JSON.parse(response);
            if(response.result){
                document.getElementById('block_output_table').innerHTML='<tr><td >'+'Block is: </td><td >'+response.result+'</th></td>';
                Block=response.result;
                }else if(response.error){
                document.getElementById('block_output_table').innerHTML='<tr><td >'+JSON.stringify(response)+'</th></td>';
                    
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
    
    var inputhash=$('#BlockExp_txid').val();
    var request="{\"agent\":\"ramchain\",\"method\":\"getrawtransaction\",\"txid\":\""+inputhash+"\",\"verbose\":1}";
    SPNAPI.makeRequest(request, function(request,response){
        document.getElementById('block_output_table').innerHTML='<tr><td>'+'Output is:</td><td width="300px"> '+response+'</th></td>';
                
            /*response=JSON.parse(response);
            if(response.result){
                document.getElementById('Blockoutput').innerHTML=response.result;
                //document.getElementById('Blockbutton').innerHTML='<button class="btn btn-raised btn-success btn-xs getBlockActionButton" data-hash="'+BlockHash+'">Get block</button>';
        
                }*/
        });
};

var change_ExternalBlocks=function(){
    

            if(document.getElementById('cbChangeExternalBlocks').checked){
                    checkExternalBlock=1;
            }else{
                 checkExternalBlock=0;
            }
            console.log("CheckExternalBlock flag change to "+checkExternalBlock);
    
};

document.getElementById('cbChangeExternalBlocks').onclick = function () {
    change_ExternalBlocks();
};

/*
 * 
 * called initially
 * 
 */
var startBlockExplorer=function(){
    
    setCoinRadio();

};
var blockExp_input_table=function(){
  
    var table='<tr><th>Input height:</th><td><input type="text" id="BlockExp_height"></td>\
<td><button class="btn btn-raised btn-success btn-xs getBlockHashActionButton" data-height="0">Get blockhash</button></td></tr>\
<tr><th>Blockhash:</th><td><input type="text" id="BlockExp_blockhash" value=""></td><td><button class="btn btn-raised btn-success btn-xs getBlockActionButton" data-hash="">Get block</button></td></tr>\n\
<tr><th>Txid:</th><td><input type="text" id="BlockExp_txid"></td><td><button class="btn btn-raised btn-success btn-xs getTrancationActionButton" data-hash="">Get transaction</button></td></tr>';
    document.getElementById('block_input_table').innerHTML=table;
    document.getElementById('block_output_table').innerHTML="";
};

function filesystem_show_file_name(){
$.ajax({
    url:fileSystem.root.toURL()+"images/BTC_blocks.jpg",
    type:'HEAD',
    error: function()
    {
        console.log("file doesnt exists");
    },
    success: function(response, textStatus, jqXHR)
    {
        console.log("Hurray we are good to go!");
        console.log("response is:");
        //file exists
    }
});
//document.getElementById('block_output_table').innerHTML='<a href="'+fileSystem.root.toURL()+"images/BTC_blocks.jpg"+'" download="MyGoogleLogo">download me</a>';

/*fileSystem.root.getFile('confs/iguana.4206523045167609019', {}, function(fileEntry) {

    // Get a File object representing the file,
    // then use FileReader to read its contents.
    fileEntry.file(function(file) {
       var reader = new FileReader();

       reader.onloadend = function(e) {
         //var txtArea = document.createElement('textarea');
         console.log("Configuration file text: "+this.result.toString());
         console.log("Full path is:"+fileEntry.fullPath);
         //document.body.appendChild(txtArea);
         document.getElementById('mousexy').innerHTML=this.result;
       };

       reader.readAsText(file);
    }, errorHandler);

  }, errorHandler);*/
      
}