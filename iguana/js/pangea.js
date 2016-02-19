/*
 * Implement basic commands
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"pangea\",\"method\":\"host\",\"minplayers\":2,\"params\":[]}"
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"pangea\",\"method\":\"lobby\"}"
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"pangea\",\"method\":\"join\",\"tablehash\":\"18e9e7448a68a4d46bfde55be0e667c4f4ba015e2c183fbc7cbc0c26996f7656\",\"handle\":\"mini\"}"
curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"pangea\",\"method\":\"start\",\"tablehash\":\"18e9e7448a68a4d46bfde55be0e667c4f4ba015e2c183fbc7cbc0c26996f7656\"}"
 * 
 */

/*
 * Saves data in format
 * {"tablehash":"9542c00ef64a73814e5694011703a69608c528c077b55cf7669d77432b7bb32b","host":"0.0.0.0","minbuyin":0,"maxbuyin":0,"minplayers":2,"maxplayers":2,"M":0,"N":2,"numcards":52,"rake":0,"maxrake":0,"hostrake":0,"pangearake":0,"bigblind":0,"ante":0,"opentime":"2016-01-30T11:30:22Z","numactive":0}
 */
var Tables=[];

/*
 * JS function to check if String is JSON
 * If yes it returns the JSON object as output
 * 
 */
function IsJsonString(str) {
    var json;
    try {
        json=JSON.parse(str);
    } catch (e) {
        return false;
    }
    return json;
}

/*
 * Funcion called when User clicks on
 * "Host Game" Button
 * Takes JSON strings as Request
 * Implements API call to host a game
 * 
 */

var hostPangea=function(){
  var text = $('textarea#json_src').val();
  var request=IsJsonString(text);
  if(request!==false){
      
      if(!request.agent){
          request.agent="pangea";
      }
      if(!request.method){
       request.method="host";   
      }
      if(!request.minplayers){
       request.minplayers=2;   
       console.log("Minimum playes is set to 2");
      }
      request=JSON.stringify(request);
      //var request='{"agent":"pangea","method":"host","minplayers":2,"params":["127.0.0.1"]}';
    SPNAPI.makeRequest(request, function(request,response){
            
    }
        );
  }else{
      console.log("Not a valid JSON");
  }
    
};

/*
 * Sets the HTML for returned list of games
 * And show in GUI
 */

var showGameList=function(){
    //console.log($('#game_list_table tbody').html());
    $('#game_list_table tbody').html("");
    var newTab;
    newTab = "<tr class='row history-row'><td >Host</td><td >MinBuyin</td><td >MaxBuyin</td><td >Min player</td><td >Max player</td><td>Join</td></tr>";
    $('#game_list_table tbody').append(newTab);
    for(var j=0; j<Tables.length;j++){
    newTab = "<tr class='row history-row'><td >"+Tables[j].host+"</td><td >"+Tables[j].minbuyin+"</td><td >"+Tables[j].maxbuyin+"</td><td >"+Tables[j].minplayers+"</td><td >"+Tables[j].maxplayers+"</td><td >"+'<button class="btn btn-primary join_pangea_game" data-tablehash="'+Tables[j].tablehash+'">Join</button>'+"</td></tr>";
    $('#game_list_table tbody').append(newTab);
    }
    
};

/*
 * API call to Get list of games
 */
var lobbyPangea= function(){
    
    var request='{"agent":"pangea","method":"lobby"}';
    SPNAPI.makeRequest(request, function(request,response){
        response=JSON.parse(response);
            if(response.tables){
                Tables=response.tables;
                showGameList();
            }
            
    }
        );
    
};

/*
 *  API call to Join a game
 *  Called when user clicks on "Join" button in Pangea tab
 */
var joinPangea= function(hash){
    var request='{"agent":"pangea","method":"join","tablehash":"'+hash+'","handle":"mini"}';
    SPNAPI.makeRequest(request, function(request,response){
            
    }
        );
    
};

var startGamePangea= function(){
    var request='{"agent":"pangea","method":"start","tablehash":"18e9e7448a68a4d46bfde55be0e667c4f4ba015e2c183fbc7cbc0c26996f7656"}';
    SPNAPI.makeRequest(request, function(request,response){
            
    });
};