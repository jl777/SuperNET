// placeholder of API peers response

var peer_resonse=[];//=[responseBTCD,responseBTC];

var currentCoin=0;
/*
 * Gets peer list using postCall or using AJAX GET request
 * (further code will need modifications when native call will be implemented)
 * (Above initialized usepostCall variable must be set to true if postCall is to be used)
 * 
 */
function getPeerList(){
    var coin_types = coinManagement.getCoinSymbols();
    if(currentCoin<coin_types.length){
     var tag = tagGen(18);
        console.log("Inside getPeerList");
        var request=
                '{"agent":"iguana","method":"peers","coin":'+'"'+coin_types[currentCoin]+'","tag":"' + tag.toString() + '"}';
currentCoin++;
//console.log('Requesting: ' + request);
SPNAPI.makeRequest(request,addpeer_toresponse);
//SPNAPI.makeRequest(request,getPeerList());
    }else{
    currentCoin=0;
    renderPeersGrid();
    }
}


function addpeer_toresponse(request, response){
    
    var data=JSON.parse(response);
       if(data.error && data.error==="peers needs coin"){
           console.log("Coin not present");
           
       }else{
           peer_resonse.push(data);
       }
       getPeerList();
}
/**
 * 
 * @param {sting} ip (ip address current of peer)
 * @param {string} coin (coin short name)
 * @returns {undefined}
 * 
 */

function connectPeer(ip,coin,id){
    
    var request='{"agent":"iguana","method":"addnode","ipaddr":'+'"'+ip+'","coin":"' + coin + '"}';
    console.log("connection to peer:"+ip+" coin:"+coin);
    SPNAPI.makeRequest(request,function(request,response){
            //console.log('Response is ' + response);
            var res=JSON.parse(response);
            if(res.result==="addnode submitted"){
                update_connected(coin,ip,id,true);
        }
        });
}

/**
 * 
 * @param {sting} ip (ip address current of peer)
 * @param {string} coin (coin short name)
 * @returns {undefined}
 * 
 */
function disconnectPeer(ip,coin,id){
    
    var request='{"agent":"iguana","method":"removenode","ipaddr":'+'"'+ip+'","coin":"' + coin + '"}';
    console.log("disconnection to peer:"+ip+" coin:"+coin);
    SPNAPI.makeRequest(request, function(request,response){
            //console.log('Response is ' + response);
//            removePeerFromConn(ip,coin);
            update_connected(coin,ip,id,false);
        });


}


var favPeers = [];
/**
 * 
 * @type Array
 * (used to store connected peer in a string format)
 */

var connectedPeers=[];
var getHtmlRow = function (peer,id) {
//    /var peer={"ipaddr":peers[ip],"coin":coin_symbol,"connected":false,"favourite":false,"nodestatus":{"ipaddr":peers[ip],"protover":0,"relay":0,"height":0,"rank":0,"usock":0,"ready":0,"recvblocks":0,"recvtotal":0,"lastcontact":0,"msgcounts":{"version":0,"verack":0,"getaddr":0,"addr":0,"inv":0,"getdata":0,"notfound":0,"getblocks":0,"getheaders":0,"headers":0,"tx":0,"block":0,"mempool":0,"ping":0,"pong":0,"reject":0,"filterload":0,"filteradd":0,"filterclear":0,"merkleblock":0,"alert":0}}};
        
    var row = '';
    var data=peer.ipaddr+peer.coin;
    row = '<tr data-id="' + data.toString() + '">';
    row += '<td>' + peer.ipaddr + '</td>';
    row += '<td>' + peer.coin + '</td>';
    row += '<td>' + peer.nodestatus.height + '</td>';
    row += '<td>' + peer.nodestatus.rank + '</td>';
    row += '<td>' + peer.nodestatus.msgcounts.block + '</td>';
    
    if (!peer.favourite) {
        row += '<td><button class="btn btn-xs btn-success btn-raised addPeerToFav" data-ip="'+peer.ipaddr.toString()+'" data-coin="'+peer.coin.toString()+'" data-id="' + id.toString() + '"> + Favorite</button></td>';
        // row += '<td><i class="material-icons addPeerToFav" data-id="' + id.toString() + '">bookmark_border</i></td>';
    }
    else {
        row += '<td><button class="btn btn-xs btn-danger btn-raised removePeerFromFav" data-ip="'+peer.ipaddr.toString()+'" data-coin="'+peer.coin.toString()+'" data-id="' + id.toString() + '"> - Unfavorite</button></td>';
        // row += '<td><i class="material-icons removePeerFromFav" data-id="' + id.toString() + '">bookmark</i></td>'
     }
    
    if (!peer.connected) {
        row += '<td><button class="btn btn-xs btn-success btn-raised connectPeer" data-ip="'+peer.ipaddr.toString()+'" data-coin="'+peer.coin.toString()+'" data-id="' + id.toString() + '"> + Connect</button>';
        row +='</td>'; 
        
    }else{
        row += '<td><button class="btn btn-xs btn-danger btn-raised disconnectPeer" data-ip="'+peer.ipaddr.toString()+'" data-coin="'+peer.coin.toString()+'" data-id="' + id.toString() + '"> -Disconnect</button>';
        row +='</td>'; 
    }
    row += '</tr>';
    return row;
};


var addPeerToConn = function (ip,coin) {
    if ($.inArray(ip+" "+coin, connectedPeers) === -1) {
        connectedPeers.push(ip+" "+coin);
        console.log('@ peer connected', connectedPeers);
    }

    // refresh grid e.getAttribute('data-id'),e.getAttribute('data-coin')
    renderPeersGrid(document.getElementById('cbShowFavoritePeers').checked);
};

var removePeerFromConn = function (ip,coin) {
    for (var index = 0; index < connectedPeers.length; index++) {
        if (ip+" "+coin === connectedPeers[index]) {
            connectedPeers.splice(index, 1);
            console.log('@ peer disconnected', connectedPeers);
            break;
        }
    }

    // refresh grid
    renderPeersGrid(document.getElementById('cbShowFavoritePeers').checked);
};



var addPeerToFav = function (id,coin) {
    if ($.inArray(id+coin, favPeers) === -1) {
        favPeers.push(id+coin);
        console.log('@ peer faved', favPeers);
    }

    // refresh grid e.getAttribute('data-id'),e.getAttribute('data-coin')
    renderPeersGrid(false);
};

var removePeerFromFav = function (id,coin) {
    for (var index = 0; index < favPeers.length; index++) {
        if (id+coin === favPeers[index]) {
            favPeers.splice(index, 1);
            console.log('@ peer unfaved', favPeers);
            break;
        }
    }

    // refresh grid
    renderPeersGrid(document.getElementById('cbShowFavoritePeers').checked);
};
/*
var renderPeersGrid = function (favoritesOnly = false) {

    console.log('@ peer print grid');
 
    var peersTableAllHtml = '';

    for (var i = 0; i < response.peers.length; i++) {

        if (favoritesOnly == true && $.inArray(i, favPeers) == -1) {
            continue;
        }

        response.peers[i].cointype = response.coin
        peersTableAllHtml += getHtmlRow(i, response.peers[i]);
    }
    document.getElementById('peersTableBody').innerHTML = peersTableAllHtml;
};*/
var favoritesOnly=false;

var renderPeersGrid = function () {

    console.log('@ peer print grid');
 
    var peersTableAllHtml = '';
    for(var j=0; j<peers_pool.peers.length;j++){
      var res=peers_pool.peers[j];
       // for (var i = 0; i < res.peers.length; i++) {
        if (favoritesOnly === true && !res.favourite) {
            continue;
        }
        //console.log(data.toString());
        peersTableAllHtml += getHtmlRow(res,j);
    //}
        
    }
    
    document.getElementById('peersTableBody').innerHTML = peersTableAllHtml;
   
};


document.getElementById('cbShowFavoritePeers').onclick = function () {
   
favoritesOnly=document.getElementById('cbShowFavoritePeers').checked;
    renderPeersGrid();
};

var startPeerManagement = function () {
    renderPeersGrid();

};


var peers_pool={"connected":0,peers:[],"saved":false,"maxpeer":SPNAPI.settings.maxpeers};

var addpeers_from_conf= function(peer_file_as_text, coin_symbol){
    var peers=peer_file_as_text.split("\n");
    var showConnected=true;
    var total_peers=0;
    for(var ip in peers){
        if(total_peers<SPNAPI.settings.maxpeers){
           if(peers[ip]!=="" && peers[ip]!=="\n"){
            console.log(peers[ip]);
        var peer={"ipaddr":peers[ip],"coin":coin_symbol,"connected":false,"favourite":false,"nodestatus":{"ipaddr":peers[ip],"protover":0,"relay":0,"height":0,"rank":0,"usock":0,"ready":0,"recvblocks":0,"recvtotal":0,"lastcontact":0,"msgcounts":{"version":0,"verack":0,"getaddr":0,"addr":0,"inv":0,"getdata":0,"notfound":0,"getblocks":0,"getheaders":0,"headers":0,"tx":0,"block":0,"mempool":0,"ping":0,"pong":0,"reject":0,"filterload":0,"filteradd":0,"filterclear":0,"merkleblock":0,"alert":0}}};
        peers_pool.peers.push(peer);
        if(total_peers<SPNAPI.settings.maxpeers){
            connectPeer_from_conf(peers[ip],coin_symbol);
        }
        total_peers=total_peers+1;
    }    
        }
     
}
peers_pool.maxpeer=SPNAPI.settings.maxpeers;
console.log("total "+total_peers+" peers added in file supporting "+coin_symbol);

};

var sync_peers_to_maxpeers=function(){
    //disconnect_all_peers();
        peers_pool.peers=[];
        load_peers_from_conf();
    
};

var disconnect_all_peers=function(){
  for(var peers in peers_pool.peers){
      if(peers_pool.peers[peers].connected){
       disconnectPeer(peers_pool.peers[peers].ipaddr,peers_pool.peers[peers].coin,0);   
      }
    }
    
};
var check_peer_present=function(ip,coin){
    for(var peers in peers_pool.peers){
        if(peers_pool.peers[peers].ipaddr ===ip && peers_pool.peers[peers].coin===coin){
           return true; 
        }
    }
    return false;
};
var update_connected=function(coin,ip,id,value){
    
    if(peers_pool.peers[id] && peers_pool.peers[id].ipaddr ===ip && peers_pool.peers[id].coin===coin){
        peers_pool.peers[id].connected=value; 
    }else{
    for(var peers in peers_pool.peers){
        if(peers_pool.peers[peers].ipaddr ===ip && peers_pool.peers[peers].coin===coin){
           peers_pool.peers[peers].connected=value; 
        }
    }    
    }
    renderPeersGrid();
};

var update_favourite=function(coin,ip,id,value){
    console.log("@update_favourite got values coin:"+coin+" ip:"+ip+" id:"+id+" value:"+value);
    
    if(peers_pool.peers[id] && peers_pool.peers[id].ipaddr ===ip && peers_pool.peers[id].coin===coin){
       peers_pool.peers[id].favourite=value;
    }else{
    for(var peers in peers_pool.peers){
        if(peers_pool.peers[peers].ipaddr ===ip && peers_pool.peers[peers].coin===coin){
           peers_pool.peers[peers].favourite=value; 
        }
    }    
    }
    renderPeersGrid();
    
};

var update_allpeer_status=function(){
    for(var peers in peers_pool.peers){
        if(peers_pool.peers[peers].connected=== true){
            var request='{"agent":"iguana","method":"nodestatus","ipaddr":'+'"'+peers_pool.peers[peers].ipaddr+'","coin":"' + peers_pool.peers[peers].coin + '"}';
           SPNAPI.makeRequest(request,function(request,response){
               
            //console.log('Response is ' + response);
           // console.log('Request was ' + JSON.parse(request));
            
               var res=JSON.parse(response);
               if(res.result!=="nodestatus couldnt find ipaddr"){
                               peers_pool.peers[peers].nodestatus=res;
            renderPeersGrid();
               }else{
                   console.log("opps! peer isnt there.");
               }

        });
        }
    }
    
};

var save_peersdata_to_conf=function(){
    peers_pool.saved=true;
    save_contents(JSON.stringify(peers_pool),"confs/peer_tab.save");
    
};

var deletePeertabFile_onclick=function(){
    //disconnect_all_peers();
    delete_file("confs/peer_tab.save");
    peers_pool.peers=[];
    renderPeersGrid();
    
};

var load_peers_to_pool=function(){
    //if()
    {
     fileSystem.root.getFile("confs/peer_tab.save", {}, function(fileEntry) {
                 //console.log("entered file fu");
    // Get a File object representing the file,
    // then use FileReader to read its contents.
    fileEntry.file(function(file) {
       var reader = new FileReader();

       reader.onloadend = function(e) {
         var peer=this.result;
         console.log("reading peerconf file "+this.result);
           peers_pool=JSON.parse(peer);
           SPNAPI.settings.maxpeers=peers_pool.maxpeer;
           resume_connected_peers();
           renderPeersGrid();
         };

       reader.readAsText(file);
    },  function(e){
        errorHandler(e);
   
});

  },  function(e){
        errorHandler(e);
   
});   
    }
    
    
};
var First_run_peer=true;
var resume_connected_peers=function(){
    console.log("resuming peers!");
   for(var peers in peers_pool.peers){
        if(peers_pool.peers[peers].connected){
          connectPeer_from_conf(peers_pool.peers[peers].ipaddr,peers_pool.peers[peers].coin);
        }
    }
    
    First_run_peer=false;
};

function connectPeer_from_conf(ip,coin){
    
    var request='{"agent":"iguana","method":"addnode","ipaddr":'+'"'+ip+'","coin":"' + coin + '"}';
    console.log("connecting to peer:"+ip+" coin:"+coin);
    SPNAPI.makeRequest(request,function(request,response){
            //console.log('Response is ' + response);
            var res=JSON.parse(response);
            if(res.result==="addnode submitted"){
                console.log('connected to peer ' + ip+" supporting "+coin);
                update_connected(coin,ip,0,true);
                renderPeersGrid();
        }else{
             update_connected(coin,ip,0,false);
             renderPeersGrid();
        }
        });
        
}

var load_peers_from_conf=function(){
    var coins= coinManagement.getCoinSymbols();
               var files=["_peers.txt"];
        for(var i=0;i<coins.length;i++){
         
            for(var j=0;j<files.length;j++){
                var name="confs/"+coins[i]+files[j];
                load_peer_file(name,coins[i]);   
            }
        }  
    
};

var load_peer_file=function(name,coin){
    
    fileSystem.root.getFile(name, {}, function(fileEntry) {

    // Get a File object representing the file,
    // then use FileReader to read its contents.
    fileEntry.file(function(file) {
       var reader = new FileReader();

       reader.onloadend = function(e) {
          addpeers_from_conf(this.result,coin);
         };

       reader.readAsText(file);
    }, errorHandler);

  }, errorHandler);
};

$(document).ready(function () {
//            $("#tab").tablesorter();
             //$("#peersTable").tablesorter();
             $('#peersTable').tablesort();
        });

$('table').on('tablesort:start', function(event, tablesort) {
    console.log("Starting the sort...");
});

$('table').on('tablesort:complete', function(event, tablesort) {
    console.log("Sort finished!");
});