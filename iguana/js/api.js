// tag string generator
function tagGen(len)
{
    var text = "";
    var charset = "0123456789";
    for( var i=0; i < len; i++ )
        text += charset.charAt(Math.floor(Math.random() * charset.length));
    return text;
}

var SPNAPI = (function(SPNAPI, $, undefined) {

    SPNAPI.methods = {};
    SPNAPI.pages = ["Settings","Instandex", "Pangea", "Peers","Debug", "Coins", "Blockexplorer"];
    SPNAPI.pageContent = {};
    SPNAPI.page = "Blockexplorer";
    /*
     * added variables for flexibility
     */
    SPNAPI.usePexe=false;
    SPNAPI.domain="http://127.0.0.1";
    SPNAPI.port="7778";
    $(document).ready(function() {

        //load Pages into the navbar
        $.each(SPNAPI.pages, function( index, value ) {
            $("#welcome").after('<li class="navigation" data-page="'+value+'"><a href="#">'+value+'</a></li>');
        });

        $(".navigation").on("click", function () {

            var page = $(this).data("page");
            $(".navigation").removeClass("active");
            SPNAPI.loadSite(page);
            console.log(page);
            if(page==="Peers"){
                peer_resonse=[];
                getPeerList();
            }else if(page==="Debug"){
                
                filesystem_save();
            }else if(page==="Coins"){
                addInitCoins();
            }else if(page==="Instandex"){
                ListAllExchanges();
            }
            
        });
        $(".page").hide();
        $("#Blockexplorer_page").show();
        $(".submit_api_request").on("click", function () {
            SPNAPI.submitRequest();
        });

        $(".clear-response").on("click", function () {
            $(".hljs").html("JSON response");
        });
        
    });

    // this function handles form in "eyedea" tab
    // you can use it as example for writing your own
    SPNAPI.submitRequest = function(e) {
        if ($("#json_src").val()) {
            var request = $("#json_src").val();
        } else {
            console.log('request is empty');
            return;
        }
        SPNAPI.makeRequest(request, function(json_req, json_resp) {
            $(".result").text(json_resp);
            historyTable.addItem(json_req);
        });
    };
    // makeRequest is wrapper-function for performing postCall requests. 
    // argument is your json request, tag is generated and added autmatically
    // two options are passed to callback, request and response
    SPNAPI.makeRequest = function( request, callback ) {
        // check if tag is already included in request
        request = JSON.parse( request );
        if ( request.tag === undefined ) {
            request = JSON.stringify( request );
            var tag = tagGen(18);
            request = request.substr(0, request.length - 1);
            request = request + ',"tag":"' + tag.toString() + '"}';
        } else {
            request = JSON.stringify( request );
        }
        console.log('Requesting: ' + request);
        /*
         * typeof nacl_module !== 'undefined' will test if pexe is loaded or not
         */
        if(typeof nacl_module !== 'undefined' && SPNAPI.usePexe){
          postCall('iguana', request, function(response){
            console.log('pexe Response is ' + response);
            //if(typeof callback === 'function'){
                callback(request, response);
    
            //}
        });   
        }else{
            request = JSON.parse( request );
        var url=SPNAPI.returnAJAXgetURL(request);
            if(url!==false){
                
    /*
     * Ajax request will be sent if pexe is not loaded or 
     * if usepexe is set to false
     * (this adds the user the ability to handle how requests are sent)
     */                 
$.ajax({
  type: "GET",
  url: url
  }).done(function( response ) {
       console.log('AJAX Response is ' + response);
            //if(typeof callback === 'function'){
            callback(request, response);
            //}
            });    
            }
   }
    };
    
    SPNAPI.returnAJAXgetURL=function(request){
        
        var url=SPNAPI.domain+":"+SPNAPI.port+"/api/";
        if(request.method === undefined){
            console.log("Invalid request.");
            return false;
        }
        if(request.agent=== undefined){
            url=url+"iguana/";
        }else{
             url=url+request.agent+"/";
        }
        
        url=url+request.method+"/";
        
        for(var i in request){
            if(i==="agent" ||i==="method"){
                continue;
            }
            if(request[i] instanceof Array ){
                for(var x in request[i]){
                    url=url+i+"/"+request[i][x]+"/";
                }
                continue;
            }
            url=url+i+"/"+request[i]+"/";
        }
        console.log("Url generated from request:"+url);
        return url;
    };
    return SPNAPI;
}(SPNAPI || {}, jQuery));
