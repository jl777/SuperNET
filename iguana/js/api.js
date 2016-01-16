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
    SPNAPI.pages = ["Settings", "eyedea", "Peers","Debug", "Coins", "Blockexplorer"];
    SPNAPI.pageContent = {};
    SPNAPI.page = "welcome";
    $(document).ready(function() {

        //load Pages into the navbar
        $.each(SPNAPI.pages, function( index, value ) {
            $("#welcome").after('<li class="navigation" data-page="'+value+'"><a href="#">'+value+'</a></li>');
        });

        $(".navigation").on("click", function () {

            var page = $(this).data("page");
            $(".navigation").removeClass("active");
            SPNAPI.loadSite(page);
        });
        $(".page").hide();
        $("#welcome_page").show();
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
        if ( request.tag == undefined ) {
            request = JSON.stringify( request );
            var tag = tagGen(18);
            request = request.substr(0, request.length - 1);
            request = request + ',"tag":"' + tag.toString() + '"}';
        } else {
            request = JSON.stringify( request );
        }
        console.log('Requesting: ' + request);
        postCall('iguana', request, function(response){
            console.log('Response is ' + response);
            callback(request, response);
        }); 
        
    }
    return SPNAPI;
}(SPNAPI || {}, jQuery));
