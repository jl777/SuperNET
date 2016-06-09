var SPNAPI = (function(SPNAPI, $, undefined) {

    SPNAPI.methods = {};
    SPNAPI.pages = ["Settings", "eyedea", "iguana","Debug","Wallet"];
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
            $(".hljs").html("JSON response");
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

    SPNAPI.submitRequest = function(e) {

//code added in order to be able to receive input from <input> or <textarea> fields
//original code: var request = $(".json_submit_url").html();
//CODE CHANGED START
        // val() will not work with multiple textareas with same class
        // when there will be one tab for talking with api - this if-else can be deleted
        if ($("#json_submit_url").val()) {
                var request = $("#json_submit_url").val();
        }
        else if ($(".json_src").val()) {
        	var request = $(".json_src").val();
        }
       
//CODE CHANGED STOP
        // add new item in history table
        historyTable.addItem(request);

        postCall('iguana', request, function(jsonstr)
        {
            $(".debuglogdebuglog").append(jsonstr);
            common.logMessage(jsonstr + '\n');

            $(".hljs").html(jsonstr);

        });
    };

    return SPNAPI;
}(SPNAPI || {}, jQuery));
