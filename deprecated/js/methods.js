var SPNAPI = (function(SPNAPI, $, undefined) {

              SPNAPI.methods.iguana = [
                                       {"id":1,"method":"wallet","base":"base","maxplayers":"maxplayers","bigblind":"bigblind","ante":"ante"},
                                       {"id":2,"method":"status","tableid":"tableid"}
                                       ];
              
              SPNAPI.methods.Wallet = [
                                       {"id":1,"method":"wallet","base":"base","maxplayers":"maxplayers","bigblind":"bigblind","ante":"ante"},
                                       {"id":2,"method":"status","tableid":"tableid"}
                                       ];
              

    SPNAPI.loadApiBox = function (agent,methods) {

        methods = methods[0];
        $(".api-panel-title").html(methods.method);

        var json = { "agent" : agent, "method" : methods.method };

        var rows = '';
        rows += '<input type="hidden" name="agent" value="'+agent+'">';
        rows += '<input type="hidden" name="method" value="'+methods.method+'">';
        rows += '<table class="table">' +
        '<thead>' +
        '<tr><th>Agent</th><th>'+agent+'</th></tr>' +
        '<tr><td>Method</th><td>'+methods.method+'</td></tr>';



        $.each(methods, function (index, value) {

            if(index !== "id") {
                if( index !== "method") {

                    var required = '';
                    if(value > '') {

                        required = 'has-success';

                    }

                    rows += '<tr><td>' + index + '</td><td><div class="form-group '+required+'"><input type="text" class="api_control form-control" class="form-control" name="' + index + '" style="width:100%;min-width:200px;"></div></td></tr>';
                    json[index] = value;
                }
            }

        });


        rows += '</table><hr>';

        json = JSON.stringify(json);
        $(".json_submit_url").html(json);

        $(".api_formfill").html(rows);


    };

    return SPNAPI;
}(SPNAPI || {}, jQuery));