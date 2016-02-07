var SPNAPI = (function(SPNAPI, $,errorHandler,undefined) {

    SPNAPI.settings = {maxpeers:3};
    SPNAPI.conf_files={};
    
    SPNAPI.getCheckBoxDetails = function(agent) {

        var extraInfo = '';

        switch (agent) {

            case 'InstantDEX':
                extraInfo = 'Extra Info on this '+agent+' Agent';
                break;
            case 'pangea':
                extraInfo = 'Extra Info on this '+agent+' Agent';
                break;
            case 'Jumblr':
                extraInfo = 'Extra Info on this '+agent+' Agent';
                break;
            case 'MGW':
                extraInfo = 'Extra Info on this '+agent+' Agent';
                break;
            case 'Atomic':
                extraInfo = 'Extra Info on this '+agent+' Agent';
                break;
            case 'PAX':
                extraInfo = 'Extra Info on this '+agent+' Agent';
                break;
            case 'Tradebots':
                extraInfo = 'Extra Info on this '+agent+' Agent';
                break;
              case 'Wallet':
              extraInfo = 'Extra Info on this '+agent+' Agent';
              break;
              case 'Jay':
              extraInfo = 'Extra Info on this '+agent+' Agent';
              break;

        }

        return extraInfo;


    };

    SPNAPI.pageContent.Settings = function () {

        var filehandle_map = {};
        var dirhandle_map = {};
/*
        var rows = '<h3>Agents</h3>';

        $.each(SPNAPI.methods, function (index, value) {

            var this_state;

            $.each(SPNAPI.settings, function (settings_index, settings_value) {

                $.each(settings_value, function (this_setting_index, this_setting_value) {

                    if(this_setting_value.agent == index) {
                        this_state = this_setting_value.state;
                    }

                })

            });

            var checkbox_text = "";
            var checkbox_checked = "";
            var extraDetails = SPNAPI.getCheckBoxDetails(index);
            if(this_state == 'inactive') { checkbox_text = '<i>Disabled</i>'; checkbox_checked = ''; extraDetails = "";  }
            else {
                checkbox_text = 'Enabled'; checkbox_checked = 'checked="checked"';

            }


            rows += '' +
            '<div class="panel panel-default">'+
            '<div class="panel-body">'+
            '<div class="col-xs-6 col-md-6 col-lg-6">'+index+'</div>'+
            '<div class="col-xs-6 col-md-6 col-lg-6" style="text-align: right;">' +
            '<div class="checkbox">'+
            '<label>'+
            '<input type="checkbox" id="'+index+'_checkbox" '+checkbox_checked+' class="agent_checkbox" value="'+index+'" aria-label="Activate/Deactivate Agent"> <span class="checkbox_'+index+'_text">'+checkbox_text+'</span>'+
            '</label>'+
            '</div>' +
            '</div>' +
            '<div class="row"><div class="'+index+'_extra_info col-xs-10 col-md-10 col-lg-10">'+extraDetails+'</div></div>'+
            '</div>'+
            '</div>';

        });


        var filename = "/persistent/SuperNET.conf";
        var access = "w+";
        postCall('fopen', filename, access, function(filename_return, filehandle) {
            filehandle_map[filehandle] = filename_return;
            common.logMessage('File ' + filename_return + ' opened successfully.');

            console.log(filehandle + " and "+filename_return);
        });
        

         var data = "SuperNETconfigurationsdaaaaa TES TEST TEST TEST";
         postCall('fwrite', 0, data, function(filehandle, bytesWritten) {
         var filename = filehandle_map[filehandle];
         common.logMessage('Wrote ' + bytesWritten + ' bytes to file ' + filename +
         '.');
         });


         var filesize = "";
         postCall('stat', filename, function(filename, size) {
         common.logMessage('File ' + filename + ' has size ' + size + '.');
         filesize = size;

         });


         var filehandle = parseInt(filehandle_map, 10);
         var numBytes = parseInt(filesize, 10);
         postCall('fread', 0, 0, function(filehandle, data) {
         var filename = filehandle_map[filehandle];
         common.logMessage('Read "' + data + '" from file ' + filename + '.');
         });
         

        $("#agent_settings").html(rows);
*/
        var config = '<h3>Config</h3>';
        var checkbox_text="";
        var checkbox_checked="";
        
        if(SPNAPI.usePexe === false) { checkbox_text = '<i>Disabled</i>'; checkbox_checked = ''; extraDetails = "";  }
            else {
                checkbox_text = 'Enabled'; checkbox_checked = 'checked="checked"';

            }
        
        config += '' +
            '<div class="panel panel-default">'+
            '<div class="panel-body">'+
            '<div class="col-xs-6 col-md-6 col-lg-6">Pexe</div>'+
            '<div class="col-xs-6 col-md-6 col-lg-6" style="text-align: right;">' +
            '<div class="checkbox">'+
            '<label>'+
            '<input type="checkbox" id="use_pexe_checkbox" class="pexe_checkbox" value="'+checkbox_checked+'" aria-label="Activate/Deactivate Agent"> <span class="pexe_checkbox_text">'+checkbox_text+'</span>'+
            '</label>'+
            '</div>' +
            '</div>' +
            '<div class="row"><div class="pexe_extra_info col-xs-10 col-md-10 col-lg-10">Use pexe or URL requests for communications</div></div>'+
            '</div>'+
            '</div>';
        config += '' +
            '<div class="panel panel-default">'+
            '<div class="panel-body">'+
            '<div class="col-xs-6 col-md-6 col-lg-6">Save default conf files</div>'+
            '<div class="col-xs-6 col-md-6 col-lg-6" style="text-align: right;">' +
            '<div class="checkbox">'+
            '<label>'+
            '<span><button class="btn btn-xs btn-success btn-raised saveConfFiles_onclick"  > Save</button></span>'+
            '</label>'+
            '</div>' +
            '</div>' +
            '<div class="row"><div class="pexe_extra_info col-xs-10 col-md-10 col-lg-10">Save configuration files to chrome APP</div></div>'+
            '</div>'+
            '</div>';
    config += '' +
            '<div class="panel panel-default">'+
            '<div class="panel-body">'+
            '<div class="col-xs-6 col-md-6 col-lg-6">Maximum peers</div>'+
            '<div class="col-xs-6 col-md-6 col-lg-6" style="text-align: right;">' +
            '<div class="checkbox">'+
            '<label>'+
            '<input type="text" id="max_peers_setting" size="4" value="'+SPNAPI.settings.maxpeers+'"/>'+
            '</label>'+
            '</div>' +
            '</div>' +
            '<div class="row"><div class="pexe_extra_info col-xs-10 col-md-10 col-lg-10">Set number of nodes connected directly per coin type</div></div>'+
            '</div>'+
            '</div>';
    
    
        $("#advanced_settings").html(config);

        

        var pexe_checkbox = $('.pexe_checkbox');

        pexe_checkbox.on("click", function () {
            if(typeof nacl_module !== 'undefined'){
              
                var thisCheck = $(this);
            if (thisCheck.is (':checked'))
            {
                $('.pexe_checkbox_text').html("Enabled");
                SPNAPI.usePexe=true;
                } else {
                SPNAPI.usePexe=false;
                $('.pexe_checkbox_text').html("<i>Disabled</i>");
            }
            }else{
                console.log("Pexe not loaded!");
            }
});

        $("#save_settings").on("click", function () {
            
            //saving max peer setting
            var peers=$('#max_peers_setting').val();
            if(SPNAPI.settings.maxpeers!==peers){
                SPNAPI.settings.maxpeers=peers;
                console.log("maxpeers set to "+SPNAPI.settings.maxpeers);
            }

            /*var agent_checkbox = $('.agent_checkbox');
            var settings = [];

            $.each(agent_checkbox, function(index, value) {

                var agent = value.value;
                console.log(agent);
                var thisCheck = $("#"+agent+"_checkbox");
                var state;
                if (thisCheck.is (':checked'))
                {
                    state = "active";

                } else {
                    state = 'inactive';
                }

                var json = { "agent" : "InstantDEX", "state" : "inactive" };
                json.agent = agent;
                json.state = state;
                settings.push(json);


            });

            //console.log(settings);

            var filename = "/persistent/SuperNET.conf";
            var access = "w";
            postCall('fopen', filename, access, function(filename_return, filehandle) {
                filehandle_map[filehandle] = filename_return;
                common.logMessage('File ' + filename_return + ' opened successfully.');

            });


            //var settings = { "agent" : "InstantDEX", "state" : "active" };
            chrome.storage.sync.set({ "settings" : settings }, function() {
                if (chrome.runtime.error) {
                    console.log("Runtime error.");
                }
            });

            chrome.storage.sync.get("settings", function(items) {
                if (!chrome.runtime.error) {
                    //console.log(items);
                    //document.getElementById("data").innerText = items.data;
                    SPNAPI.settings = items;
                }
            });*/

        });

    };

    return SPNAPI;
}(SPNAPI || {}, jQuery,errorHandler));


