var historyTable = (function(historyTable, $, undefined) {

    var items = [];
    historyTable.addItem = function(json) {
        //method for adding new line to table
        if (json == undefined) {
            console.log('json is empty');
            return;
        }
        var newTab = "<tr class='row history-row'><td class='col-md-10 json-container'>" + json + "</td><td class='col-md-2'><button class='btn btn-default btn-resubmit'>Re-submit</button></td></tr>";
        if ( items.length == 0 ) {
            //adding first item
            items.push(json);
            $('#submit_history tbody').append(newTab);
            localStorage['submit_history'] = JSON.stringify(items);
        } else {
            //check for duplicates
            var jsonExist = false;
            for ( i=0; i<items.length; i++ ) {
                if ( json == items[i] ) {
                    jsonExist = true;
                }
            }
            if ( jsonExist == false ) {
                items.push(json);
                $('#submit_history tbody').append(newTab);
                localStorage['submit_history'] = JSON.stringify(items);
            } else {
                console.log('this json already exist');
            }
            
        }
    };



    $(document).ready(function() {
        // loading previously submitted jsons from local storage
        if ( localStorage['submit_history'] ) {
            var submit_history = JSON.parse(localStorage['submit_history']);
            for ( i=0; i < submit_history.length; i++ ) {
                historyTable.addItem(submit_history[i]);
            }
        }

        // handling clear history button
        $('#clearHistory').click(function() {
            $('#submit_history tbody').empty();
            items = [];
            localStorage.removeItem('submit_history');
        });
        
        // bind handler to resubmit buttons
        $('#submit_history').on('click', '.btn-resubmit', function(evt) {
            var request = $(evt.target.parentElement.parentElement).find('.json-container').text();
            $('#json_src').val(request);
            SPNAPI.submitRequest();
        });
    });

    

    return historyTable;
}(historyTable || {}, jQuery));
