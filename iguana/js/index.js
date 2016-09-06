$(document).ready(function() {
    var val;
    var val1;
    $("#currancy2").on('change', function() {
        var option1 = $("#currancy1 option:selected").text();
        var option2 = $("#currancy2 option:selected").text();
        if (option1 == option2) {
            alert("Please slect diffrent Currancy");
        }
    });

    $("#currancy1").on('change', function() {
        var option1 = $("#currancy1 option:selected").text();
        var option2 = $("#currancy2 option:selected").text();

        if (option1 == option2) {

            alert("Please slect diffrent Currancy");
        } else {
            $("#one_coin1_value").each(function() {
            });
        }
    });

    $("#one_coin1_value").keyup(function() {
        calculateSum();
    });
});

function calculateSum() {
    var texboxval = parseFloat($("#one_coin1_value").val())
    var value = parseFloat($("#currancy1").val());
    var value1 = parseFloat($("#currancy2").val());

    var sum = texboxval + value;
    var result = (sum) / (value1);

    $("#one_coin2_value").val(result);
    //$("#one_coin2_value").text(result);
    //.toFixed() method will roundoff the final sum to 2 decimal places
    //$("#one_coin2_value").html(sum.toFixed(2)); 
}