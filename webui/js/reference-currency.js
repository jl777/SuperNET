var currencyArr = [ { "id": 1, "shortName": "USD", "fullName": "United States Dollar", "flagid": "us", "selected" :1 },
                    { "id": 2, "shortName": "EUR", "fullName": "Euro", "flagid": "eu", "selected": 0 }];


$(document).ready(function(e) {
  var outPut = "";
  var defaultActive = "";

  for (var i in currencyArr)
  {
	  defaultActive = "";

    if (currencyArr[i].selected == 1) {
      defaultActive = "selected";
    }

    outPut += "<li class=\"country-li " + defaultActive + "\" data-id=\"" + currencyArr[i].id + "\">" +
                "<h1 class=\"flag-head\">" +
                  "<span class=\"label label-default\">" +
                    "<span class=\"flag-icon flag-icon-" + currencyArr[i].flagid + "\"></span>" +
                  "</span>" +
                "</h1>" +
                "<strong class=\"short-name\">" + currencyArr[i].shortName + "</strong>" +
                "<span class=\"full-name\">" + currencyArr[i].fullName + "</span>" +
              "</li>";
  }
  $('.currency-loop').html(outPut);
  	$('.country-li').on("click",function(){
      var id = $(this).attr("data-id");

      $('.country-li').removeClass("selected");
    	$(this).addClass("selected");
	});
});