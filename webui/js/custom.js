$(document).ready(function(e) { 	 
  var json_Obj =currency_arr;            
  var outPut="";
  var defaultActive="";
  
    for (var i in json_Obj) 
    { 
	defaultActive="";
	if(json_Obj[i].selected==1)
			defaultActive=" selected";
			
	  outPut+="<li class='country-li "+defaultActive+"' data-id='"
	    +json_Obj[i].id 
        +"'><h1 class='flag-head'><span class='label label-default'><span class='flag-icon flag-icon-"
	    +json_Obj[i].flagid+"'></span></span></h1><strong class='short-name'>" 
	    + json_Obj[i].shortName + "</strong><span class='full-name'> "
	    +json_Obj[i].fullName+"</span></li>"; 
	}
  $('.currency-loop').html(outPut);			
  $('.country-li').on("click",function(){	
    console.clear()
    $('.country-li').removeClass("selected");
    $(this).addClass("selected");			
    var id=$(this).attr("data-id");
    console.log(currency_arr[id-1]); });
});