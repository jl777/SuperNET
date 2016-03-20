$('#pic-changer').change(function(){ //if the select value gets changed on BitMap Page
   var imageSource = $(this).find(':selected').data('picture'); //get the data from data-picture attribute
   if(imageSource){ //if it has data
      $('#image-location').html('<img src="'+imageSource+'" name="bitmapImg" id="bitmapImg" style="width:100%;display: block; margin-left: auto;margin-right: auto;">'); // insert image in div image-location
   } else {
      $('#image-location').html(''); //remove content from div image-location, thus removing the image
      $('#bit_mousexy').html('');
   }
})
 

$(window).bind('resize',function(){
	var imgId = document.getElementById('bitmapImg');
	if(imgId != null || imgId != undefined){
	  var imagename=imgId.name;
	  var img = $('#bitmapImg');
	  var relX = img.width();
	  var relY = img.height();
	  console.log(relY);
	  console.log(relX);
	  
	  console.log(imagename);
	    $.ajax({
	       type: "GET",
	       url: "http://127.0.0.1:7778/api/mouse/image/name/"+imagename+"/x/"+Math.round(relX)+"/y/"+Math.round(relY),
	       success: function( response ) {
	            console.log('AJAX Response is ' + response);
	                 //if(typeof callback === 'function'){
	                 //callback(request, response);
	                 //}
	                 }
	 });
	}
 });



var prevXY={"X":0,"Y":0};
var prevID=0;
$(document).ready(function() {
$('#Bitmap_page').on("click","img",function(e){
	
      e = window.event ? event.srcElement : e.target;
      var imagename=e.getAttribute('name');
      console.log("Clicked on image"+ imagename);
      
  $.ajax({
    type: "GET",
    url: "http://127.0.0.1:7778/api/mouse/click/name/"+imagename+"/x/"+Math.round(prevXY.X)+"/y/"+Math.round(prevXY.Y),
    success: function( response ) {
         console.log('AJAX Response is ' + response);
              //if(typeof callback === 'function'){
              //callback(request, response);
              //}
              }
    });
  });

});



$('#Bitmap_page').on("mousemove","img",function(e){
     
      var imagename=document.getElementById('bitmapImg').name;
      
      var parentOffset = $("#bitmapImg").offset();
      var relX=e.pageX-parentOffset.left;
      var relY=e.pageY-parentOffset.top;
      prevXY.X=relX;
      prevXY.Y=relY;
      
      
      $.ajax({
      type: "GET",
      url: "http://127.0.0.1:7778/api/mouse/image/name/"+imagename+"/x/"+Math.round(relX)+"/y/"+Math.round(relY),
      success: function( response ) {
           console.log('AJAX Response is ' + response);
                //if(typeof callback === 'function'){
                //callback(request, response);
                //}
                }
      });
   
   var a = document.getElementById('bit_mousexy');
   a.innerHTML="parent offset x:"+relX+" y:"+relY;
  
   console.log("Moved mouse on image imagename "+imagename);
   console.log("calling API");
   // {"agent":"mouse","method":"image","name":"bitmap.jpg","x":<width>,"y":<height>}              
	$.ajax({
	  type: "GET",
	  url: "http://127.0.0.1:7778/api/mouse/change/name/"+imagename+"/x/"+Math.round(relX)+"/y/"+Math.round(relY),
	  success: function( response ) {
	       console.log('AJAX Response is ' + response);
	            //if(typeof callback === 'function'){
	            //callback(request, response);
	            //}
	            }
	  });

 });
