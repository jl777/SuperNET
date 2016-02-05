/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

var prevXY={"X":0,"Y":0};
var prevID=0;

$(document).ready(function() {
 loadImages();
    
    
    $('.imagAPI').click(function(e){
      e = window.event ? event.srcElement : e.target;
      var id=e.getAttribute('data-id');
      var imagename=document.getElementById('name-imagAPI-'+id).value;
        console.log("Clicked on image"+id);
      
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


var loadImages=function(){
for(var i=1;i<=10;i++){
    
     var img = document.getElementById("src-imagAPI-"+i);  
             var canvas = document.createElement('canvas');
    canvas.width = img.naturalWidth;
    canvas.height = img.naturalHeight;
var context = canvas.getContext('2d');

//alert(img.src);
context.drawImage(img, 0, 0 );
var dataURL = {data:canvas.toDataURL('image/jpg'),height:img.height,width:img.width,type:'JPG'};
var name='imagedata-'+i;
/*if(typeof localStorage !== 'undefined'){
    localStorage[name]=JSON.stringify(dataURL);
}else{
        chrome.storage.local.set({name: JSON.stringify(dataURL)});
}*/
        Storage.save(name,JSON.stringify(dataURL));
$("#dest-imagAPI-"+i).attr('src', dataURL.data);
    
}
    
};

$('.imagAPI').mousemove(function(e){
     //e = window.event ? event.srcElement : e.target;
     

      var id=event.srcElement.getAttribute('data-id');
      
           var imagename=document.getElementById('name-imagAPI-'+id).value;
      
      var parentOffset = $("#dest-imagAPI-"+id).offset();
      var relX=e.pageX-parentOffset.left;
      var relY=e.pageY-parentOffset.top;
      prevXY.X=relX;
    prevXY.Y=relY;
      
      if(prevID!==id){
          prevID=id;
          
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
      document.getElementById('mousexy').innerHTML="parent offset x:"+relX+" y:"+relY;
      
    console.log("Moved mouse on image "+id+" imagename "+imagename);
    
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