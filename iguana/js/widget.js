var widgetsManagement={};

// Functions

widgetsManagement.createWidgets = function() {
	var widgets = document.getElementsByClassName("iguana-widget");

	for(var key in widgets) {
		var iframeEL = document.createElement("iframe");
		var widget = widgets[key];
		widget.innerHTML="";
		widget.appendChild(iframeEL);
		iframeEL.src="//127.0.0.1:7778/js/widgets?id="+widget.getAttribute("data-ref");
		iframeEL.style.width="100%";
		iframeEL.style.height="100%";
		iframeEL.style.border="0";
	}
};


// Event Handlers

window.addEventListener('load', widgetsManagement.createWidgets);
