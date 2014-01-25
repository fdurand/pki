<html>
<head>
<STYLE type="text/css">
body {
	# margin:10px 10px 0px 10px;
	padding:0;
	margin: 0;
}


body,th,td,p,div,span,a,input,select,textarea,ul,ol,dl,h1,h2,h3,h4,h5,h6,li,big,small,blockquote{font-family:verdana,arial,helvetica,sans-serif}
body,th,td,p,div,span,a,ul,ol,dl,li,select,input,textarea,blockquote{font-size:11px}
body,th,td,p{color:#000}
code,kbd,tt,pre,code span,kbd span,tt span,pre span{color:#000}


h1 {font-size: 155%;  font-weight: normal; padding: 0px; margin: 0px; margin-bottom: 15px; font-family:"Trebuchet MS",verdana,arial,helvetica,sans-serif}
h2 {font-size: 130%;  font-weight: normal; padding-bottom: 10px}
h3 {font-size: 100%;}

img{border: 0px}
img {vertical-align:middle;}

a{text-decoration:none}
a:visited{color:#000}
a:link,a.named:visited {color:#000}
a {cursor: pointer;}
a:hover {text-decoration:underline}

hr {height:1px; color:#999999}

form{display:inline}
form,select,input,textarea,ul li{margin:0px;padding:0px}

input {
	border-bottom: solid 1px #cccccc;
	border-right: solid 1px #cccccc;
	margin: 5px;
	padding: 2px;
	-moz-border-radius: 5px;
}

td {

}

#root {
	position: relative;
	top: 15%;
}
 

#page, #custom {
	width: 500px;
	border-left: 1px solid black;
	border-right: 1px solid black;
}



.submit {
	padding-top: 10px;
	text-align: right;
}


#copyright {
   margin-top: 1em;
   padding-right: 1em;
   text-align: right;
   padding-top: 1em;
   color: #333333;
   border-top: 1px solid #ccc;
}

#licence {
   display: none;
   margin-right: 1em; text-align: right;
}

#header {
	border-top: 1px solid #bbbbbb;
}

#footer {
	margin: 0;
	margin-top: 5em;
        border-top: 1px solid #ccc; clear: both;margin-top: 1em;
	height: 3em; background: #eb171d;
}

#custom {
	height: 3em;
	background: #eb171d;
	background-repeat: no-repeat;
	border-bottom: 1px solid #777777;
}
</STYLE>
<script language="javascript">
var Drag = {

	obj : null,

	init : function(o, oRoot, minX, maxX, minY, maxY, bSwapHorzRef, bSwapVertRef, fXMapper, fYMapper)
	{
		o.onmousedown	= Drag.start;

		o.hmode			= bSwapHorzRef ? false : true ;
		o.vmode			= bSwapVertRef ? false : true ;

		o.root = oRoot && oRoot != null ? oRoot : o ;

		if (o.hmode  && isNaN(parseInt(o.root.style.left  ))) o.root.style.left   = "0px";
		if (o.vmode  && isNaN(parseInt(o.root.style.top   ))) o.root.style.top    = "0px";
		if (!o.hmode && isNaN(parseInt(o.root.style.right ))) o.root.style.right  = "0px";
		if (!o.vmode && isNaN(parseInt(o.root.style.bottom))) o.root.style.bottom = "0px";

		o.minX	= typeof minX != 'undefined' ? minX : null;
		o.minY	= typeof minY != 'undefined' ? minY : null;
		o.maxX	= typeof maxX != 'undefined' ? maxX : null;
		o.maxY	= typeof maxY != 'undefined' ? maxY : null;

		o.xMapper = fXMapper ? fXMapper : null;
		o.yMapper = fYMapper ? fYMapper : null;

		o.root.onDragStart	= new Function();
		o.root.onDragEnd	= new Function();
		o.root.onDrag		= new Function();
	},

	start : function(e)
	{
		var o = Drag.obj = this;
		e = Drag.fixE(e);
		var y = parseInt(o.vmode ? o.root.style.top  : o.root.style.bottom);
		var x = parseInt(o.hmode ? o.root.style.left : o.root.style.right );
		o.root.onDragStart(x, y);

		o.lastMouseX	= e.clientX;
		o.lastMouseY	= e.clientY;

		if (o.hmode) {
			if (o.minX != null)	o.minMouseX	= e.clientX - x + o.minX;
			if (o.maxX != null)	o.maxMouseX	= o.minMouseX + o.maxX - o.minX;
		} else {
			if (o.minX != null) o.maxMouseX = -o.minX + e.clientX + x;
			if (o.maxX != null) o.minMouseX = -o.maxX + e.clientX + x;
		}

		if (o.vmode) {
			if (o.minY != null)	o.minMouseY	= e.clientY - y + o.minY;
			if (o.maxY != null)	o.maxMouseY	= o.minMouseY + o.maxY - o.minY;
		} else {
			if (o.minY != null) o.maxMouseY = -o.minY + e.clientY + y;
			if (o.maxY != null) o.minMouseY = -o.maxY + e.clientY + y;
		}

		document.onmousemove	= Drag.drag;
		document.onmouseup		= Drag.end;

		return false;
	},

	drag : function(e)
	{
		e = Drag.fixE(e);
		var o = Drag.obj;

		var ey	= e.clientY;
		var ex	= e.clientX;
		var y = parseInt(o.vmode ? o.root.style.top  : o.root.style.bottom);
		var x = parseInt(o.hmode ? o.root.style.left : o.root.style.right );
		var nx, ny;

		if (o.minX != null) ex = o.hmode ? Math.max(ex, o.minMouseX) : Math.min(ex, o.maxMouseX);
		if (o.maxX != null) ex = o.hmode ? Math.min(ex, o.maxMouseX) : Math.max(ex, o.minMouseX);
		if (o.minY != null) ey = o.vmode ? Math.max(ey, o.minMouseY) : Math.min(ey, o.maxMouseY);
		if (o.maxY != null) ey = o.vmode ? Math.min(ey, o.maxMouseY) : Math.max(ey, o.minMouseY);

		nx = x + ((ex - o.lastMouseX) * (o.hmode ? 1 : -1));
		ny = y + ((ey - o.lastMouseY) * (o.vmode ? 1 : -1));

		if (o.xMapper)		nx = o.xMapper(y)
		else if (o.yMapper)	ny = o.yMapper(x)

		Drag.obj.root.style[o.hmode ? "left" : "right"] = nx + "px";
		Drag.obj.root.style[o.vmode ? "top" : "bottom"] = ny + "px";
		Drag.obj.lastMouseX	= ex;
		Drag.obj.lastMouseY	= ey;

		Drag.obj.root.onDrag(nx, ny);
		return false;
	},

	end : function()
	{
		document.onmousemove = null;
		document.onmouseup   = null;
		Drag.obj.root.onDragEnd(	parseInt(Drag.obj.root.style[Drag.obj.hmode ? "left" : "right"]), 
									parseInt(Drag.obj.root.style[Drag.obj.vmode ? "top" : "bottom"]));
		Drag.obj = null;
	},

	fixE : function(e)
	{
		if (typeof e == 'undefined') e = window.event;
		if (typeof e.layerX == 'undefined') e.layerX = e.offsetX;
		if (typeof e.layerY == 'undefined') e.layerY = e.offsetY;
		return e;
	}
};
</script>
</head>
	<body>		
<div style="position: absolute; top:25%;left:40%">
<pre>
       .-'`\-,/^\ .-.
      /    |  \  ( ee\   __
     |     |  |__/,--.`"`  `,
     |    /   .__/    `"""",/
     |   /    /  |
    .'.-'    /__/
   `"`| |';-;_`
        |/ /-))))))
</pre>
</div>
<center>
		<div id=root>
		<div id='custom' style="text-align: right; padding-top: 10px; color: white; margin-top: 15%; border-top: 1px solid black"></div>
		<div id="page">
		<div id='header'></div>

<div style='background: #efefef'>
<div style='padding: 20px'>
Votre mot de passe a changé.<br>
Veuillez saisir votre ancien mot de passe pour mettre à jour votre profil<br>
</div>
__FORM__
<br><i>En cas de perte de celui ci, veuillez contacter votre administrateur système</i>
</table>
</form>

<div id="footer" style='border-bottom: 1px solid black'></div>
</div>
</div>
</div>
</center>

<script language="javascript">
	var theHandle = document.getElementById("custom");
	var theRoot   = document.getElementById("root");
	Drag.init(theHandle, theRoot);
</script>

</body>
</html>
