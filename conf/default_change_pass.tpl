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
}

#root {
	 position: relative;
	 top: 15%;
}

#custom {
	  width: 550px;
	  height: 500px;
	  background-repeat: no-repeat;
	  background-image: url('/static/bg.png');
}

.submit {
	  padding-top: 10px;
          text-align: right;
}

</STYLE>
</head>
	<body onload="document.auth_form.vulture_login.focus();">		
<div style="position: absolute; top:25%;left:25%">

<center>
		<div id=root>
	<div id="custom" style="margin: 0pt; padding: 50px 0pt 0px;">
<i>Vous devez changer votre mot de passe</i>
<br>
<br>
__FORM__
<tr><td></td><td align="right"><input type="submit" value="Envoyer"></td></tr>
</table>
</form>
<br>
</div>
</div>
</div>
</center>
</div>
<script language="javascript">
	var theHandle = document.getElementById("custom");
	var theRoot   = document.getElementById("root");
	Drag.init(theHandle, theRoot);
</script>

</body>
</html>
