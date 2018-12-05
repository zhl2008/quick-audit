#!/usr/bin/env python

content_thresold_value = 100

file_extensions = ['php','php5','php7','php3','php4','pht','phtml','inc','html']


tencent_webshell_rule_php = (('common_webshell1', 0, 10101, '(?i)[\\r\\n;/\\*]+\\s*\\b(include|require)(_once)?\\b[\\s\\(]*[\'"][^\\n\'"]{1,100}((\\.(jpg|png|txt|jpeg|log|tmp|db|cache)|\\_(tmp|log))|((http|https|file|php|data|ftp)\\://.{0,25}))[\'"][\\s\\)]*[\\r\\n;/\\*]+', 0), ('common_webshell2', 0, 10102, '(?i)(?<!->)\\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\\b[/*\\s]*\\(+[/*\\s]*((\\$_(GET|POST|REQUEST|COOKIE).{0,25})|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\\s\\(]*(\\$_(GET|POST|REQUEST|COOKIE).{0,25}))', 0), ('common_webshell3', 0, 10103, '(?i)\\$\\s*(\\w+)\\s*=[\\s\\(\\{]*(\\$_(GET|POST|REQUEST|COOKIE).{0,25});[\\s\\S]{0,200}(?<!\\>)\\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\\b[/*\\s]*\\(+[\\s"/*]*(\\$\\s*\\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\\s\\("]*\\$\\s*\\1))', 0), ('common_webshell4', 1, 10104, '(?i)(preg_replace|preg_filter)[/*\\s]*\\(+[/*\\s]*((\\$_(GET|POST|REQUEST|COOKIE).{0,25})|[^,]{0,250}chr[\\s\\(](101|0x65|0145|\\d+)[^,]{0,25}\\s*|[\'"]\\s*(([^\\s])[^,]{0,20}\\7[\'"]*|[\\(\\}\\[].{0,20}[\\(\\}\\]])\\w*e\\w*[\'"])\\s*,([^\\),]*(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)|((\\$_(GET|POST|REQUEST|COOKIE).{0,25})))', 0), ('common_webshell5', 1, 10105, '(?i)\\$\\s*(\\w+)\\s*=\\s*((\\$_(GET|POST|REQUEST|COOKIE).{0,25})|[^;]*chr[\\s\\(]*(101|0x65|0145|\\d+)|[\'"](/[^/]*/|\\|[^\\|]*\\||\\\\\'[^\']*\')\\w{0,5}e\\w{0,5}[\'"])[\\s\\S]{0,1000}(preg_replace|preg_filter)[/*\\s]*\\([/*\\s]*\\$\\s*\\1.{0,30}(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)', 0), ('common_webshell6', 1, 10106, '(?i)\\$\\s*(\\w+)\\s*=\\s*(\\$_(GET|POST|REQUEST|COOKIE).{0,25})[\\s\\S]{0,1000}(preg_replace|preg_filter)[/*\\s]*\\(+[/*\\s]*((\\$_(GET|POST|REQUEST|COOKIE).{0,25})|[^,]{0,250}chr[\\s\\(](101|0x65|0145|\\d+)[^,]{0,25}\\s*|[\'"]\\s*(([^\\s])[^,]{0,20}\\10|[\\(\\}\\[].{0,20}[\\(\\}\\]])\\w*e\\w*[\'"])\\s*,([^\\)]*(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)|\\s*\\$\\1)', 0), ('common_webshell7', 0, 10107, '(?i)(array_map|call_user_func|call_user_func_array|new\\s*ReflectionFunction|register_shutdown_function|register_tick_function|new\\s*ArrayObject[\\s\\S]*->u[ak]sort)\\s*\\(+\\s*([\'"]\\s*(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|[^\'"]*\\\\x).{0,200}|(\\$_(GET|POST|REQUEST|COOKIE)\\[[^,;\\)]{0,250},[^;\\),]{0,50}\\$[^;\\),]{0,50}\\)))', 0), ('common_webshell8', 0, 10108, '(?i)\\$\\s*(\\w+)\\s*=[\\s\\(\\{]*((\\$_(GET|POST|REQUEST|COOKIE|SERVER).{0,25})|[\'"]\\s*(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))[\\s\\S]{0,200}(?<!\\>)\\b(array_map|call_user_func|call_user_func_array|new\\s*ReflectionFunction|register_shutdown_function|register_tick_function|new\\s*ArrayObject[\\s\\S]*->u[ak]sort)\\b\\s*\\(+\\s*(\\$\\s*\\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\\s\\(]*\\$\\s*\\1))[^,;]*,[^;\\)]{0,50}\\$[^;\\)]{0,50}\\)', 0), ('common_webshell9', 1, 10109, '(?i)((array_filter|array_reduce|array_diff_ukey|array_udiff|array_walk|uasort|uksort|usort|new\\s*SQLite3[\\s\\S]*->\\s*createFunction)\\s*\\(+\\s*.{1,100}|PDO::FETCH_FUNC\\s*),\\s*([\'"]\\s*(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\\s*[\'"]|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\\s\\(]+.{1,25}|(\\$_(GET|POST|REQUEST|COOKIE).{0,25}))\\s*\\)', 0), ('common_webshell10', 1, 10110, '(?i)\\$\\s*(\\w+)\\s*=[\\s\\(\\{]*((\\$_(GET|POST|REQUEST|COOKIE).{0,25})|[\'"]\\s*(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|[^,;]*?\\\\x|[^,;]*?[\'"]\\s*\\.\\s*[\'"]))[\\s\\S]{0,1000}(?<!\\>)((array_filter|array_reduce|array_diff_ukey|array_udiff|array_walk|uasort|uksort|usort|new\\s*SQLite3[\\s\\S]*->\\s*createFunction)\\s*\\(+[^,]*\\$[^,]*|PDO::FETCH_FUNC\\s*),\\s*(\\$\\s*\\1\\s*\\)|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\\s\\(]*\\$\\s*\\1))', 0), ('common_webshell11', 1, 10111, '(?i)\\$(\\w*)\\s*=\\s*\\bcreate_function\\b\\s*\\(+\\s*[^;\\n\\r\\)]{1,100},\\s*([\'"]\\s*[^;\\n\\r\\)]{0,100}(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|poc_open|pcntl_exec).{1,600}\\s*[\'"]|[^,]{0,100}(\\$_(GET|POST|REQUEST|COOKIE|SERVER).{1,})|[^,\\n\\r\\)]{0,100}file_get_contents.{1,})\\s*\\)[\\s\\S]+\\$\\1\\s*\\([^\\)]*\\)', 0), ('common_webshell12', 1, 10112, '(?i)\\$(\\w*)\\s*=\\s*\\bcreate_function\\b\\s*\\([^;]*;[\\s\\S]*\\$\\1\\s*\\([^\\)]*([\'"]\\s*[^;\\n\\r\\)]{0,100}(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|poc_open|pcntl_exec).{1,600}\\s*[\'"]|[^;\\n\\r]{0,100}(\\$_(GET|POST|REQUEST|COOKIE|SERVER).{1,})|[^;\\n\\r\\)]{0,100}file_get_contents.{1,})', 0), ('common_webshell13', 0, 10113, '(?i)\\$\\s*(\\w+)\\s*=[\\s\\(\\{]*((\\$_(GET|POST|REQUEST|COOKIE|SERVER).{0,25})|[\'"]\\s*.{0,100}(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec).{1,100}\\s*[\'"]|file_get_contents)[\\s\\S]{0,200}create_function\\s*\\(+[^,]{1,100},[\'"\\s]*(\\$\\s*\\1[\'"\\s]*\\)|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\\s\\(]*\\$\\s*\\1))', 0), ('common_webshell14', 0, 10114, '(?i)\\$\\s*(\\w+)\\s*=\\s*((\\$_(GET|POST|REQUEST|COOKIE|SERVER).{0,25})|[\'"]\\s*(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\\s*[\'"]|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\\s*\\()[\\s\\S]{0,200}(?<![:>\\s])\\s*\\$\\1\\s*\\(+[^\\)]*(\\$_(GET|POST|REQUEST|COOKIE|SERVER).{0,25})', 0), ('common_webshell15', 0, 10115, '(?i)sqlite_create_function\\s*\\([\\s\\S]{0,200}(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)|(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)[\\s\\S]{0,200}sqlite_create_function\\s*\\(', 0), ('common_webshell25', 0, 10116, '(?i)\\b(filter_var|filter_var_array)\\b\\s*\\(.*FILTER_CALLBACK[^;]*((\\$_(GET|POST|REQUEST|COOKIE|SERVER).{0,25})|(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))', 0), ('common_webshell16', 0, 10117, '(?i)\\$\\s*(\\w+)\\s*=\\s*((\\$_(GET|POST|REQUEST|COOKIE|SERVER).{0,25})|[\'"]\\s*(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\\s*[\'"]|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\\s*\\()[\\s\\S]{0,200}\\b(filter_var|filter_var_array)\\b\\s*\\(.*FILTER_CALLBACK[^;]*\\$\\1', 0), ('common_webshell17', 0, 10118, '(?i)\\b(mb_ereg_replace|mb_eregi_replace)\\b\\s*\\((.*,){3}\\s*([\'"][^,"\'\\)]*e[^,"\'\\)]*[\'"]|.*(\\$_(GET|POST|REQUEST|COOKIE|SERVER).{0,25}).*|chr\\s*\\(\\s*101|chr\\s*\\(\\s*0x65|chr\\s*\\(\\s*0145)\\s*\\)', 0), ('common_webshell25', 0, 10119, '(?i)\\$\\s*(\\w+)\\s*=\\s*((\\$_(GET|POST|REQUEST|COOKIE|SERVER).{3,25})|[\'"][^;]*e|[^;]*chr[\\s\\(]*(101|0x65|0145))[\\s\\S]{0,200}\\b(mb_ereg_replace|mb_eregi_replace)\\b\\s*\\((.*,){3}\\s*\\$\\1', 0), ('common_webshell18', 0, 10120, '(?i)array_walk(_recursive)?\\s*\\([^;,]*,\\s*([\'"]\\s*(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|preg_replace)\\s*[\'"]|(\\$_(GET|POST|REQUEST|COOKIE|SERVER).{0,25}))', 0), ('common_webshell19', 0, 10121, '(?i)\\$\\s*(\\w+)\\s*=\\s*((\\$_(GET|POST|REQUEST|COOKIE|SERVER).{0,25})|[\'"]\\s*(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|preg_replace))[\\s\\S]{0,200}array_walk(_recursive)?\\s*\\([^;,]*,\\s*(\\$\\s*\\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\\s\\(]*\\$\\s*\\1))', 0), ('common_webshell20', 0, 10122, '(?i)\\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\\b\\s*\\(\\s*(file_get_contents\\s*\\(\\s*)?[\'"]php://input', 0), ('common_webshell21', 1, 10123, '^(\\xff\\xd8|\\x89\\x50|GIF89a|GIF87a|BM|\\x00\\x00\\x01\\x00\\x01)[\\s\\S]*<\\?\\s*php', 0), ('common_webshell22', 0, 10124, "\\$(\\w)=\\$[a-zA-Z]\\('',\\$\\w\\);\\$\\1\\(\\);", 0), ('common_webshell23', 1, 10125, "(?i)\\$(\\w+)\\s*=\\s*str_replace\\s*\\([\\s\\S]*\\$(\\w+)\\s*=\\s*\\$(\\w+)(([\\s\\S]{0,255})|(\\s*\\(\\'\\',\\s*(\\$(\\w+)\\s*\\(\\s*)+))\\$\\1\\s*\\([\\s\\S]{0,100};?\\s*\\$\\2\\(?\\s*\\)", 0), ('common_webshell24', 0, 10126, '(?i)ob_start\\s*\\(+\\s*([\'"]\\s*(eval|assert|ass\\\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec).{0,20}|[\'"]\\s*\\w+[\\s\\S]{1,50}phpinfo\\s*\\(\\s*\\))', 0), ('common_webshell25', 0, 10127, '\\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\\b\\s*\\(((\\$_SERVER|\\$_ENV|getenv|\\$GLOBALS)\\s*[\\[\\(]\\s*[\'"]+(REQUEST_URI|QUERY_STRING|HTTP_[\\w_]+|REMOTE_[\\w_])[\'"\\s]+\\s*[\\]\\)]|php://input|exif_read_data\\s*\\()', 0), ('common_webshell24', 0, 10128, 'eval\\("\\?>"\\.|gzinflate\\(base64_decode\\(|eval\\(base64_decode\\(|cat\\s*/etc/passwd|Safe_Mode\\s*Bypass', 0), ('common_webshell25', 1, 10129, '\\$_\\[\\$_|\\${"_P"\\.|a(.)s\\1s\\1e\\1r\\1t|\'e\'\\.\'v\'\\.\'a\'\\.\'l|687474703a2f2f626c616b696e2e64756170702e636f6d2f7631|python_eval\\("import os\\\\nos.system\\(|\\$bind_pl\\s*=\\s*"IyEvdXNyL2Jpbi9lbnYgcGV|phpsocks5_encrypt\\s*\\(|eNrs/Vmv41iWJgq+ZwH1H7wdAWRksypJihRF3kQ0mvMsihTnuoUA53meeVG/valj5mbuHpF9b6P7se', 0), ('common_webshell25', 1, 10130, 'preg_replace\\s*\\(\\s*[\'"][^;]*e[^;]*[\'"],([^;]{0,30}\\\\x|[^;\\)]{200,300})|\\$back_connect="IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU2|define\\(\'gzip\',function_exists\\("ob_gzhandler"\\)|chr\\(112\\)\\.chr\\(97\\)\\.chr\\(115\\)\\.chr\\(115\\)|687474703a2f2f377368656c', 0), ('common_webshell24', 1, 10131, 'ini_get\\s*\\(\\s*"disable_functions"\\s*\\)|\\d\\s*=>\\s*array\\s*\\(\\s*[\'"]\\s*pipe\\s*[\'"]|gzuncompress\\(base64_decode\\(|crypt\\(\\$_SERVER\\[\'HTTP_H0ST\'\\],\\d+\\)==|if\\(file_exists\\(\\$settings\\[\'STOPFILE\'\\]\\)\\)', 0), ('common_webshell25', 1, 10132, '\\$nofuncs=\'no\\s*exec\\s*functions|udf\\.dll|\\$b374k|POWER-BY\\s*WWW.XXDDOS.COM|<title>Safes\\s*Mode\\s*Shell</title>|Siyanur\\.PHP\\s*</font>|c999shexit\\(\\)|\\$c99sh_|c99_sess_put\\(|Coded\\s*by\\s*cyb3r|cyb3r_getupdate\\(|coded\\s*by\\s*tjomi4|john\\.barker446@gmail\\.com|eval\\("\\\\\\$x=gzin"|eval\\("\\?>"\\.gzinflate\\(base64_decode\\(|eval\\(gzinflate\\(base64_decode\\(|eval\\(gzuncompress\\(base64_decode\\(|eval\\(gzinflate\\(str_rot13\\(base64_decode\\(|function_exists\\("zigetwar_buff_prepare"\\)|dQ99shell|r57shell|c99shell|lama\'s\'hell\\s*v|Carbylamine\\s*PHP\\s*Encoder|Safe\\s*Mode\\s*Shell|\\$dI3h=\\${\'_REQUEST\'};|new\\s*COM\\("IIS://localhost/w3svc"\\)|n57http-based\\[\\s*-\\]terminal|Dosya\\s*Olu|errorlog\\("BACKEND:\\s*startReDuh,|form\\s*name=sh311Form|PHPJackal<br>|Reddragonfly\'s\\s*WebShell|\\("system"==\\$seletefunc\\)\\?system\\(\\$shellcmd\\)|eNrsvGmT40iSKPZ5xmz|CrystalShell\\s*v\\.|Special\\s*99\\s*Shell|Simple\\s*PHP\\s*Mysql\\s*client|\'_de\'\\.\'code\'|phpsocks5_encrypt\\(|define\\(\'PHPSHELL_VERSION\',|ZXZhbCgkX1BPU1RbMV0p|\\$__H_H\\(\\$__C_C', 0), ('common_webshell25', 1, 10133, 'PD9waHANCiRzX3ZlciA9ICIxLjAiOw0KJHNfdGl0bGUgPSAiWG5vbnltb3V4IFNoZWxsIC|GFnyF4lgiGXW2N7BNyL5EEyQA42LdZtao2S9f|IyEvdXNyL2Jpbi9wZXJsDQokU0hFTEw9Ii9iaW4vYmFzaCAtaSI7|setcookie\\("N3tsh_surl"\\);|function\\s*Tihuan_Auto|\\$_COOKIE\\[\'b374k\'\\]|function_exists\\("k1r4_sess_put"\\)|http://www.7jyewu.cn/|scookie\\(\'phpspypass|PHVayv.php\\?duzkaydet=|phpRemoteView</a>|define\\(\'envlpass\',|KingDefacer_getupdate\\(|relative2absolute\\(|Host:\\s*old.zone-h.org|<h3>PHPKonsole</h3>|\\$_SESSION\\[\'hassubdirs\'\\]\\[\\$treeroot\\]|strtolower\\(\\$cmd\\)\\s*==\\s*"canirun"|\\$shell\\s*=\\s*\'uname\\s*-a;\\s*w;\\s*id;|Avrasya\\s*Veri\\s*ve\\s*NetWork|<h1>Linux Shells</h1>|\\$MyShellVersion\\s*=\\s*"MyShell|<a\\s*href="http://ihacklog.com/"|setcookie\\(\\s*"mysql_web_admin_username"\\s*\\)|<title>PHP\\s*Shell\\s*[^\\n\\r]*</title>|\\$OOO000000=urldecode|1MSSYowqjzlVVAwAoHHFXzQ5Lc|\'xiaoqiwangluo\'|EqQC1FhyXxpEi7l2g\\+yNjW62S|\\$_uU\\(83\\)\\.\\$_uU\\(84\\)|7kyJ7kSKioDTWVWeRB3TiciL1UjcmRiLn4SKiAETs90cuZlTz5mROtHWHdWfRt0ZupmVRNTU2Y2MVZkT8|<title>\\s*ARS\\s*Terminator\\s*Shell</title>|base64_decode\\("R0lGODdhEgASAKEAAO7u7gAAAJmZmQAAACwAAA|\\\\x50\\\\x4b\\\\x03\\\\x04\\\\x0a\\\\x00\\\\x00\\\\x00\\\\x00|\'<title>W3D\\s*Shell|\\$back_connect="IyEvdXNyL2Jpbi9wZXJsD', 0), ('common_webshell30', 1, 10135, '\\$(\\w+)[\\s]*\\=[\\s]*\\$_(?:POST|GET|REQUEST|COOKIE|SERVER).{0,25}[\\s\\S]*(?<!\\>)\\$(?:\\1\\(\\s*\\$_(?:POST|GET|REQUEST|COOKIE|SERVER).{0,25}\\s*\\)|(\\w+)\\s*\\=\\s*\\$_(?:POST|GET|REQUEST|COOKIE|SERVER).{0,25}[\\s\\S]*(?<!\\>)\\$(\\1\\(\\s*\\$\\2|\\2\\(\\s*\\$\\1)\\s*\\)|_(?:POST|GET|REQUEST|COOKIE|SERVER).{0,25}\\(\\s*\\$\\1\\s*\\))|\\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\\[([\'"]\\w+[\'"]|\\d+)\\]\\(\\s*\\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\\[([\'"]\\w+[\'"]|\\d+)\\]\\s*\\)', 0))

