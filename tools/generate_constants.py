#!/usr/bin/env python3
"""Generate Go constants from pinned curl_cffi const.py (see UPSTREAM.md)."""
import ast
import operator
import pathlib
import sys

src = ast.parse(pathlib.Path(sys.argv[1]).read_text())
groups = {'CurlOpt': ('Option', 'Opt'), 'CurlInfo': ('Info', 'Info'),
          'CurlECode': ('ErrorCode', 'ErrCode'), 'CurlMOpt': ('MultiOption', 'MultiOpt'),
          'CurlHttpVersion': ('HTTPVersion', 'HTTPVersion'), 'CurlWsFlag': ('WSFlag', 'WS'),
          'CurlSslVersion': ('SSLVersion', 'SSLVersion'), 'CurlIpResolve': ('IPResolve', 'IPResolve'),
          'CurlFollow': ('Follow', 'Follow')}
words = '''WRITE Write DATA Data READ Read FUNCTION Function HEADER Header URL URL PORT Port
PROXY Proxy USER User PWD Pwd RANGE Range ERROR Error BUFFER Buffer TIMEOUT Timeout
INFILE InFile SIZE Size POST Post FIELDS Fields REFERER Referer FTP FTP AGENT Agent
COOKIE Cookie HTTP HTTP SSL SSL CERT Cert KEY Key PASSWD Passwd INFO Info VERSION Version
CUSTOM Custom REQUEST Request STDERR StdErr QUOTE Quote VERBOSE Verbose NO No PROGRESS Progress
BODY Body FAIL Fail ON On UPLOAD Upload DIR Dir LIST List ONLY Only APPEND Append NET Net RC RC
FOLLOW Follow LOCATION Location TRANSFER Transfer TEXT Text AUTO Auto AUTH Auth REUSE Reuse
INTERFACE Interface KRB KRB LEVEL Level CA CA MAX Max REDIRS Redirs FILE File TIME Time CONNECT Connect
FRESH Fresh FORBID Forbid VERIFY Verify PEER Peer HOST Host JAR Jar CIPHER Cipher GET Get TYPE Type
ENGINE Engine DEFAULT Default DNS DNS USE Use GLOBAL Global CACHE Cache DEBUG Debug SESSION Session
PATH Path SIGNAL Signal ACCEPT Accept ENCODING Encoding PRIVATE Private UNRESTRICTED Unrestricted
CTX Ctx CREATE Create MISSING Missing DIRS Dirs SERVER Server RESPONSE Response IP IP RESOLVE Resolve
LARGE Large TCP TCP NODELAY NoDelay MS MS T T E E V4 V4 V6 V6
SPEED Speed SEND Send RECV Recv STREAM Stream WEIGHT Weight EXCLUSIVE Exclusive
EC EC CURVES Curves SIG Sig HASH Hash ALGS Algs ALPS ALPS TLS TLS GREASE Grease
PERMUTE Permute EXTENSIONS Extensions EXTENSION Extension ORDER Order SETTINGS Settings
PSEUDO Pseudo HEADERS Headers WINDOW Window UPDATE Update STREAMS Streams SIGNED Signed
TIMESTAMPS Timestamps STATUS Status DELEGATED Delegated CREDENTIALS Credentials RECORD Record
LIMIT Limit SHARES Shares NEW New CODEPOINT Codepoint PRIORITY Priority SPLIT Split COOKIES Cookies
FORM Form BOUNDARY Boundary QUIC QUIC PARAMETERS Parameters CID CID LENGTH Length
TRUST Trust ANCHORS Anchors INITIAL Initial PACKET Packet NUMBER Number HTTP2 HTTP2 HTTP3 HTTP3
WS WS ALLOW Allow PROTOCOLS Protocols STR Str OPTIONS Options BLOB Blob KEEP Keep ALIVE Alive
AGE Age LIFE Life TOTAL Total EFFECTIVE Effective CODE Code TIME Time LOOKUP Lookup LOCAL Local
PRIMARY Primary COUNT Count ACTIVE Active SOCKET Socket OS OS ERRNO Errno COOKIELIST CookieList
COOKIECHANGES CookieChanges HISTORY History UPKEEP Upkeep PAUSE Pause
'''.split()
mapping = dict(zip(words[::2], words[1::2]))
compact = {'WRITEDATA': 'WriteData', 'READDATA': 'ReadData', 'HEADERDATA': 'HeaderData',
 'WRITEFUNCTION': 'WriteFunction', 'READFUNCTION': 'ReadFunction', 'HEADERFUNCTION': 'HeaderFunction',
 'DEBUGFUNCTION': 'DebugFunction', 'DEBUGDATA': 'DebugData', 'SEEKFUNCTION': 'SeekFunction',
 'SEEKDATA': 'SeekData', 'XFERINFOFUNCTION': 'XferInfoFunction', 'XFERINFODATA': 'XferInfoData',
 'HTTPHEADER': 'HTTPHeader', 'HTTPBASEHEADER': 'HTTPBaseHeader', 'HTTPHEADER_ORDER': 'HTTPHeaderOrder',
 'HTTP3_HTTPHEADER': 'HTTP3HTTPHeader', 'WS_HTTPHEADER': 'WSHTTPHeader',
 'POSTFIELDS': 'PostFields', 'POSTFIELDSIZE': 'PostFieldSize', 'COPYPOSTFIELDS': 'CopyPostFields',
 'CUSTOMREQUEST': 'CustomRequest', 'USERAGENT': 'UserAgent', 'USERPWD': 'UserPwd',
 'PROXYUSERPWD': 'ProxyUserPwd', 'KEYPASSWD': 'KeyPasswd', 'SSLCERT': 'SSLCert',
 'SSLKEY': 'SSLKey', 'CAINFO': 'CAInfo', 'CAPATH': 'CAPath', 'NOPROXY': 'NoProxy',
 'NOBODY': 'NoBody', 'NOPROGRESS': 'NoProgress', 'NOSIGNAL': 'NoSignal',
 'FOLLOWLOCATION': 'FollowLocation', 'FAILONERROR': 'FailOnError', 'HTTPGET': 'HTTPGet',
 'HTTPAUTH': 'HTTPAuth', 'PROXYAUTH': 'ProxyAuth', 'HTTPPROXYTUNNEL': 'HTTPProxyTunnel',
 'CONNECTTIMEOUT': 'ConnectTimeout', 'MAXREDIRS': 'MaxRedirs', 'COOKIEFILE': 'CookieFile',
 'COOKIEJAR': 'CookieJar', 'SSLVERSION': 'SSLVersion', 'CERTINFO': 'CertInfo',
 'ACTIVESOCKET': 'ActiveSocket', 'MIMEPOST': 'MIMEPost', 'POSTREDIR': 'PostRedir',
 'SSL_VERIFYRESULT': 'SSLVerifyResult', 'HTTP_CONNECTCODE': 'HTTPConnectCode',
 'MAXAGE': 'MaxAge', 'MAXLIFETIME': 'MaxLifeTime', 'INFILESIZE': 'InFileSize',
 'MAXFILESIZE': 'MaxFileSize', 'PRETRANSFER': 'PreTransfer', 'STARTTRANSFER': 'StartTransfer',
 'APPCONNECT': 'AppConnect', 'POSTTRANSFER': 'PostTransfer', 'NAMELOOKUP': 'NameLookup'}
def numeric_expression(node):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    operations = {ast.Add: operator.add, ast.Sub: operator.sub, ast.LShift: operator.lshift,
                  ast.BitOr: operator.or_}
    if isinstance(node, ast.BinOp) and type(node.op) in operations:
        return operations[type(node.op)](numeric_expression(node.left), numeric_expression(node.right))
    raise ValueError('constant must be an integer expression')
def name(s):
    if s in compact:
        return compact[s]
    return ''.join(compact.get(p, mapping.get(p, p.title())) for p in s.split('_'))
out = ['// Code generated from curl_cffi const.py; DO NOT EDIT.', '// Upstream MIT license: LICENSE.',
       'package curlgo', '']
for cls in src.body:
    if not isinstance(cls, ast.ClassDef) or cls.name not in groups:
        continue
    typ, prefix = groups[cls.name]
    out += [f'type {typ} int', 'const (']
    for stmt in cls.body:
        if not isinstance(stmt, ast.Assign) or not isinstance(stmt.targets[0], ast.Name):
            continue
        key = stmt.targets[0].id
        value = numeric_expression(stmt.value)
        out += [f'    {prefix}{name(key)} {typ} = {value}', f'    {cls.name}_{key} = {prefix}{name(key)}']
    out += [')', '']
pathlib.Path('constants.go').write_text('\n'.join(out))
