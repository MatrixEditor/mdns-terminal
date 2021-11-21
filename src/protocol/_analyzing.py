import sys

from protocol.mdns import *

if sys.platform == 'win32':
  SEP = '\\'
else:
  SEP = '/'

_types = [(TYPE_A, 'A'), (TYPE_AAAA, 'AAAA'), (TYPE_ALL, '*'),
        (TYPE_PTR, 'PTR'), (TYPE_SRV, 'SRV'), (TYPE_TXT, 'TXT'), (TYPE_OPT, 'OPT')]

TABLE_HEADER = ' No.    Source          Destination   Port   Data'
TABLE_HEADER_JSON = '"no": %s,\n"source": "%s",\n"dest": "224.0.0.251",\n"port": 5353,\n"data": "%s"\n'
TABLE_TEMPLATE = ' %s   %s    224.0.0.251   5353   %s'

ADDR_HEADER = " Address           No. of packets"

IF_TXT  = 'txt'
IF_JSON = 'json'

IMPLEMENTED_FORMATS = [IF_TXT, IF_JSON]

#WRITE_TYPE = ['table', 'packet', 'addr']
WT_TABLE   = 1
WT_PACKET  = 2
WT_ADDR    = 3

FT_TABLE  = "packet-table"
FT_PACKET = "packets"
FT_ADDR   = "ip-addr"

MAX_TABLE_LENGTH = 125



class FileFormatter:
  def __init__(self, ext) -> None:
      self.extension = ext

  def iniwriteT(self) -> str:
    pass

  def iniwriteP(self) -> str:
    pass

  def iniwriteA(self) -> str:
    pass

  def writeP(self, data, c) -> str:
    pass

  def writeT(self, data, c) -> str:
    pass
  
  def writeA(self, data) -> str:
    pass

  def close() -> str:
    pass

class TXTFormatter(FileFormatter):
  def __init__(self) -> None:
    super().__init__(IF_TXT)
  
  def writeA(self, data) -> str:
    s = ''
    for k in data:
         s += ' ' + ''.join([k, ' '*6, str(data[k])]) + "\n"
    return s

  def writeP(self, data, c) -> str:
      s = ''
      rq = data[0]
      h = rq[HEADER]; b = rq[BODY]
      s += '[>] Packet: src="%s", no=%d\n  <header>\n' % (data[1], c)
      for x in h:
        s += '    %s: %s\n' % (x, h[x])
      s += '  [body]\n'
      for y in b:
        s += '    [%s]\n' % (y)
        for i, z in enumerate(b[y]):
          s += ' '*6 + f'[No={i}]\n'
          for a in z:
            s += ' '*8 + '%s: %s\n' % (a, str(z[a]))
      return s + '\n'

  def writeT(self, data, c) -> str:
    h = len_host(data[1])
    n = len_num(c)

    dataf = format_data(data[0])
    return '\n' + TABLE_TEMPLATE % (n, h, dataf)

  def iniwriteA(self) -> str:
    return ADDR_HEADER + '\n'

  def iniwriteP(self) -> str:
    return ''
    
  def iniwriteT(self) -> str:
    return TABLE_HEADER

  def close() -> str:
    return ''

class JSONFormatter(FileFormatter):
  def __init__(self) -> None:
    super().__init__(IF_JSON)

  def writeP(self, data, c) -> str:
    return ('{"no": %d,' % (c)) + packetf(data)
  
  def writeA(self, data) -> str:
    s = ''
    for k in data:
      s += '{\n"ip": "%s",\n"amount": %d},\n' % (k, data[k])
    return s

  def writeT(self, data, c) -> str:
    h = len_host(data[1])
    n = len_num(c)

    dataf = format_data(data[0])
    return '{' + (TABLE_HEADER_JSON % (n, h, dataf.replace('"', "'"))) + '},'

  def iniwriteT(self) -> str:
    return '{"file": "ip-addr.json","table": ['

  def iniwriteP(self) -> str:
    return '{"file": "packets.json", "packets": ['

  def iniwriteA(self) -> str:
    return '{"file": "ip-addr.json","style": {"ip": "...","amount": 0},"addr": ['

  def close() -> str:
    return '"noerror"\n]\n}'


FORMATTERS = [TXTFormatter(), JSONFormatter()]

class mDNSFormatter:
  def __init__(self) -> None:
    self.c = 0

  def openf(self, path, name, f):
    x = open(SEP.join([path, ".".join([name, f])]), 'w')
    for _F in FORMATTERS:
        if _F.extension == f:
          x.write(_F.iniwriteT() if name == FT_TABLE else _F.iniwriteA() if name == FT_ADDR else _F.iniwriteP())
    x.flush()
    return x

  def closef(self, file, f):
    for _F in FORMATTERS:
        if _F.extension == f:
          file.write(_F.close())
    file.flush()
    file.close()

  def printf(self, data: dict, addr):
    self.c += 1
    h = len_host(addr[0])
    n = len_num(self.c)

    dataf = format_data(data)
    print(TABLE_TEMPLATE % (n, h, dataf))

  def writef(self, data, file, writetype=-1, format=IF_TXT):
    if writetype == -1:
      return

    for _F in FORMATTERS:
        if _F.extension == format:
          file.write(_F.writeT(data, self.c) if writetype == WT_TABLE else _F.writeA(data) if writetype == WT_ADDR else _F.writeP(data, self.c))
    file.flush()

def len_host(host) -> str:
  if len(host) == 14:
    host += ' '
  elif len(host) == 13:
    host += ' '*2
  return host

def len_num(counter):
  num = str(counter)
  if counter < 1000:
    num += ' '
  if counter < 100:
    num += ' '
  if counter < 10:
    num += ' '
  return num

def format_data(qu_data) -> str:
  s = ''
  header = qu_data[HEADER]
  try:
    if str(header[PK_FLAGS_RCODE[0]]) == '0x8400':
        s += 'Standard query response %s, ' % (str(header[PK_TRANSACTION_ID[0]]))
    else:
        s += 'Standard query %s, ' % (header[PK_TRANSACTION_ID[0]])
  except:
    s += 'ID-Error %s, ' % (header[PK_TRANSACTION_ID[0]])

  try:
    queries = qu_data[BODY][QUERIES]
    if len(queries) > 0:
      q = queries[0]; l = [typeof(q[QRY_TYPE[0]]), q[QRY_NAME[0]]]
      if str(q[QRY_QU[0]]) == '0x801':
        s += '"QU" question '
      else:
        s += '"QM" question '
      s += ' '.join([str(x) for x in l]) + ', '
  except:
    pass

  try:
    answers = qu_data[BODY][ANSWERS]
    if len(answers) > 0:
      a = answers[0]
      s += ' '.join([str(x) for x in [typeof(a[AS_TYPE[0]]), a[AS_NAME[0]]]]) + ', '
  except:
    pass

  try:
    records = qu_data[BODY][RECORDS]
    if len(records) > 0:
      r = records[0]
      if r[RC_TYPE[0]] == TYPE_OPT:
        s += ', question OPT '
      else:
        s += typeof(r[RC_TYPE[0]]) + ' '
  except:
    pass

  if len(s) > MAX_TABLE_LENGTH:
    s = s[:MAX_TABLE_LENGTH]

  return s + '...'

def typeof(t):
    for n, v in _types:
      if n == t:
        return v 
    return 'NONE'

def packetf(qu_data):
  return str(qu_data[0]).replace("'", '"').replace('b"', '"')[1:] + ','