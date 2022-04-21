import mdns

class DNSMessageHeader:

  ABS_DNSM_H_LEN = 12

  def __init__(self, id=0, flags=0, qCount=0, awCount=0, auCount=0, adCount=0) -> None:
    self.id = id
    self.flags = flags
    self.questionCount = qCount
    self.answerCount = awCount
    self.authorityCount = auCount
    self.additionalCount = adCount
  
  def __str__(self) -> str:
    return """<DNSMessageHeader id=%d flags=%d QCount=%d AwCount=%d AuCount=%d AdCount=%s |>""" % (
      self.id, self.flags, self.questionCount, self.answerCount,
      self.authorityCount, self.additionalCount
    )

class DNSMessage:
  def __init__(self, header, data, qu=None, an=None, au=None, ad=None) -> None:
    self.h = header
    self.data = data
    self.questions = qu if qu else []
    self.answers = an if an else []
    self.authorities = au if au else []
    self.additionalRR = ad if ad else []
  
  def __str__(self) -> str:
    s = "<DNSMessage "
    for k in vars(self):
      if k != 'data':
        s += '%s=%s ' % (k, getattr(self, k))
    return s + '|>'

def loadm(data: bytes) -> DNSMessage:
  if len(data) < DNSMessageHeader.ABS_DNSM_H_LEN:
    raise IndexError('data.len < 12')

  _head = data[:DNSMessageHeader.ABS_DNSM_H_LEN]
  _message = DNSMessage(DNSMessageHeader(), data[DNSMessageHeader.ABS_DNSM_H_LEN:])

  _message.h.id = mdns.u16(_head)
  _message.h.flags = mdns.u16(_head, 2)

  count = [mdns.u16(_head, 4), mdns.u16(_head, 6), mdns.u16(_head, 8), mdns.u16(_head, 10)]
  _message.h.questionCount = count[0]
  _message.h.answerCount = count[1]
  _message.h.authorityCount = count[2]
  _message.h.additionalCount = count[3]

  _offset = 0
  for i in range(count[0]):
    _q = mdns.get_query(_message.data, _offset)
    _offset += _q.size
    _message.questions.append(_q)
  
  for i, l in enumerate([_message.answers, _message.authorities, _message.additionalRR], start=1):
    for c in range(count[i]):
      _x = mdns.get_resource(_message.data, _offset)
      _offset += _x.size
      l.append(_x)
  
  return _message

def buildq(dname, qType=mdns.types.DNS_QCLASS_ANY, qClass=mdns.types.DNS_CLASS_IN, qu=False):
  name = None
  if type(dname) == list:
    name = dname
  elif '.' in dname:
    name = dname.split('.')
  else:
    raise ValueError('Invalid Domain-Name type!')
  
  if qu:
    qClass &= mdns.types.DNS_QCLASS_UR
  
  return mdns.Query(mdns.DomainName(name), qType, qClass)

def buildm(id=0x0000, flags=0x0000, questions=None):
  if not questions:
    questions = []

  return DNSMessage(DNSMessageHeader(id, flags, len(questions)), None, questions) 

def to_bytes(obj, buf: bytearray) -> bytes:
  o_type = type(obj)

  if o_type == DNSMessage:
    to_bytes(obj.h, buf)
    for _q in obj.questions:
      to_bytes(_q, buf)

  elif o_type == DNSMessageHeader:
    for z in [obj.id, obj.flags, obj.questionCount,
              obj.answerCount, obj.authorityCount,
              obj.additionalCount]:
      for x in __u16tou8(z):
        buf.append(x)

  elif o_type == mdns.Query:
    to_bytes(obj.qname, buf)
    for z in [obj.qtype, obj.qclass]:
      for x in __u16tou8(z):
        buf.append(x)

  elif o_type == mdns.DomainName:
    if obj.isRef:
      buf.append(0xc0)
      buf.append(obj.ref_num)
    else:
      for x in obj.raw_name:
        buf.append(len(x))
        for y in x:
          buf.append(ord(y))
      buf.append(0x00)
  
  else:
    raise TypeError('Unsupported Type')

U8_MASK = 0xFF

def __u16tou8(num) -> tuple:
  return (num >> 8, num & U8_MASK)

def __u32tou8(num) -> tuple:
  return (num >> 24, (num >> 16) & U8_MASK, (num >> 8) & U8_MASK, num & U8_MASK)