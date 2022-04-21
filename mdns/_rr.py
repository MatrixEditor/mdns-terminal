import mdns

class RRException(Exception):
  pass

class Query:
  def __init__(self, name=None, qtype=0, qclass=0) -> None:
    self.qname = [] if not name else name
    self.qtype = qtype
    self.qclass = qclass
    self.size = 0
  
  def __str__(self) -> str:
    s = "<Query "
    for k in vars(self):
      s += '%s=%s ' % (k, getattr(self, k))
    return s + '|>'

class ResourceRecord:
  def __init__(self) -> None:
    super().__init__()
    self.ttl = 0
    self.rdlength = 0
    self.rdata = None
    self.name = []
    self.type = -1
    self.clazz = 0
    self.size = 0
  
    def __str__(self) -> str:
      s = "<ResourceRecord "
      for k in vars(self):
        if k == 'rdata':
          s += getattr(self, k).__str__()
        else:
          s += '%s=%s ' % (k, getattr(self, k))
      return s + '|>'

  def has_cache_flush(self):
    return (self.clazz & 32768) != 0

class DomainName:
  def __init__(self, name=None, ref_num=-1, isRef=False) -> None:
    self.isRef = isRef
    self.ref_num = ref_num
    self.raw_name = name if name else []
  
  def __str__(self) -> str:
    return '.'.join(self.raw_name)

def get_txt(data, offset) -> tuple:
  if data[offset] == 0xc0:
    return (offset + 2, [data[offset + 1]])
  
  index = offset
  name = []
  while True:
    if data[index] == 0x00:
      break
  
    if data[index] == 0xc0:
      index += 1
      name.append(data[index])
      index += 1
      break

    _len = mdns.u8(data, index)
    index += 1
    try:
      name.append(str(data[index:index+_len], 'utf-8'))
    except:
      pass
    index += _len

  return (index + 1, name)

def get_qname(all_data, offset) -> tuple:
  index = offset
  name = DomainName()
  while True:
    _c0 = mdns.u8(all_data, index)
    if _c0 == 0x00:
      break
    
    tmp = _c0 & 0xc0
    if tmp == 0xc0:
      n_off = ((_c0 & 0x3F) << 8) | mdns.u8(all_data, index + 1) - mdns.DNSMessageHeader.ABS_DNSM_H_LEN
      index += 1
        
      if n_off < len(all_data):
        if mdns.u8(all_data, n_off) & 0xc0 != 0:
          print("[!] Compression pointer must point to real label")
          break
        
        name.isRef = True
        name.ref_num = n_off
        name.raw_name += get_qname(all_data, n_off)[1].raw_name
      break 

    elif tmp == 0x40:
      raise IndexError('Extended EDNS0 label types not supported')
    
    elif tmp == 0x80:
      raise IndexError('Illegal label length 0x%X in domain name' % tmp)

    else:
      length = _c0
      index += 1
      try:
        name.raw_name.append(str(all_data[index:index+length], 'utf-8'))
      except:
        pass
      index += length
  
  return (index + 1, name)

def get_query(data, offset) -> Query:
  index, name = get_qname(data, offset)
  if index > len(data):
    raise RRException() from IndexError
  
  rr_q = Query()
  rr_q.qname = name

  rr_q.qtype = mdns.u16(data, index)
  index += 2
  if rr_q.qtype not in mdns.DNS_TypeValues:
    raise RRException('Not a default Query-Type') from ValueError

  rr_q.qclass = mdns.u16(data, index)
  index += 2
  if (rr_q.qclass & mdns.types.DNS_QCLASS_ANY) == 0:
    raise RRException('Not a default Query-Class')

  rr_q.size = index - offset
  return rr_q

def get_resource(data, offset) -> ResourceRecord:
  if data[offset] == 0x00:
    # meta-RR (OPT)
    return mdns.DNS_TypeValues[41][2](data, offset, -1)

  index, name = get_qname(data, offset)
  if len(data) < index:
    raise IndexError()
  
  record = ResourceRecord()
  record.name = name

  record.type = mdns.u16(data, index)
  index+=2
  record.clazz = mdns.u16(data, index)
  index+=2

  record.ttl = mdns.u32(data, index)
  index+=4
  record.rdlength = mdns.u16(data, index)
  index+=2

  if record.type in mdns.DNS_TypeValues:
    r_type = mdns.DNS_TypeValues[record.type]
    record.rdata = r_type[2](data, index, record.rdlength)
  
  record.size = (index+record.rdlength) - offset
  return record
