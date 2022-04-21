import mdns
import math

class RData:
  def __str__(self) -> str:
    s = "<RData "
    for k in vars(self):
      s += '%s=%s ' % (k, getattr(self, k))
    return s + '|>' 

class OPT:
  def __init__(self, code=0, length=0, data=None) -> None:
    self.opcode = code
    self.oplength = length
    self.opdata = data
  
  def __str__(self) -> str:
    s = "<OPT "
    for k in vars(self):
      s += '%s=%s ' % (k, getattr(self, k))
    return s + '|>' 

def ip32bitstr(addr):
  ip = [0 for i in range(4)]
  ip[0] = str(math.floor(addr / 16777216))
  ip[1] = str(math.floor((addr / 65536) % 256))
  ip[2] = str(math.floor((addr / 256) % 256))
  ip[3] = str(addr % 256)
  return '.'.join(ip)

def kDNSType_A(data, offset, length) -> RData:
  rdata = RData()
  if length != 4:
    raise IndexError('Length != 4')

  ipAddr32Bit = mdns.u32(data, offset)
  setattr(rdata, 'addr', ip32bitstr(ipAddr32Bit))
  return rdata

def kDNSType_SRV(data, offset, length) -> RData:
  if length < 7:
    raise IndexError('len(data) < 7')
  
  rd = RData()
  setattr(rd, 'priority', mdns.u16(data, offset))
  setattr(rd, 'weight', mdns.u16(data, offset+2))
  setattr(rd, 'port', mdns.u16(data, offset+4))
  setattr(rd, 'target', mdns.get_qname(data, offset+6))
  return rd

def kDNSType_MemCpy(data, offset, length) -> RData:
  rd = RData()
  setattr(rd, 'payload', data[offset:offset+length])
  return rd

def kDNSType_OPT(data, offset, length) -> RData:
  if data[offset] != 0x00:
    raise IndexError('Not a Meta-RR!')
  
  record = mdns.ResourceRecord()
  index = offset + 1
  
  record.type = mdns.u16(data, index)
  index += 2
  record.clazz = mdns.u16(data, index)
  index += 2
  record.ttl = mdns.u32(data, index)
  index += 4

  dlen = mdns.u16(data, index)
  index += 2
  record.size = index + dlen
  record.rdlength = dlen

  rd = RData()
  opts = []
  while index < len(data):
    o = OPT(code=mdns.u16(data, index), length=mdns.u16(data, index+2))
    o.opdata = data[index+4:index+4+o.oplength]
    
    opts.append(o)
    index += 4 + o.oplength
  
  setattr(rd, 'options', opts)
  record.rdata = rd
  return record

def kDNSType_MX(data, offset, length) -> RData:
  return __kDNSType_PR_DN(data, offset, length)

def kDNSType_AFSDB(data, offset, length) -> RData:
  return __kDNSType_PR_DN(data, offset, length)

def kDNSType_RT(data, offset, length) -> RData:
  return __kDNSType_PR_DN(data, offset, length)

def kDNSType_KX(data, offset, length) -> RData:
  return __kDNSType_PR_DN(data, offset, length)

def __kDNSType_PR_DN(data, offset, length) -> RData:
  rd = RData()
  setattr(rd, 'preference', mdns.u16(data, offset))
  setattr(rd, 'target', mdns.get_qname(data, offset+2))
  return rd

def kDNSType_DN(data, offset, length, count=1, names=None) -> RData:
  index, name = mdns.get_qname(data, offset)

  rd = RData()
  setattr(rd, 'name', name)
  if count > 1:
    __index = index
    for i in range(1, count):
      i2, name = mdns.get_qname(data, __index)
      __index = i2
      setattr(rd, names[i-1], name)
  return rd

def kDNSType_SOA(data, offset, length) -> RData:
  rd = RData()
  
  index, mname = mdns.get_qname(data, offset)
  i2, rname = mdns.get_qname(data, index)

  setattr(rd, 'mname', mname)
  setattr(rd, 'rname', rname)
  setattr(rd, 'serial', mdns.u32(data, i2))
  setattr(rd, 'refresh', mdns.u32(data, i2+4))
  setattr(rd, 'retry', mdns.u32(data, i2+8))
  setattr(rd, 'expire', mdns.u32(data, i2+12))
  setattr(rd, 'minimum', mdns.u32(data, i2+16))

def kDNSType_HINFO(data, offset, length) -> RData:
  cpu_len = mdns.u8(data, offset)
  if cpu_len + 1 > length:
    raise IndexError('Malformed CPU-String')
  
  rd = RData()
  
  index = offset + 1
  setattr(rd, 'cpu', data[index:index+cpu_len])
  index += cpu_len

  os_len = mdns.u8(data, index)
  if os_len + 1 > length:
    raise IndexError('Malformed OS-String')

  index += 1
  setattr(rd, 'cpu', data[index:index+os_len])
  return rd

def kDNSType_MINFO(data, offset, length) -> RData:
  return kDNSType_DN(data, offset, length, count=2, names=["emailbx"])

def kDNSType_RP(data, offset, length) -> RData:
  return kDNSType_DN(data, offset, length, count=2, names=["other"])

def kDNSType_PX(data, offset, length) -> RData:
  pr = mdns.u16(data, offset)
  rd = kDNSType_DN(data, offset+2, length, count=2, names=["other"])
  setattr(rd, 'preference', pr)
  return rd

def kDNSType_NSEC(data, offset, length) -> RData:
  index, name = mdns.get_qname(data, offset)
  rd = RData()

  setattr(rd, 'next_dn', name)
  bmp_window_block = mdns.u8(data, index) & 1
  bmp_len = mdns.u8(data, index+1)

  bmp = data[index+2:index+2+bmp_len]
  bmp_types = []
  counter = 0
  for i in range(bmp_len):
    for shift in range(7, 0, -1):
      _type = 1 << shift
      if bmp[i] & _type != 0:
        dns_rr_type = mdns.DNS_TypeValues[counter]
        bmp_types.append(dns_rr_type[:2])
      counter += 1
    counter += 1

  setattr(rd, 'bitmap', bmp)
  setattr(rd, 'bitmap_len', bmp_len)
  setattr(rd, 'bmp_wblock', bmp_window_block)
  setattr(rd, 'bitmap_types', bmp_types)
  return rd

def kDNSType_AAAA(data, offset, length) -> RData:
  ipv6 = ['' for i in range(8)]
  index = 0
  for i in range(8):
    x = mdns.u16(data, offset+index)
    if x != 0:
      ipv6[i] = hex(x)[2:]
    index += 2
  
  rd = RData()
  setattr(rd, 'addr', ':'.join(ipv6).replace('::', ':'))
  return rd

