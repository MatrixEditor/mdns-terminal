import mdns
import socket
import struct
import threading

HANDLERS = []

def handler(func):
  if func not in HANDLERS:
    HANDLERS.append(func)
  return func

class dnssocket:
  def __init__(self, proto='ipv4', address=None, broadcast_ip=None) -> None:
    if proto not in ('ipv4', 'ipv6'):
      raise ValueError("Invalid proto - expected one of {}".format(('ipv4', 'ipv6')))

    self._af_type = socket.AF_INET if proto == 'ipv4' else socket.AF_INET6
    self.sock = socket.socket(self._af_type, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if proto == 'ipv4':
      self._broadcast_ip = mdns.types.MDNS_IPV4_MCAST_IP if not broadcast_ip else broadcast_ip
      self._address = (self._broadcast_ip, 5353)
      bind_address = "0.0.0.0"
      mreq = socket.inet_aton(self._broadcast_ip)
      if address is not None:
          mreq += socket.inet_aton(address)
      else:
          mreq += struct.pack(b"@I", socket.INADDR_ANY)
      self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq,)
      self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1) 

    elif proto == "ipv6":
      self._broadcast_ip = mdns.types.MDNS_IPV6_MCAST_IP if not broadcast_ip else broadcast_ip
      self._address = (self._broadcast_ip, 5353, 0, 0)
      mreq = socket.inet_pton(socket.AF_INET6, self._broadcast_ip)
      mreq += socket.inet_pton(socket.AF_INET6, "::")
      self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq,)
      self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)
      bind_address = "::"

    self.sock.bind((bind_address, 5353)) 

MDNS_SOCKET = dnssocket()

def sendN(data, s=MDNS_SOCKET):
  return s.sock.sendto(data, s._address)

def startup(s=MDNS_SOCKET, count=-1):
  th = threading.Thread(target=__thread_delegate, args=(s, count))
  th.start()

def __thread_delegate(s=MDNS_SOCKET, count=-1):
  try:
    c = 0
    while c < count and count > 0:
      data, address = s.sock.recvfrom(1024)
      packet = mdns.loadm(data)
      __delegate_exec(packet, address)
      c += 1
  except Exception as e:
    print('Stopped at <Exception e="%s" |>' % (e))

def __delegate_exec(packet, addr):
  for _h in HANDLERS:
    try:
      _h(packet, addr)
    except:
      pass

