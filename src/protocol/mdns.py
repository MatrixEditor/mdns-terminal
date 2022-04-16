import socket
import struct

# The header has always a fixed length of 12 bytes
MDNS_HEADER_LENGTH = 12

# below all types of mdns response-messages are listed:
# Type A (host address)
TYPE_A = 1
# PTR-Records (domain name pointer)
TYPE_PTR = 12
# TXT text strings
TYPE_TXT = 16
# IPv6 address
TYPE_AAAA = 28
# Server Selection
TYPE_SRV = 33
# in records defined
TYPE_OPT = 41
# also only in records defined (Next SECure)
TYPE_NSEC = 47
# request for all records
TYPE_ALL = 255

# below all packet attributes (The tuple was indentionally added
# to make printing easier)
PK_TRANSACTION_ID = ('dns.id', 'Transaction ID')
PK_FLAGS_RCODE = ('dns.flags.rcode', 'Flags')
PK_QUERIES = ('dns.count.queries', 'Queries')
PK_ANSWERS = ('dns.count.awnsers', 'Awnser RRs')
PK_AUTH_RR = ('dns.count.auth_rr', 'Authority RRs')
PK_ADD_RR = ('dns.count.add_rr', 'Additional RRs')

# below the constants for the awnser section
AS_NAME = ('dns.resp.name', 'Name')
AS_TYPE = ('dns.resp.type', 'Type')
AS_TTL = ('dns.resp.ttl', 'Time to live')
AS_DATA_LENGTH = ('dns.resp.len', 'Data Length')
AS_CACHE_FLUSH = ('dns.resp.cache_flush', 'Cache Flush')

# custom properties for each response type
PTR_DOMAIN_NAME = ('dns.ptr.domain_name', 'Domain Name')
SRV_PRIORITY = ('dns.srv.priority', 'Priority')
SRV_WEIGHT = ('dns.srv.weight', 'Weight')
SRV_PORT = ('dns.srv.port', 'Port')
SRV_TARGET = ('dns.srv.target', 'Target')
TXT_DATA = ('dns.txt', 'Text')
TXT_LENGTH = ('den.txt.length', 'Text Length')
A_ADDRESS = ('dns.a', 'Address')
AAAA_ADRESS = ('dns.aaaa', 'IPv6 Address')

# constants for query section
QRY_NAME = ('dns.qry.name', 'Name')
QRY_TYPE = ('dns.qry.type', 'Type')
QRY_QU = ('dns.qry.qu', 'QU')
QRY_DATA = ('dns.qry.data', 'Data')

# record constants
RC_TYPE = ('dns.rc.type', 'Type')
RC_NAME = ('dns.rc.name', 'Name')
RC_DATA = ('dns.rc.data', 'Data')
RC_TTL = ('dns.rc.ttl', 'Time to live')
RC_CACHE_FLUSH = ('dns.rc.cflush', 'Cache Flush')
RC_PAYLOAD_SIZE = ('dns.rc.payload_size', 'Payload Size')
RC_RCODE = ('dns.rc.rcode', 'RCODE')
RC_EDNS = ('dns.rc.edns', 'EDNS0')
RC_OPTION_CODE = ('dns.rc.option.code', 'Option Code')
RC_OPTION_LENGTH = ('dns.rc.option.length', 'Option Length')
RC_OPTION_DATA = ('dns.rc.option.data', 'Option Data')

# the standard multicast ipv4-address
IPV4_MCAST_IP = '224.0.0.251'

# the standard multicast ipv6-address
IPV6_MCAST_IP = 'ff02::fb'

# the standard port (two times the DNS port [DNS port: 53])
MDNS_PORT = 5353

# section name constants:
QUERIES = 'Queries'
ANSWERS = 'Answers'
AUTH = 'Auth'
RECORDS = 'Records'
OPTION = 'Optionwir'
HEADER = 'header'
BODY = 'body'

# ------------ utility methods ------------
def hexof(_bytes: list) -> str:
    '''
    Returns a printable hex-version of the given bytes. A possible 
    output could be: \n
        from '\\x0\\x32\\x56\\xe7'
        to '0x003256e7'
    '''
    a = ''
    for b in _bytes:
        h = hex(b)
        if h == '0x0':
            if len(a) == 0:
                a += '0x00'
            else:
                a += '00'
        else:
            if len(a) == 0:
                a += h
            else:
                a += h[2:]
    return a

def __sum__(data: list) -> int:
    # the origional sum method threw errors on my machine
    # so here is an own dirty implementation of sum
    i = 0
    for x in data:
        i += x
    return i

def __resolve__(data) -> tuple:
    '''
    Referring to the rfc-article 6762 page 62:

    >>> Format:
                                                  ------
                                                 | 0x00 |   length = 0
                                                  ------
    >>> 
                             ------------------   ------
                            | 0x03 | o | r | g | | 0x00 |   length = 4
                             ------------------   ------
    >>> 
      -----------------------------------------   ------
     | 0x04 | i | e | t | f | 0x03 | o | r | g | | 0x00 |   length = 9
      -----------------------------------------   ------

    ----------------------------------------------------
    Here is defined how the namespaced in mdns packets 
    should be resolved. In some cases there wasn't the 
    multicast domain name given and just two bytes are 
    delivered. When looking at these two bytes the first 
    one was always \\xc0 or 0xc0. 
    '''
    if data[0] == 0xc0:
        return (hexof(data[:2])[2:], 2)

    index = 0
    name = []
    while True:
        if data[index] == 0x00:
            break
        # In some cases there was a \xc0 byte in 
        # the text which also indicates a previous 
        # usage of that specific domain name
        elif data[index] == 0xc0:
            name.append('c0...'); index += 1
            break
        _len = struct.unpack('!B', data[index:index+1])[0]
        index += 1
        x = data[index:index+_len]
        try:
            name.append(str(x, 'utf-8'))
        except:
            pass
        index += _len

    return ('.'.join(name), index + 1)

# ------------ classes ------------
class mDNSParser:

    def mdns_frame(self, _bytes):
        # the first bytes contain the domain name
        dns_resp_name, current_index = __resolve__(data=_bytes)
        # after that, the next two bytes contain the response type 
        # (either 0x0000 or 0x8400)
        dns_resp_type = __sum__(_bytes[current_index:current_index+2])
        cache_flush = hexof(_bytes[current_index + 2: current_index + 4])
        current_index += 4
        # the time to live is packed in four
        x =  _bytes[current_index:current_index+4] # debugging reasons
        ttl = __sum__(struct.unpack('!H H', x))
        current_index += 4
        # finally, the payload length is given within two bytes
        length = struct.unpack('!H', _bytes[current_index:current_index+2])[0]
        return dns_resp_name, dns_resp_type, cache_flush, ttl, length, current_index+2

    def convert_text(self, i, data):
        # converts a text section by first reading the length
        # of the section and reads this amount of bytes afterwards.
        txt_data = []
        while True:
            if i >= len(data):
                break
            _len = struct.unpack('!B', data[i:i+1])[0]
            i += 1
            txt_data.append(['', _len])
            for b in data[i:i+_len]:
                if 32 <= b <= 176:
                    txt_data[len(txt_data) - 1][0] += chr(b)
            i += _len;
        return txt_data

    def parse(self, data, addr) -> dict:
        try:
            header = {}
            body = {}

            header.setdefault(PK_TRANSACTION_ID[0], hexof(data[:2]))
            # The following values indicate how much data is defined
            # in every category. 
            questions, rr_awnser, rr_authority, rr_additional = struct.unpack('!H H H H', data[4:12])
        
            header.setdefault(PK_FLAGS_RCODE[0], hexof(data[2:4]))
            header.setdefault(PK_QUERIES[0], questions)
            header.setdefault(PK_ANSWERS[0], rr_awnser)
            header.setdefault(PK_AUTH_RR[0], rr_authority)
            header.setdefault(PK_ADD_RR[0], rr_additional)

            data = data[MDNS_HEADER_LENGTH:]
            body.setdefault(QUERIES, [])
            for i in range(questions):
                # In a Query-section there are some additional fields that
                # contain some data. The Domain-name has a variable length
                # so we have to use the '__resolvedn__'-method. After that
                # a response type is specified (see values at start of code).
                # The next field contains a flag that indicates the method 
                # of the qustion. At last, there is raw data displayed if 
                # mapped.
                name, index = __resolve__(data=data)
                type_ = __sum__(struct.unpack('!H', data[index: index + 2]))
                qu = hexof(data[index+2:index+4])
                data = data[index+4:]

                body[QUERIES].append(
                    {QRY_NAME[0]: name,QRY_TYPE[0]: type_, QRY_QU[0]: qu, QRY_DATA[0]: data})
            
            body.setdefault(ANSWERS, [])
            for i in range(rr_awnser):
                rsp_name, rsp_type, cflush, ttl, length, i = self.mdns_frame(data)

                info = {AS_NAME[0]: rsp_name, AS_TYPE[0]: rsp_type, AS_CACHE_FLUSH[0]: cflush,
                AS_TTL[0]: ttl, AS_DATA_LENGTH[0]: length}
                # The different response types contain different fields so
                # every type needs an implementation:
                # the domain name pointer just contains the domain name
                if rsp_type == TYPE_PTR:
                    d_name, _q = __resolve__(data=data[i:i+length])
                    info.setdefault(PTR_DOMAIN_NAME[0], d_name)
                    i += length
                # the server selection contains a target, priority, 
                # weight and port
                elif rsp_type == TYPE_SRV:
                    priority, weight, port = struct.unpack('!H H H', data[i:i+6])
                    i += 6
                    target, _q = __resolve__(data=data[i:i + (length - 6)])
                    info.setdefault(SRV_PRIORITY[0], priority)
                    info.setdefault(SRV_WEIGHT[0], weight)
                    info.setdefault(SRV_TARGET[0], target)
                    info.setdefault(SRV_PORT[0], port)
                    i += (length - 6)
                # this message usually just contains the host address
                elif rsp_type == TYPE_A:
                    x = data[i:i+4]
                    address = '.'.join([str(y) for y in struct.unpack('!B B B B', x)])
                    info.setdefault(A_ADDRESS[0], address)
                    i += length
                # TODO parse ipv6
                elif rsp_type == TYPE_AAAA:
                    i += length
                    info.setdefault(AAAA_ADRESS[0], 'ffff::ff')
                    pass
                elif rsp_type == TYPE_TXT:
                    x = data[i:length]
                    txt_data = self.convert_text(i=0, data=x)
                    i += length
                    info.setdefault(TXT_DATA[0], txt_data)

                body[ANSWERS].append(info)
                # Don't forget to slice the data (current index 'i' important)
                data = data[i:]

            # I didn't see such an auth-fragment in one of the mdns-packets
            # its rather commonly used in DNS-packets
            body.setdefault(AUTH, [])
            for i in range(rr_authority):
                _name, index = __resolve__(data=data)
                data = data[index:]
                _type, _class = struct.unpack('!H H', data[:4])
                _ttl = __sum__(struct.unpack('!H H', data[4:8]))

                length = struct.unpack('!H', data[8:10])[0]
                x = data[10:10+length]
                # important to set this
                data = data[10+length:] 

            body.setdefault(RECORDS, [])
            for i in range(rr_additional):
                additional = {}
                # there are two cases I saw in mDNS-packets:
                #   1: there was a fully qualified domain name
                #   2: the byte 0x00 indicated no name at the beginning 
                #       (TYPE_OPT <41>)
                if data[0] != 0x00:
                    # Name length could be different
                    _name, index = __resolve__(data)
                    data = data[index:]
                    # type is important but in records with defined domain 
                    # name there wasn't anything else than TYPE_NSEC
                    _type = struct.unpack('!H', data[:2])[0]
                    additional.setdefault(RC_NAME[0], _name)
                    additional.setdefault(RC_TYPE[0], _type)

                    if _type == TYPE_NSEC:
                        # here we got the cache flush another time and the TTL
                        cflush = hexof(data[2:4])
                        _ttl = __sum__(struct.unpack('!H H', data[4:8]))

                        # usually after the length field there is a domain name 
                        # and a RR type 
                        length = struct.unpack('!H', data[8:10])[0]
                        x = data[10:10+length]
                        data = data[10+length:]
                        additional.setdefault(RC_CACHE_FLUSH[0], cflush)
                        additional.setdefault(RC_TTL[0], _ttl)
                        additional.setdefault(RC_DATA[0], hexof(x)[2:])
                else:
                    # the name only consits of the first byte
                    _name = hex(data[0])[2:]
                    data = data[1:]
                    # then a type is defined (always TYPE_OPT)
                    _type = struct.unpack('!H', data[:2])[0]
                    _p_size = hexof(data[2:4])
                    additional.setdefault(RC_NAME[0], _name)
                    additional.setdefault(RC_TYPE[0], _type)
                    additional.setdefault(RC_PAYLOAD_SIZE[0], _p_size)

                    if _type == TYPE_OPT: 
                        # this type contains the üayload size, a strange rcode,
                        # also a strange value named z and the Extended DNS version
                        _rcode = hex(data[5])
                        _edns = struct.unpack('!B', data[6:7])[0]
                        _z = hexof(data[7:9])

                        # last but not least the data provided as an option is given
                        length = struct.unpack('!H', data[10:12])[0]
                        x = data[12:12+length]

                        op_code, op_length = struct.unpack('!H H', x[:4])
                        op_data = hexof(x[4:])[2:]
                        data = data[12+length:]
                        # now put everything together
                        additional.setdefault(RC_RCODE[0], _rcode)
                        additional.setdefault(RC_EDNS[0], _edns)
                        additional.setdefault('Z', _z)
                        additional.setdefault(OPTION, {RC_OPTION_CODE[0]: op_code,
                        RC_OPTION_LENGTH[0]: op_length, RC_OPTION_DATA[0]: op_data})
            
            return {HEADER: header, BODY: body}
        except Exception:
            # raisuíng an exception could be fatal while capturing
            #raise ParsingException()
            return {HEADER: header, BODY: body}

class ParsingException(Exception):
    pass

class MulticastDNSListener:
    def __init__(self, proto='ipv4', address=None, broadcast_ip=None) -> None:
        self.stopped = False

        if proto not in ('ipv4', 'ipv6'):
            raise ValueError("Invalid proto - expected one of {}".format(('ipv4', 'ipv6')))

        if proto == 'ipv4':
            self._af_type = socket.AF_INET
            self._broadcast_ip = IPV4_MCAST_IP if not broadcast_ip else broadcast_ip
            self._address = (self._broadcast_ip, MDNS_PORT)
            bind_address = "0.0.0.0"
        elif proto == "ipv6":
            self._af_type = socket.AF_INET6
            self._broadcast_ip = IPV6_MCAST_IP if not broadcast_ip else broadcast_ip
            self._address = (self._broadcast_ip, MDNS_PORT, 0, 0)
            bind_address = "::"

        self.sock = socket.socket(self._af_type, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if proto == 'ipv4':
            mreq = socket.inet_aton(self._broadcast_ip)
            if address is not None:
                mreq += socket.inet_aton(address)
            else:
                mreq += struct.pack(b"@I", socket.INADDR_ANY)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq,)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1) 
        elif proto == "ipv6":
            mreq = socket.inet_pton(socket.AF_INET6, self._broadcast_ip)
            mreq += socket.inet_pton(socket.AF_INET6, "::")
            self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq,)
            self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)
        self.sock.bind((bind_address, MDNS_PORT))

    def on_recv(self, data, addr):
        pass

    def bsend(self, msg) -> int:
        self.sock.sendto(msg, self._address)

    def foreach(self):
        try:
            while not self.stopped:
                data, address = self.sock.recvfrom(2048)
                yield (data, address)
        except KeyboardInterrupt or ParsingException or socket.timeout:
            pass
        except Exception:
            self.sock.close()
            raise
        finally:
            self.sock.close()

    def listen(self, p=on_recv):
        try:
            while not self.stopped:
                data, address = self.sock.recvfrom(2048)
                p(data, address)
        except KeyboardInterrupt or ParsingException or socket.timeout:
            pass
        except Exception:
            self.sock.close()
            raise
        finally:
            self.sock.close()

    def close(self):
        self.sock.close()
