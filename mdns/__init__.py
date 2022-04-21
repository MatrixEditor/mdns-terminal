####################################################
# Data-Types
####################################################
def u16(data, offset: int = 0):
  return (data[offset] << 8) | data[offset+1]

def u8(data, offset: int = 0):
  return int(data[offset])

def u32(data, offset: int = 0):
  return (data[offset] << 24) | (data[offset+1] << 16) | (data[offset+2] << 8) | data[offset+3]

####################################################
# DNS-Definitions
####################################################
from . import _dnstypes as types
from . import _stdrr as std_rr

DNS_TypeValues = {
  1: ('A', 'host Address', std_rr.kDNSType_A),
  2: ('NS', 'authoritative Name Server', std_rr.kDNSType_DN),
  3: ('MD', 'Mail Destination', std_rr.kDNSType_DN),
  4: ('MF', 'Mail Forwarder', std_rr.kDNSType_DN),
  5: ('CNAME', 'Canonical Name', std_rr.kDNSType_DN),
  6: ('SOA', 'Start of Authority', std_rr.kDNSType_SOA),
  7: ('MB', 'Mailbox', std_rr.kDNSType_DN),
  8: ('MG', 'Mail Group', std_rr.kDNSType_DN),
  9: ('MR', 'Mail Rename', std_rr.kDNSType_DN),
  10: ('NULL', 'Null RR', std_rr.kDNSType_MemCpy),
  11: ('WKS', 'Well-Known-Service', std_rr.kDNSType_MemCpy),
  12: ('PTR', 'Domain name PoinTeR', std_rr.kDNSType_DN),
  13: ('HINFO', 'Host INFOrmation', std_rr.kDNSType_HINFO),
  14: ('MINFO', 'Mailbox INFOrmation', std_rr.kDNSType_MINFO),
  15: ('MX', 'Mail eXchanger', std_rr.kDNSType_MX),
  16: ('TXT', 'Arbitrary text string', std_rr.kDNSType_MemCpy),
  17: ('RP', 'Responsible person', std_rr.kDNSType_RP),
  18: ('AFSDB', 'AFS cell database', std_rr.kDNSType_AFSDB),
  19: ('X25', 'X_25 calling address', std_rr.kDNSType_MemCpy),
  20: ('ISDN', 'ISDN calling address', std_rr.kDNSType_MemCpy),
  21: ('RT', 'Router', std_rr.kDNSType_RT),
  22: ('NSAP', 'NSAP Address', std_rr.kDNSType_MemCpy),
  23: ('NSAP_PTR', 'Reverse NSAP lookup (deprecated)', std_rr.kDNSType_DN),
  24: ('SIG', 'Security signature', std_rr.kDNSType_MemCpy),
  25: ('KEY', 'Security key', std_rr.kDNSType_MemCpy),
  26: ('PX', 'X.400 mail mapping', std_rr.kDNSType_PX),
  27: ('GPOS', 'Geographical position (withdrawn)', std_rr.kDNSType_MemCpy),
  28: ('AAAA', 'IPv6 Address', std_rr.kDNSType_AAAA),
  29: ('LOC', 'Location Information', std_rr.kDNSType_MemCpy),
  30: ('NXT', 'Next domain (security)', std_rr.kDNSType_MemCpy),
  31: ('EID', 'Endpoint identifier', std_rr.kDNSType_MemCpy),
  32: ('NIMLOC', 'Nimrod Locator', std_rr.kDNSType_MemCpy),
  33: ('SRV', 'Service record', std_rr.kDNSType_SRV),
  34: ('ATMA', 'ATM Address', std_rr.kDNSType_MemCpy),
  35: ('NAPTR', 'Naming Authority PoinTeR', std_rr.kDNSType_MemCpy),
  36: ('KX', 'Key Exchange', std_rr.kDNSType_KX),
  37: ('CERT', 'Certification record', std_rr.kDNSType_MemCpy),
  38: ('A6', 'IPv6 Address (deprecated)', std_rr.kDNSType_MemCpy),
  39: ('DNAME', 'Non-terminal DNAME (for IPv6)', std_rr.kDNSType_DN),
  40: ('SINK', 'Kitchen sink (experimental)', std_rr.kDNSType_MemCpy),
  41: ('OPT', 'EDNS0 option (meta-RR)', std_rr.kDNSType_OPT),
  42: ('APL', 'Address Prefix List', std_rr.kDNSType_MemCpy),
  43: ('DS', 'Delegation Signer', std_rr.kDNSType_MemCpy),
  44: ('SSHFP', 'SSH Key Fingerprint', std_rr.kDNSType_MemCpy),
  45: ('IPSECKEY', 'IPSECKEY', std_rr.kDNSType_MemCpy),
  46: ('RRSIG', 'RRSIG', std_rr.kDNSType_MemCpy),
  47: ('NSEC', 'Denial of Existence', std_rr.kDNSType_NSEC),
  48: ('DNSKEY', 'DNSKEY', std_rr.kDNSType_MemCpy),
  49: ('DHCID', 'DHCP Client Identifier', std_rr.kDNSType_MemCpy),
  50: ('NSEC3', 'Hashed Authenticated Denial of Existence', std_rr.kDNSType_MemCpy),
  51: ('NSEC3PARAM', 'Hashed Authenticated Denial of Existence', std_rr.kDNSType_MemCpy),

  55: ('HIP', 'Host Identity Protocol', std_rr.kDNSType_MemCpy),

  64: ('SVCB', 'Service Binding', std_rr.kDNSType_MemCpy),
  65: ('HTTPS', 'HTTPS Service Binding', std_rr.kDNSType_MemCpy),
  
  99: ('SPF', 'Sender Policy Framework for E-Mail', std_rr.kDNSType_MemCpy),
  100: ('UINFO', 'IANA-Reserved', std_rr.kDNSType_MemCpy),
  101: ('UID', 'IANA-Reserved', std_rr.kDNSType_MemCpy),
  102: ('GID', 'IANA-Reserved', std_rr.kDNSType_MemCpy),
  103: ('UNSPEC', 'IANA-Reserved', std_rr.kDNSType_MemCpy),
  
  249: ('TKEY', 'Transaction key', std_rr.kDNSType_MemCpy),
  250: ('TSIG', 'Transaction signature', std_rr.kDNSType_MemCpy),
  251: ('IXFR', 'Transaction zone transfer', std_rr.kDNSType_MemCpy),
  252: ('AXFR', 'Transfer zone of authority', std_rr.kDNSType_MemCpy),
  253: ('MAILB', 'Transfer mailbox records', std_rr.kDNSType_MemCpy),
  254: ('MAILA', 'Transfer mail agent records', std_rr.kDNSType_MemCpy),
  255: ('Any', '*', std_rr.kDNSType_MemCpy),
}

DNS_ClassValues = {
  types.DNS_CLASS_IN: ('IN', 'Internet'),
  types.DNS_CLASS_CS: ('CS', 'CSNET'),
  types.DNS_CLASS_CH: ('CH', 'CHAOS'),
  types.DNS_CLASS_HS: ('HS', 'Hesiod'),
  types.DNS_CLASS_NONE: ('NONE', ''),

  types.DNS_QCLASS_ANY: ('Any', 'Not a DNS class, but a DNS query class, meaning "all classes"')
}

####################################################
# Module-Definitions
####################################################
from ._rr import (
  get_query,
  get_resource,
  get_txt,
  get_qname,
  Query,
  ResourceRecord,
  DomainName
)

from ._mDNSCommon import (
  loadm,
  buildm,
  buildq,
  to_bytes,
  DNSMessage,
  DNSMessageHeader
)

from ._mDNS import (
  handler,
  startup,
  sendN,
  MDNS_SOCKET
)