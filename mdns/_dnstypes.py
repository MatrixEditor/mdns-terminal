####################################################
# DNS-Classes
####################################################
DNS_CLASS_IN = 1
DNS_CLASS_CS = 2
DNS_CLASS_CH = 3
DNS_CLASS_HS = 4
DNS_CLASS_NONE = 254

DNS_QCLASS_ANY = 255

DNS_CLASS_URR = 0x8000
DNS_QCLASS_UR = 0x8000

####################################################
# Error states
####################################################
mStatus_Waiting = 1
mStatus_NoError = 0
mStatus_UnknownErr = 0xFFFF

####################################################
# DNS-Flags
####################################################
FLAG_QR     = 0b1000000000000000
FLAG_OPCODE = 0b0111100000000000
FLAG_AA_BIT = 0b0000010000000000
FLAG_TC_BIT = 0b0000001000000000
FLAG_RD_BIT = 0b0000000100000000
FLAG_RA_BIT = 0b0000000010000000
FLAG_Z_BIT  = 0b0000000001000000
FLAG_AD_BIT = 0b0000000000100000
FLAG_CD_BIT = 0b0000000000010000
FLAG_RCODE  = 0b0000000000001111


# the standard multicast ipv4-address
MDNS_IPV4_MCAST_IP = '224.0.0.251'

# the standard multicast ipv6-address
MDNS_IPV6_MCAST_IP = 'ff02::fb'