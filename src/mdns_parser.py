import sys
import socket


from argparse import ArgumentParser
from protocol import mdns, _analyzing

hhosts = socket.gethostbyname_ex(socket.gethostname())[2]
i = int(input('%s\n[*] Choose your address: ' % (str(hhosts))))
host_address = hhosts[i]

try:
    client = mdns.MulticastDNSListener(address=host_address)
except Exception as e:
    print('[!] Error: %s' % (e))
    sys.exit(-1)

parser = mdns.mDNSParser()
receiver = _analyzing.PacketReceiver(parser)

print("[*] Receiving packets on host: %s " % (host_address))
print(_analyzing.TABLE_HEADER)
try:
    client.listen(p=receiver.handle)
except KeyboardInterrupt:
    packets = receiver.packets
    print("\n[*] Captured %d packet(s)" %  (len(packets)))
    if len(packets) > 0:
        addr = {}
        for num, a, packet in packets:
            if a[0] in addr:
                addr[a[0]] += 1
            else:
                addr.setdefault(a[0], 1)
            
        print(" Address           No. of packets")
        for k in addr:
            x = str(k); y = str(addr[k])
            if len(x) == 13:
                x += ' '*2
            elif len(x) == 14:
                x += ' '
            print(' ' + ''.join([x, ' '*6, y]))
    
while True:
    print('\n[*] Press ^C to end process or choose packet to analyze:')
    i = int(input('--> '))

    #TODO