import mdns

# This method will handle every incoming MDNS packet
# on port 5353. A filter can be applied in this method.
@mdns.handler
def packet_handler(packet, addr):
  print(packet, '\n')

if __name__ == '__main__':
  # Starting the network listener with a packet-capture
  # limit of 5 packets in total.
  mdns.startup(count=5)

  # EXAMPLE: build a query
  message = mdns.buildm(questions=[mdns.buildq("some.domain.name")])
  data = bytearray()

  mdns.to_bytes(message, data)
  mdns.sendN(data)
