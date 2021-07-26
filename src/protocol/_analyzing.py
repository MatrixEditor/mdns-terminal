from protocol.mdns import *

_types = [(TYPE_A, 'A'), (TYPE_AAAA, 'AAAA'), (TYPE_ALL, '*'),
        (TYPE_PTR, 'PTR'), (TYPE_SRV, 'SRV'), (TYPE_TXT, 'TXT'), (TYPE_OPT, 'OPT')]

TABLE_HEADER = ' No.   Source            Destination   Port   Data'
TABLE_TEMPLATE = ' %s   %s   224.0.0.251   5353   %s'

class PacketReceiver:
    def __init__(self, psr) -> None:
        self.c = 0
        self.packets = []
        self.psr = psr

    def handle(self, data, addr):
        qu_data = self.psr.parse(data=data, addr=addr)
        self.c += 1
        host = addr[0]
        
        if len(host) == 14:
            host += ' '
        elif len(host) == 13:
            host += ' '*2
        
        num = str(self.c)
        if self.c < 100:
            num += ' '
        if self.c < 10:
            num += ' '

        data_str = self.analyze_data(qu_data)
        
        print(TABLE_TEMPLATE % (num, host, data_str))
        self.packets.append((num, addr, qu_data))

    def analyze_data(self, data: dict):
        s = ''
        header = data[HEADER]
        if str(header[PK_FLAGS_RCODE[0]]) == '0x8400':
            s += 'Standard query response %s, ' % (str(header[PK_TRANSACTION_ID[0]]))
        else:
            s += 'Standard query %s, ' % (header[PK_TRANSACTION_ID[0]])

        queries = data[BODY][QUERIES]
        answers = data[BODY][ANSWERS]

        def typeof(t):
            for n, v in _types:
                if n == t:
                    return v 
            return 'NONE'
        
        if len(queries) > 0:
            q = queries[0]; l = [typeof(q[QRY_TYPE[0]]), q[QRY_NAME[0]]]
           
            if str(q[QRY_QU[0]]) == '0x801':
                s += '"QU" question '
            else:
                s += '"QM" question '
            s += ' '.join([str(x) for x in l]) + ', '
        elif len(answers) > 0:
            a = answers[0]
            s += ' '.join([str(x) for x in [typeof(a[AS_TYPE[0]]), a[AS_NAME[0]]]]) + ', '

        records = data[BODY][RECORDS]
        if len(records) > 0:
            r = records[0]
            if r[RC_TYPE[0]] == TYPE_OPT:
                s += ', question OPT '
            else:
                s += typeof(r[RC_TYPE[0]]) + ' '
            
        return s + '...'
