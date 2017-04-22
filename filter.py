import pydivert
from pydivert import windivert_dll

# Whats available to modify in packets: 
"""
Packet({'direction': <Direction.OUTBOUND: 0>,
 'dst_addr': '10.0.0.25',
 'dst_port': 1234,
 'icmpv4': None,
 'icmpv6': None,
 'interface': (21L, 0L),
 'ipv4': {'cksum': 45575,
          'df': True,
          'diff_serv': 0,
          'dscp': 0,
          'dst_addr': '10.0.0.25',
          'ecn': 0,
          'evil': False,
          'flags': 2,
          'frag_offset': 0,
          'hdr_len': 5,
          'header_len': 20,
          'ident': 29853,
          'mf': False,
          'packet_len': 52,
          'raw': <memory at 0x0000000003DECAF8>,
          'reserved': False,
          'src_addr': '10.0.0.7',
          'tos': 0,
          'ttl': 64},
 'ipv6': None,
 'is_inbound': False,
 'is_loopback': False,
 'is_outbound': True,
 'payload': '',
 'raw': <memory at 0x0000000003DECB88>,
 'src_addr': '10.0.0.7',
 'src_port': 51248,
 'tcp': {'ack': False,
         'ack_num': 0,
         'cksum': 26893,
         'control_bits': 2,
         'cwr': False,
         'data_offset': 8,
         'dst_port': 1234,
         'ece': False,
         'fin': False,
         'header_len': 32,
         'ns': False,
         'payload': '',
         'psh': False,
         'raw': <memory at 0x0000000003DECC18>,
         'reserved': 0,
         'rst': False,
         'seq_num': 3250407063L,
         'src_port': 51248,
         'syn': True,
         'urg': False,
         'urg_ptr': 0,
         'window_size': 8192},
 'udp': None})
"""

# TCP OPTIONS:
# 0 End of options list
# 1 NOP
# 2 MSS
# 3 Window Scale
# 4 Selective ACK ok
# 8 Timemstamp

# Make dict of decimal mss values to hex bytes
mssDict = {64:(b'\x02',b'\x40')}


def getMssIndex(options):
    """
    Returns index of MSS option

    Args:
        options: integer list of bytes in tcp header options
    """
    validOptions = [0, 1, 2, 3, 4, 8]
    i = 0
    # iterate to third to last index. If we dont see a 2 there we
    # never had one, return null
    while i < len(options) - 2:
        if options[i] == 1:
            i += 1
        elif options[i] in [3,4,8]:
            i += options[i+1]  # the byte indicating length
        elif options[i] == 2:
            return i
        elif options[i] == 0:
            return None

def main():
    print("Started d-divert")
    # It sucks that windivert filters like this. It would be cool if we 
    # could pass it a bpf like "port 1234" from the command line
    with pydivert.WinDivert("tcp.DstPort == 1234 or tcp.SrcPort == 1234") as w:
        for packet in w:
            print "got packet"
            if packet.src_addr == '10.0.0.25' or packet.dst_addr == '10.0.0.25':
                print (packet)
                packet.ipv4.ttl = 64

                # Look for syn packet. I think I read that mss is negotiated in 
                # handshake, or that fingerprinters typically only look at the handshake anyway
                if packet.tcp.syn is True and packet.tcp.ack is False :
                    print ("This is a syn packet, looking for options...")
                    
                    # If tcp header length > 20 then we have tcp options
                    if packet.tcp.header_len > 20:
                        # Get memory view object of tcp reader
                        mv = packet.tcp.raw
                        options = mv[20:]
                        print ("..options: " + str(options))
                        print (".. toBytes: " + str(options.tobytes()).encode('hex'))
                        print (".. toList: " + str(options.tolist()))
                        print (".. is this read only? " + str(options.readonly))  # we want to be able to write to this mem location
                        index = getMssIndex(options.tolist())

                        # set new mss
                        if index is not None:
                            print (".. writting 02 171 to options")
                            options[index+2] = mssDict[64][0]
                            options[index+3] = mssDict[64][1]
                            # options[index+3] = b'\x40'
                            print (".. options toBytes: " + str(options.tobytes()).encode('hex'))
                
            # No need to recalc checksum, send does it for us.
            w.send(packet)

if __name__ == "__main__":
    main()
