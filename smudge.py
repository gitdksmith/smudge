import pydivert


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
This is a syn packet, looking for options...
..options: <memory at 0x0000000003A74558>
.. toBytes: 020405b40103030801010402
.. toList: [2, 4, 5, 180, 1, 3, 3, 8, 1, 1, 4, 2]
.. is this read only? False
packet raw 450000344959400040069d5c0a0000070a000008ec0e04d203a86c760000000080022000da020000020405b40103030801010402
ip raw 450000344959400040069d5c0a0000070a000008ec0e04d203a86c760000000080022000da020000020405b40103030801010402
tcp raw ec0e04d203a86c760000000080022000da020000020405b40103030801010402
"""

# tsval sample: 08, 0a, 01 83 8a c2, 00 00 00 00
#              kind, len, tsval, tsreply

class Spoof:
    wildcard = "*"
    optionNameToByte = {'end':'00', 'nop':'01', 'mss':'02', 'ws':'03', 'sok':'04', 'ts':'08'}
    linuxDefOptVals = {'00':"", '01':"", '02':"0405b4", '03':"0307", '04':"02", '08':"0a01cad9bc00000000"}
    linuxSig = "*:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0" 

    def __init__(self, spoofType):
        if spoofType == "Linux":
            self.configure(self.linuxSig)

    def configure(self, sig):
        s = str.split(sig, ":")
        self.version = s[0]
        self.ttl = s[1]
        self.olen = s[2]
        self.mss = s[3]
        self.wsize_multiplier = str.split(str.split(s[4], ",")[0], "*")[1]
        self.wscale = str.split(s[4], ",")[1]
        self.olayout = [self.optionNameToByte[x] for x in str.split(s[5], ",")]
        self.quirks = str.split(s[6], ",")
        self.pclass = s[7]
        self.defOptVals = self.linuxDefOptVals


# Make dict of decimal mss values to hex bytes
mssDict = {64:(b'\x02',b'\x40')}

# Option name string to byte value
byteToOptName = {'00':'end', '01':'nop', '02':'mss', '03':'ws', '04':'sok', '08':'ts'}

# sig = ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass

# ver = ipv4 or ipv6 version
# olen = length of IPv4 options or IPv6 extension headers
# olayout = TCP options layout
# quirks = other properties observed in IP or TCP header, like "do not fragment", or "PUSH flag used"
# pclass = payload size classification: '0' for zero, '+' nonzero, '*' for any.

def spoofPacket(spoof, packet):
    rawBytes = str(packet.raw.tobytes()).encode('hex')
    print "phase 1 raw", rawBytes
    db = [rawBytes]
    # set all new tcp values except options here
    # Regarding:
    #   version - no value to set in packet object
    #   olen    - no value to set in packet object
    #             seems to always be 0 in the sigs anyway
    #   mss,scale,window_size
    #           - have to be set after parsing options
    if spoof.ttl != spoof.wildcard:
        packet.ipv4.ttl = int(spoof.ttl)
        # Do we need to set the ttl to ttl - 1 ?

    rawBytes = str(packet.raw.tobytes()).encode('hex')
    print "phase 2 raw", rawBytes
    db.append(rawBytes)

    # If tcp header length > 20 then we have tcp options
    if packet.tcp.header_len > 20:
        # Get memory view object of tcp reader
        mv = packet.tcp.raw
        options = mv[20:]
        oldOptionsBytes = str(options.tobytes()).encode('hex')
        if len(oldOptionsBytes) % 2 != 0:
            return

        # since we're parsing up options, grab the new wsize too
        newOptionsBytes, wsize = reorderOptions(oldOptionsBytes, spoof)
        rawBytes = str(packet.raw.tobytes()).encode('hex')
        print "phase 3 raw", rawBytes

        # Mss and Scale were set in reorderOptions. Set new window_size to match
        packet.tcp.window_size = wsize
        
        # set new header lenghts and data offset to match new options
        oldOptLen = len(oldOptionsBytes) / 2  # b/c counting num bytes, "5a" = one byte
        newOptLen = len(newOptionsBytes) / 2
        
        # No need to reset ipv4 packet len, updating the "raw" attributes will update it
        # But we do need to update tcp.data_offset, which will update tcp.header_len
        packet.tcp.data_offset = (packet.tcp.header_len - oldOptLen + newOptLen) / 4

        # replace bytes in tcp.raw
        print "find this:", oldOptionsBytes
        print "replace with:", newOptionsBytes
        fnd = oldOptionsBytes.decode('hex')
        rpc = newOptionsBytes.decode('hex')
        packet.tcp.raw = packet.tcp.raw.tobytes().replace(fnd, rpc)

        rawBytes = str(packet.raw.tobytes()).encode('hex')
        print "phase 4 raw", rawBytes
        db.append(rawBytes)

        # print all rawBytes seen so far together for easier comparison for debugging
        print ""
        print db[0]
        print db[1]
        print db[2]

        # print ("..options: " + str(options))
        # print (".. toBytes: " + str(options.tobytes()).encode('hex'))
        # print (".. toList: " + str(options.tolist()))
        # print (".. is this read only? " + str(options.readonly))  # we want to be able to write to this mem location


def reorderOptions(optionsBytes, spoof):
    """
    Returns: string representing new options to use in a packet.
                EX: newOptions "020405b40402080a000000000000000001030308"
             integer window size value
    """

    optionsList = [optionsBytes[i:i + 2] for i in range(0, len(optionsBytes), 2)]
    print "parsed options", optionsList

    # make a dict of option title byte to list of other bytes that go with it
    # ignore nops
    optionsDict = dict()
    i = 0
    while i < (len(optionsList) - 1): # get to 2nd to last byte since we will be reading ahead or its a nop/end
        if optionsList[i] in byteToOptName:
            if optionsList[i] == '01':
                i += 1
            elif optionsList[i] == '00':
                # end of options
                break
            else:
                command = optionsList[i]
                end = i + int(optionsList[i+1],16) 
                optionsDict[command] = list() # we should be putting a command in here, like '02' for mss
                # make a list of what else goes with this option and put in dict
                i += 1
                while i < end:
                    optionsDict[command].append(optionsList[i])
                    i += 1

    print "------> optionsDict", optionsDict
    newOrder = spoof.olayout
    print "newOrder", newOrder
    newOptions = ""
    # Loop through and make a new options string. 
    # Change values or include new options to match signature.
    for byte in spoof.olayout:
        # scale has to be set to signatures scale
        if byte != spoof.optionNameToByte["ws"] and byte in optionsDict:
            newOptions += byte + "".join(optionsDict[byte])
        else:  # include it with a default value
            newOptions += byte + spoof.defOptVals[byte]
        # We need the mss to calculate window size
        if byte == spoof.optionNameToByte["mss"]:
            mss = int(newOptions[-4:], 16)

    if not mss:
        print "Warning: did not have mss set. Using default."
        mss = int(spoof.defOptVals[spoof.optionNameToByte["mss"]][-4:], 16)

    # the window size is dependent on knowing the mss and scale.
    # Calculate the new size here and return it so we can put it in the packet.
    wsize = mss * int(spoof.wsize_multiplier)
    print "new window size", wsize

    return newOptions, wsize


def getMssIndex(options):  # TODO: unused method, delete
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
    print("getting spoof object")
    lspoof = Spoof("Linux")
    # lspoof = spoof.spoof("Linux")
    print lspoof.ttl
    print lspoof.olayout
    # It sucks that windivert filters like this. It would be cool if we 
    # could pass it a bpf like "port 1234" from the command line
    with pydivert.WinDivert("tcp.DstPort==1234 or tcp.SrcPort==1234") as w:
        print "here"
        print w
        for packet in w:
            print "got packet"
            print (packet)

            # Look for syn packet. I think I read that mss is negotiated in 
            # handshake, or that fingerprinters typically only look at the handshake anyway
            if packet.tcp.syn is True and packet.tcp.ack is False :
                print ("This is a syn packet, looking for options...")

                spoofPacket(lspoof, packet)
                print "__________ packet after spoofPacket__________ "
                print packet
                """
                # # If tcp header length > 20 then we have tcp options
                if packet.tcp.header_len > 20:
                    # Get memory view object of tcp reader
                    mv = packet.tcp.raw
                    options = mv[20:]
                    print ("..options: " + str(options))
                    print (".. toBytes.encodeHex: " + str(options.tobytes()).encode('hex'))
                    print (".. toList: " + str(options.tolist()))
                    print (".. is this read only? " + str(options.readonly))  # we want to be able to write to this mem location
                   
                    print "packet raw", str(packet.raw.tobytes()).encode('hex')
                    print "ip raw", str(packet.ipv4.raw.tobytes()).encode('hex')
                    print "tcp raw", str(packet.tcp.raw.tobytes()).encode('hex')

                    # if reorderOptions(options, lspoof) == None:
                    #     pass # should do some kind of checking
                #packet.tcp.raw = packet.tcp.raw.tobytes().replace(b"test", b"abcd")
                #find this: 020405b40103030801010402
                #replace with: 020405b40402080a000000000000000001030307  
                print (".. toBytes.encodeHex testA: " + str(packet.tcp.raw.tobytes()).encode('hex'))
                fnd = "020405b40103030801010402".decode('hex')
                rpc = "020405b40402080a000000000000000001030307".decode('hex')
                packet.tcp.raw = packet.tcp.raw.tobytes().replace(fnd, rpc)
                #packet.tcp.raw = "\x41\x41\x41\x41"
                print (".. toBytes.encodeHex testB: " + str(packet.tcp.raw.tobytes()).encode('hex'))
                # packet.tcp.data_offset = 10 # so testing with wireshark, it look like the header_len is reset for us. Maybe in send()?
                print packet

                """

                #     index = getMssIndex(options.tolist())
                #     # set new mss
                #     if index is not None:
                #         print (".. writting 02 171 to options")
                #         options[index+2] = mssDict[64][0]
                #         options[index+3] = mssDict[64][1]
                #         # options[index+3] = b'\x40'
                #         print (".. options toBytes: " + str(options.tobytes()).encode('hex'))
            
            # No need to recalc checksum, send does it for us.
            w.send(packet)

if __name__ == "__main__":
    main()



