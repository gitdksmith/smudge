import pydivert
import getopt
import sys 
import time

# tsval sample: 08, 0a, 01 83 8a c2, 00 00 00 00
#              kind, len, tsval, tsreply

# sig = ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass

# ver = ipv4 or ipv6 version
# olen = length of IPv4 options or IPv6 extension headers
# olayout = TCP options layout
# quirks = other properties observed in IP or TCP header, like "do not fragment", or "PUSH flag used"
# pclass = payload size classification: '0' for zero, '+' nonzero, '*' for any.


class Spoof:
    wildcard = "*"
    optionNameToByte = {'end':'00', 'nop':'01', 'mss':'02', 'ws':'03', 'sok':'04', 'ts':'08'}
    linuxDefOptVals = {'00':"", '01':"", '02':"0405b4", '03':"0307", '04':"02", '08':"0axxxxxxxx00000000"}
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


# Option name string to byte value
byteToOptName = {'00':'end', '01':'nop', '02':'mss', '03':'ws', '04':'sok', '08':'ts'}

# Available Types
typeMap = {0:'Linux'}
DEFAULT_SPOOF_TYPE = "Linux"


def tsval_generate(spoof):
    # this gets the hex value of the epoch time and strips out the 0x
    tsval = hex(int(time.time()))
    tsval = tsval[2:]
    return spoof.defOptVals['08'].replace("xxxxxxxx", tsval)


def spoofPacket(spoof, packet):
    rawBytes = str(packet.raw.tobytes()).encode('hex')
    db = [rawBytes]
    
    # set all new tcp values except these options
    #   version - no value to set in packet object
    #   olen    - no value to set in packet object
    #             seems to always be 0 in the sigs anyway
    #   mss,scale,window_size
    #           - have to be set after parsing options
    if spoof.ttl != spoof.wildcard:
        packet.ipv4.ttl = int(spoof.ttl)
        # Do we need to set the ttl to ttl - 1 ?

    rawBytes = str(packet.raw.tobytes()).encode('hex')
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
        db.append(rawBytes)

        # print all rawBytes seen so far together for easier comparison for debugging
        print ""
        print db[0]
        print db[1]
        print db[2]


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

    newOptions = ""
    # Loop through and make a new options string. 
    # Change values or include new options to match signature.
    for byte in spoof.olayout:
        if byte == spoof.optionNameToByte['ts']:
            print 'calling tsval_generate'
            tsval = tsval_generate(spoof)
            print 'tsval returned', tsval
            newOptions += byte + tsval

        # scale has to be set to signatures scale
        elif byte != spoof.optionNameToByte['ws'] and byte in optionsDict:
            newOptions += byte + "".join(optionsDict[byte])
        else:  
            # include it with a default value
            newOptions += byte + spoof.defOptVals[byte]
        # We need the mss to calculate window size
        if byte == spoof.optionNameToByte['mss']:
            mss = int(newOptions[-4:], 16)

    if not mss:
        print 'Warning: did not have mss set. Using default.'
        mss = int(spoof.defOptVals[spoof.optionNameToByte["mss"]][-4:], 16)

    # the window size is dependent on knowing the mss and scale.
    # Calculate the new size here and return it so we can put it in the packet.
    wsize = mss * int(spoof.wsize_multiplier)
    print 'new window size', wsize

    return newOptions, wsize


def usage():
    print "  -s <type>     int value for type of OS to spoof (default", DEFAULT_SPOOF_TYPE,")"
    print "  --list-types  prints list of available OS's to impersonate" 
    print "  -h            print this help message"

def listTypes():
    print 'Available options for -s:'
    for k, v in typeMap.items():
        print "    ", k,"    ", v


def main():
    spoofType = DEFAULT_SPOOF_TYPE

    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:h', ['list-types'])
    except getopt.GetoptError as err:
        print err
        usage()
        return 1

    # Then check the flags and get their values
    for opt, arg in opts:
        if opt == '-s':
            try:
                spoofType = typeMap[int(arg)]
            except Exception as err:
                print 'Invalid spoof type. Check available options with --list-types.', err
                sys.exit(1)
        elif opt == '--list-types':
            listTypes()
            return 0
        elif opt == '-h':
            usage()
            return 0
        else: 
            usage()
            return 1

    lspoof = Spoof(spoofType)

    # It sucks that windivert filters like this. It would be cool if we 
    # could pass it a bpf like "port 1234" from the command line
    print 'Starting smudge...'
    with pydivert.WinDivert('tcp.DstPort==1234 or tcp.SrcPort==1234') as w:
        print w
        for packet in w:
            print 'got packet'
            print (packet)

            # Look for syn packet. I think I read that mss is negotiated in 
            # handshake, or that fingerprinters typically only look at the handshake anyway
            if packet.tcp.syn is True and packet.tcp.ack is False :
                print ('This is a syn packet, looking for options...')

                spoofPacket(lspoof, packet)
                print '__________ packet after spoofPacket__________'
                print packet

            # No need to recalc checksum, send does it for us.
            w.send(packet)

if __name__ == '__main__':
    sys.exit(main())



