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
    osVersionSigMap = (('Linux',{
                            '3.11': '*:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0',
                            '3.1-3.10': '*:64:0:*:mss*10,4:mss,sok,ts,nop,ws:df,id+:0',
                            '2.6.x': '*:64:0:*:mss*4,6:mss,sok,ts,nop,ws:df,id+:0'}),
                        ('Windows', {
                            '7':'*:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0',
                            '8':'*:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0',
                            'xp':'*:128:0:*:16384,0:mss,nop,nop,sok:df,id+:0'}),
                       )

    def __init__(self, spoofType, spoofVersion=None):
        #if spoofType == "Linux":
            #self.configure(self.linuxSig)
        
        print "conifguring for signature", self.getSig(spoofType, spoofVersion)
        self.configure(self.getSig(spoofType, spoofVersion))

    def configure(self, sig):
        s = str.split(sig, ":")
        self.version = s[0]
        self.ttl = s[1]
        self.olen = s[2]
        self.mss = s[3]
        self.wsize_multiplier = get_multiplier(str.split(str.split(s[4], ",")[0], "*")[1])
        if self.wsize_multiplier is None:
            self.wsize = asdfalksjdfaslkdj # make method to figure out if * is in the wsize, or if not return none and 
                                            # we set the value as the int in the signature. Then in reorder options we 
                                            # check if the wsize exists, else do the multiplier stuff.
        self.wscale = str.split(s[4], ",")[1]
        self.olayout = [self.optionNameToByte[x] for x in str.split(s[5], ",")]
        self.quirks = str.split(s[6], ",")
        self.pclass = s[7]
        self.defOptVals = self.linuxDefOptVals

    @staticmethod   
    def getVersionToSigMap(spoofType):
        for tup in Spoof.osVersionSigMap:
            if tup[0] == spoofType:
                return tup[1]
                
        # if spoofType == "Linux":
        #     return Spoof.osVersionSigMap
        # if spoofType == "Windows":
        #     pass

    def getSig(self, spoofType, spoofVersion=None):
        sigMap = self.getVersionToSigMap(spoofType)
        if spoofVersion is None:
            # get the first version as default if no version provided
            spoofVersion = self.getVersions(spoofType)[0]
        return sigMap[spoofVersion]

    @staticmethod
    def getVersions(spoofType):
        """
        return sorted list of versions for spoofType
        """
        sigMap = Spoof.getVersionToSigMap(spoofType)
        return sorted(sigMap.keys(), reverse=True)

    @staticmethod
    def getOsList():
        return [a[0] for a in Spoof.osVersionSigMap]


# Option name string to byte value
byteToOptName = {'00':'end', '01':'nop', '02':'mss', '03':'ws', '04':'sok', '08':'ts'}

# Available Types
typeMap = {0:'Linux', 1: "Windows"}
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

def getSpoofType(strng):
    osList = Spoof.getOsList()
    # see if we were passed in a name
    if strng in osList:
        return strng

    # else access by index
    try:
        spoofType = osList[int(strng)]
    except Exception as err:
        print 'Invalid spoof type', err
        return None
    return spoofType


def usage():
    print "  -s <type>                int value for type of OS to spoof (default", DEFAULT_SPOOF_TYPE + ")"
    print "  -v <version>             version to spoof for type"
    print "  --list-types             prints list of available OS's to impersonate" 
    print "  --list-versions          lists available versions for type (defaul all)"
    print "                             If used with -s, lists versions for that type only"
    print "  -h                       print this help message"


def listTypes():
    print 'Available types:'
    osList = Spoof.getOsList()
    i = 0
    for o in osList:
        print "    ", i,"    ", o
        i += 1


def listVersions(t):
    osList = [t]
    if t == 'all':
        osList = Spoof.getOsList()

    for o in osList:
        vlist = Spoof.getVersions(o)
        print 'Available versions for', o
        print "    ", vlist


def main():
    spoofType = DEFAULT_SPOOF_TYPE
    spoofSet = False
    lstVersions = False

    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:v:h', ['list-types', 'list-versions'])
    except getopt.GetoptError as err:
        print err
        usage()
        return 1

    # Then check the flags and get their values
    for opt, arg in opts:
        if opt == '-s':
            spoofType = getSpoofType(arg)
            spoofSet = True
            if not spoofType:
                listTypes()
                return 1
        elif opt == '--list-types':
            listTypes()
            return 0
        elif opt == '--list-versions':
            lstVersions = True
        elif opt == '-h':
            usage()
            return 0
        else: 
            usage()
            return 1

    if lstVersions:
        if spoofSet:
            listVersions(spoofType)
        else:
            listVersions('all')
        return 0

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



