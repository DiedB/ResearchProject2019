import os
import json
import tempfile
import subprocess
import pandas as pd
import math
import ipaddress
from progress.bar import Bar
from shared import calculateComplexity

def convertPcapToDataFrame(input_file):
    if not os.path.exists(input_file):
        raise IOError("File " + input_file + " does not exist")

    tshark_fields = "-e _ws.col.Destination " \
                    "-e _ws.col.Source " \
                    "-e _ws.col.Length " \
                    "-e ip.proto " \
                    "-e ip.src " \
                    "-e udp.dstport " \
                    "-e tcp.dstport " \
                    "-e udp.srcport " \
                    "-e tcp.srcport " \
                    "-e tcp.flags " \
                    "-e icmp.type " 

    temporary_file = tempfile.TemporaryFile("r+b")

    p = subprocess.Popen(["/usr/local/bin/tshark -n -r \"" + input_file + "\" -E separator='\x03'  -E header=y -T fields " + tshark_fields],
                         shell=True, stdout=temporary_file) #\x03 is ETX
    p.communicate()
    p.wait()

    temporary_file.seek(0)

    df = pd.read_csv(temporary_file, sep="\x03", low_memory=False, error_bad_lines=False)

    temporary_file.close()
    
    return df

def extractIntValue(value):
    if type(value) == int or (type(value) == str and value.isdigit()) or ((type(value) == float) and not math.isnan(value)):
        return int(value)
    elif (type(value) == str) and ',' in value:
        return int(value.split(',')[0])
    elif type(value) == float and math.isnan(value):
        return False
    else:
        print(value)
        raise ValueError('extractIntValue: Unexpected value')

def areEqual(arr1, arr2): 
    n = len(arr1)
    m = len(arr2)

    # If lengths of array are not  
    # equal means array are not equal 
    if (n != m): 
        return False; 
  
    # Sort both arrays 
    arr1.sort(); 
    arr2.sort(); 
  
    # Linearly compare elements 
    for i in range(0, n - 1): 
        if (arr1[i] != arr2[i]): 
            return False; 
  
    # If all elements were same. 
    return True;         

# Read Type 2 value
def compareIpAddresses(packetTraceSrcIp, bgpFlowspecSrcIp):
    network = ipaddress.ip_network(bgpFlowspecSrcIp)
    network2 = ipaddress.ip_network(packetTraceSrcIp + '/32')

    return network2.subnet_of(network)

# Read Type 3 value
def compareProtocols(packetTraceProtocol, bgpFlowspecProtocols):
    intValue = extractIntValue(packetTraceProtocol)
    if intValue != False:
        return intValue in bgpFlowspecProtocols
    else:
        return False

# Read Type 5/6 value
def comparePorts(packetTracePort, bgpFlowspecRulePorts):
    intValue = extractIntValue(packetTracePort)
    if intValue != False:
        return intValue in bgpFlowspecRulePorts
    else:
        return False

# Read Type 7 value
def compareIcmpTypes(packetTraceIcmpType, bgpFlowspecRuleIcmpType):
    intValue = extractIntValue(packetTraceIcmpType)
    if intValue != False:
        return intValue == bgpFlowspecRuleIcmpType
    else:
        return False

# Read Type 9 value
def compareTcpFlags(packetTraceTcpFlags, bgpFlowspecTcpFlags):
    # Convert hex to flags
    binaryFlags = str(bin(int(packetTraceTcpFlags, 16))[2:].zfill(8))
    tcpFlagMapping = ['cwr', 'ecn', 'urg', 'ack', 'psh', 'rst', 'syn', 'fin']

    mappedTcpFlags = []
    for index, binaryFlag in enumerate(binaryFlags):
        if binaryFlag == '1':
            mappedTcpFlags.append(tcpFlagMapping[index])
    
    return areEqual(mappedTcpFlags, bgpFlowspecTcpFlags)

# Calculate matching packets based on dataset and BGP Flowspec Rule
def calculateEndUserImpact(df, bgpFlowspecRule):
    totalPackets = len(df.index)
    matchingPackets = 0

    bar = Bar('Calculating end-user impact...', max = totalPackets)
    # Iterate over PCAP dataframe
    for _, row in df.iterrows():
        bar.next()
        matchesFlowspecRule = False

        # Compare Type 3 (protocol, OR)
        if compareProtocols(row.get('ip.proto'), bgpFlowspecRule['type3']):

            # ICMP-specific
            if 1 in bgpFlowspecRule['type3']:

                # Compare Type 5 (destination port, OR)
                if (not ('type5' in bgpFlowspecRule)) or comparePorts(row.get('udp.dstport'), bgpFlowspecRule['type5']) or comparePorts(row.get('tcp.dstport'), bgpFlowspecRule['type5']):
                    
                    # Compare Type 6 (source port, OR)
                    if (not ('type6' in bgpFlowspecRule)) or comparePorts(row.get('udp.srcport'), bgpFlowspecRule['type6']) or comparePorts(row.get('tcp.srcport'), bgpFlowspecRule['type6']):

                        # Compare Type 7 (ICMP type)
                        if compareIcmpTypes(row.get('icmp.type'), bgpFlowspecRule['type7']):
                            matchesFlowspecRule = True

            # TCP-specific
            if 6 in bgpFlowspecRule['type3']:

                # Compare Type 5 (destination port, OR)
                if (not ('type5' in bgpFlowspecRule)) or comparePorts(row.get('tcp.dstport'), bgpFlowspecRule['type5']):
                    
                    # Compare Type 6 (source port, OR)
                    if (not ('type6' in bgpFlowspecRule)) or comparePorts(row.get('tcp.srcport'), bgpFlowspecRule['type6']):
                        matchesFlowspecRule = True

            # Todo: UDP-specfic (UDP, SSDP, QUIC)
            if 17 in bgpFlowspecRule['type3']:

                # Compare Type 5 (destination port, OR)
                if (not ('type5' in bgpFlowspecRule)) or comparePorts(row.get('udp.dstport'), bgpFlowspecRule['type5']):
                    
                    # Compare Type 6 (source port, OR)
                    if (not ('type6' in bgpFlowspecRule)) or comparePorts(row.get('udp.srcport'), bgpFlowspecRule['type6']):
                        matchesFlowspecRule = True

        if matchesFlowspecRule:
            matchingPackets += 1

    bar.finish()

    return matchingPackets / totalPackets

# Calculate matching packets based on dataset and BGP Flowspec Rule
def calculateEffectiveness(df, bgpFlowspecRule):
    matchingVolume = 0
    totalVolume = 0

    bar = Bar('Calculating rule effectiveness...', max = len(df.index))
    # Iterate over PCAP dataframe
    for _, row in df.iterrows():
        bar.next()

        packetLength = row.get('_ws.col.Length')
        totalVolume += packetLength

        matchesFlowspecRule = False

        # Compare Type 3 (protocol, OR)
        if compareProtocols(row.get('ip.proto'), bgpFlowspecRule['type3']):

            # Compare IP addresses
            if compareIpAddresses(row.get('ip.src'), bgpFlowspecRule['type2']):
                
                # ICMP-specific
                if 1 in bgpFlowspecRule['type3']:

                    # Compare Type 5 (destination port, OR)
                    if (not ('type5' in bgpFlowspecRule)) or comparePorts(row.get('udp.dstport'), bgpFlowspecRule['type5']) or comparePorts(row.get('tcp.dstport'), bgpFlowspecRule['type5']):
                        
                        # Compare Type 6 (source port, OR)
                        if (not ('type6' in bgpFlowspecRule)) or comparePorts(row.get('udp.srcport'), bgpFlowspecRule['type6']) or comparePorts(row.get('tcp.srcport'), bgpFlowspecRule['type6']):

                            # Compare Type 7 (ICMP type)
                            if compareIcmpTypes(row.get('icmp.type'), bgpFlowspecRule['type7']):
                                matchesFlowspecRule = True

                # TCP-specific
                if 6 in bgpFlowspecRule['type3']:

                    # Compare Type 5 (destination port, OR)
                    if (not ('type5' in bgpFlowspecRule)) or comparePorts(row.get('tcp.dstport'), bgpFlowspecRule['type5']):
                        
                        # Compare Type 6 (source port, OR)
                        if (not ('type6' in bgpFlowspecRule)) or comparePorts(row.get('tcp.srcport'), bgpFlowspecRule['type6']):
                            matchesFlowspecRule = True

                # UDP-specfic (UDP, SSDP, QUIC)
                if 17 in bgpFlowspecRule['type3']:

                    # Compare Type 5 (destination port, OR)
                    if (not ('type5' in bgpFlowspecRule)) or comparePorts(row.get('udp.dstport'), bgpFlowspecRule['type5']):
                        
                        # Compare Type 6 (source port, OR)
                        if (not ('type6' in bgpFlowspecRule)) or comparePorts(row.get('udp.srcport'), bgpFlowspecRule['type6']):
                            matchesFlowspecRule = True

        if matchesFlowspecRule:
            matchingVolume += packetLength

    bar.finish()

    return matchingVolume / totalVolume


def readPcap(path):
    dataFrame = None
    try:
        dataFrame = pd.read_pickle(path + '.pkl')
    except FileNotFoundError as _:
        dataFrame = convertPcapToDataFrame(path + '.pcap')
        dataFrame.to_pickle(path + '.pkl')
    finally:
        return dataFrame


def calculateImpactQuantification(baseEndUserImpact, bgpFlowspecRuleset, ddosPacketTracePath, realPacketTracePath, prefixLengthWeight, complexityWeight, effectivenessWeight, endUserImpactWeight, maxComplexity):
    print('Initializing PCAP dataframes...')
    ddosPacketTraceDf = readPcap(ddosPacketTracePath)
    print('DDoS packet trace has been loaded')

    impactQuantificationResults = []

    for bgpFlowspecRule in bgpFlowspecRuleset:
        currentImpactQuantificationResult = {}

        ruleEffectiveness = calculateEffectiveness(ddosPacketTraceDf, bgpFlowspecRule)
        ruleComplexity = calculateComplexity(bgpFlowspecRule) / maxComplexity

        rulePrefixLength = int(bgpFlowspecRule['type2'].split('/')[1])
        rulePrefixLengthFactor = prefixLengthWeight * ((math.pow(2, 32 - rulePrefixLength) - 1) / math.pow(2, 32))

        # Todo: still needed to compensate for this?
        ruleEffectiveness = ruleEffectiveness - rulePrefixLengthFactor
        ruleEndUserImpact = baseEndUserImpact + rulePrefixLengthFactor

        # impactQuantification = (complexityWeight * ruleComplexity) + (effectivenessWeight * ruleEffectiveness) + (endUserImpactWeight * ruleEndUserImpact)
        # print('Rule ' + str(bgpFlowspecRule['index']) + ': C=' + str(ruleComplexity) + ': PLF=' + str(rulePrefixLengthFactor) + ', E=' + str(ruleEffectiveness) + ', I=' + str(ruleEndUserImpact)+ ', Q=' + str(impactQuantification))

        currentImpactQuantificationResult['ruleDefinition'] = bgpFlowspecRule
        impactFactors = {}

        impactFactors['c'] = ruleComplexity
        impactFactors['plf'] = rulePrefixLengthFactor
        impactFactors['e'] = ruleEffectiveness
        impactFactors['i'] = ruleEndUserImpact

        currentImpactQuantificationResult['impactFactors'] = impactFactors.copy()
        impactQuantificationResults.append(currentImpactQuantificationResult.copy())
        
    return impactQuantificationResults