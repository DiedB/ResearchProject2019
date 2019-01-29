import json
import math
import itertools
from bitstring import BitArray
from ipaddress import ip_network, ip_address
from socket import inet_aton
from shared import calculateComplexity

# Generate Type 1 and Type 2 rule components
def convertIpAddressesIntoCdirMaxRules(ipAddresses, maxRuleAmount):
    currentPrefixSize = 32
    
    binaryIpAddresses = [BitArray(inet_aton(ipAddress)).bin for ipAddress in ipAddresses]
    binaryIpAddresses.sort()

    prefixIdCounter = activePrefixIds = len(binaryIpAddresses)
    prefixIdMemory = [[32, i] for i in range(1, prefixIdCounter + 1)]
    
    def updatePrefixIdMemoryRange(startIndex, endIndex, newPrefixSize):
        nonlocal prefixIdCounter, activePrefixIds, prefixIdMemory
        prefixIdsToRemove = len(set([memoryValue[1] for memoryValue in prefixIdMemory[startIndex:endIndex + 1]])) - 1
    
        if prefixIdsToRemove > 0:
            # print(prefixIdsToRemove, prefixIdMemory, startIndex, endIndex, newPrefixSize)
            
            prefixIdCounter = prefixIdCounter + 1
            activePrefixIds -= prefixIdsToRemove
            newPrefixIdMemoryValue = [newPrefixSize, prefixIdCounter]

            endIndex += 1
            prefixIdMemory[startIndex:endIndex] = itertools.repeat(newPrefixIdMemoryValue, (endIndex - startIndex))
                
    while activePrefixIds > maxRuleAmount:
        currentPrefixSize = currentPrefixSize - 1

        # Make a list scoped to the current prefix size
        currentPrefixList = [ipAddress[0:currentPrefixSize] for ipAddress in binaryIpAddresses]
        
        # Loop through the list with prefixes and check for duplicates
        oldestEqualPrefixListIndex = 0
        oldestEqualPrefixListValue = currentPrefixList[0]
        
        for currentPrefixListIndex, currentPrefixListValue in enumerate(currentPrefixList):            
            # Check if sequence has been broken
            if activePrefixIds <= maxRuleAmount:
                break
            if currentPrefixListValue != oldestEqualPrefixListValue:
                # Check if multiple equal values
                if oldestEqualPrefixListIndex != currentPrefixListIndex - 1:
                    # We have matches, check amount of overlap with prefixIdMemory
                    updatePrefixIdMemoryRange(oldestEqualPrefixListIndex, currentPrefixListIndex - 1, currentPrefixSize) 
                
                # Reset memory
                oldestEqualPrefixListIndex = currentPrefixListIndex
                oldestEqualPrefixListValue = currentPrefixListValue
            elif currentPrefixListIndex == len(currentPrefixList) - 1:
                # Check if multiple equal values
                if oldestEqualPrefixListValue == currentPrefixListValue:
                    # We have matches, check amount of overlap with prefixIdMemory
                    updatePrefixIdMemoryRange(oldestEqualPrefixListIndex, currentPrefixListIndex, currentPrefixSize) 
                
                # Reset memory
                oldestEqualPrefixListIndex = currentPrefixListIndex
                oldestEqualPrefixListValue = currentPrefixListValue

    # Initialize a list with resulting prefixes
    resultList = []
    passedMemoryEntries = set()
    for memoryIndex, memoryEntry in enumerate(prefixIdMemory):
        if memoryEntry[1] not in passedMemoryEntries:
            passedMemoryEntries.add(memoryEntry[1])
            
            # Get the prefix size for the current prefix
            prefixSize = memoryEntry[0]
            slicedBinaryIpAddress = binaryIpAddresses[memoryIndex][0:prefixSize]

            # Pad the IP address with zeroes again and convert it into a decimal representation
            decimalIpAddress = str(ip_address(int(slicedBinaryIpAddress.ljust(32, '0'), 2)))

            # Add the prefix to the result list
            resultList.append('{}/{}'.format(decimalIpAddress, prefixSize))

    return resultList

# Generate Type 3 rule component
def getIpProtocols(fingerprintProtocol):
    ipProtocols = []

    if fingerprintProtocol in ['TCP', 'DNS', 'Chargen']:
        ipProtocols.append(6)
    if fingerprintProtocol in ['UDP', 'DNS', 'Chargen', 'QUIC', 'NTP', 'SSDP']:
        ipProtocols.append(17)
    if fingerprintProtocol in ['ICMP']:
        ipProtocols.append(1)

    return ipProtocols

# Generate Type 5 or Type 6 rule component
def getPorts(fingerprintPorts):
    ports = []

    for port in fingerprintPorts:
        if not math.isnan(port):
            ports.append(int(port))

    return ports

# Generate Type 7 rule component
def getIcmpType(fingerprintIcmpType):
    return int(float(fingerprintIcmpType))

# Generate Type 9 rule component
def getTcpFlag(fingerprintTcpFlag):
    filteredTcpFlag = fingerprintTcpFlag.replace('\u00b7', '')

    tcpFlags = []

    for flag in filteredTcpFlag:
        if flag == 'S':
            tcpFlags.append('syn')
        elif flag == 'E':
            tcpFlags.append('ecn')
        elif flag == 'C':
            tcpFlags.append('cwr')
        elif flag == 'U':
            tcpFlags.append('urg')
        elif flag == 'A':
            tcpFlags.append('ack')
        elif flag == 'P':
            tcpFlags.append('psh')
        elif flag == 'R':
            tcpFlags.append('rst')
        elif flag == 'F':
            tcpFlags.append('fin')
        else:
            raise ValueError('Encountered flag with unknown format')

    return tcpFlags

# Helper function to extract list of source ips from fingerprint
def extractSourceIps(fingerprint):
    sourceIps = fingerprint['src_ips']
    
    if len(sourceIps) > 0:
        if isinstance(sourceIps[0], str):
            return sourceIps
        elif isinstance(sourceIps[0], dict):
            return [sourceIp['ip'] for sourceIp in sourceIps]
        else:
            raise ValueError('Encountered fingerprint with unknown format')

# Rule generator
def generateBgpFlowspecRules(fingerprint, maxComplexity, maxRuleAmount):
    flowspecRules = []
    baseFlowspecRule = {}

    # Collect Type 3 (IP protocol)
    type3 = getIpProtocols(fingerprint['protocol'])
    baseFlowspecRule['type3'] = type3

    # Collect type 5 (Destination ports)
    if 'dst_ports' in fingerprint:
        type5 = getPorts(fingerprint['dst_ports'])

        # Only add if 5 ports or less
        if (len(type5) <= 5):
            baseFlowspecRule['type5'] = type5

    # Collect type 6 (Source ports)
    if 'src_ports' in fingerprint:
        type6 = getPorts(fingerprint['src_ports'])

        # Only add if 5 ports or less
        if (len(type6) <= 5):
            baseFlowspecRule['type6'] = type6

    # If ICMP, collect its ICMP information
    if 1 in type3:
        type7 = getIcmpType(fingerprint['additional']['icmp_type'])
        baseFlowspecRule['type7'] = type7

    # If TCP, collect its flag information
    if 6 in type3:
        type9 = getTcpFlag(fingerprint['additional']['tcp_flag'])
        baseFlowspecRule['type9'] = type9

    # Generate all type 2 values (source IPs)
    type2Values = convertIpAddressesIntoCdirMaxRules(extractSourceIps(fingerprint), maxRuleAmount)

    # Generate a rule for each type 2 value (prefix)
    for index, type2 in enumerate(type2Values):
        currentFlowspecRule = baseFlowspecRule.copy()
        currentFlowspecRule['type2'] = type2

        # Check if the rule complexity does not exceed maximum rule complexity
        if (calculateComplexity(currentFlowspecRule) <= maxComplexity):
            currentFlowspecRule['index'] = index
            flowspecRules.append(currentFlowspecRule)

    return flowspecRules
