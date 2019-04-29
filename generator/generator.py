import sys
import math
import json

# Generate Type 3 rule component
# TODO: Support more protocols?
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

# Rule generator
def main():
    fingerprint = None

    # Read the fingerprint file
    if (len(sys.argv) == 2):
        f = open(sys.argv[1], 'r')
        fingerprint = json.loads(f.read())
    else:
        raise ValueError('Please supply a fingerprint file path as argument')

    # Resulting array
    flowspecRules = []

    # Rule that will be used as template
    baseFlowspecRule = {}

    # Collect Type 1 (Destination IP)
    # TODO: Add actual destination address
    baseFlowspecRule['type1'] = None

    # Type 2 will be dynamically generated and added to the resulting ruleset later
    # TODO: Create (weighted) algorithm for reducing fingerprint source IPs into prefixes
    baseFlowspecRule['type2'] = None

    # Collect Type 3 (IP protocol)
    type3 = getIpProtocols(fingerprint['protocol'])
    baseFlowspecRule['type3'] = type3

    # Collect type 5 (Destination ports)
    if 'dst_ports' in fingerprint:
        type5 = getPorts(fingerprint['dst_ports'])

        # Only add if 5 ports or less
        if (len(type5) == 1):
            baseFlowspecRule['type5'] = type5

    # Collect type 6 (Source ports)
    if 'src_ports' in fingerprint:
        type6 = getPorts(fingerprint['src_ports'])

        # Only add if 5 ports or less
        if (len(type6) == 1):
            baseFlowspecRule['type6'] = type6

    # If ICMP, collect its ICMP information
    if 1 in type3:

        # Collect type 7
        baseFlowspecRule['type7'] = getIcmpType(fingerprint['additional']['icmp_type'])

    # If TCP, collect its flag information
    if 6 in type3:

        # Collect type 9
        baseFlowspecRule['type9'] = getTcpFlag(fingerprint['additional']['tcp_flag'])

    flowspecRules.append(baseFlowspecRule)
    return flowspecRules

if __name__ == '__main__':
    print(main())
