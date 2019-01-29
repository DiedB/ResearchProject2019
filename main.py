from generator import *
from impact import *

def readJsonFile(path):
    with open(path, 'r') as f:
        jsonFile = json.load(f)
        return jsonFile

# Set parameters for rule generation
maxComplexity = 20
fingerprintId = '94e9a2940ddd082e6e3fdc84ead74ef0'
ddosDbDatasetPath = '../../dataset/final'
fingerprintPath = ddosDbDatasetPath + '/' + fingerprintId + '.json'

# Set parameters for impact quantification
prefixLengthWeight = -15
complexityWeight = -2
effectivenessWeight = 2
endUserImpactWeight = -20
ddosPacketTracePath = ddosDbDatasetPath + '/' + fingerprintId
realPacketTracePath = 'bigFlows'

# Generate the BGP Flowspec ruleset
fingerprint = readJsonFile(fingerprintPath)

# Set rule amounts and run algorithm
maxRuleAmounts = [1, 5, 10, 25, 50, 75, 100]
maxRuleAmounts = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
results = []


realPacketTraceDf = readPcap(realPacketTracePath)
print('bigFlows has been loaded')
# baseEndUserImpact = calculateEndUserImpact(realPacketTraceDf, generateBgpFlowspecRules(fingerprint, maxComplexity, 1)[0])

baseEndUserImpact = 0.0

for maxRuleAmount in maxRuleAmounts:
    print('Running on fingerprint ' + fingerprintId + ' with maxRuleAmount ' + str(maxRuleAmount))

    currentResult = {}
    currentResult['fingerprintId'] = fingerprintId
    currentResult['maxRuleAmount'] = maxRuleAmount
    # Generate the ruleset
    bgpFlowspecRuleset = generateBgpFlowspecRules(fingerprint, maxComplexity, maxRuleAmount)

    # Run impact calculator on given packetTrace and BGP Flowspec Ruleset
    currentImpactQuantification = calculateImpactQuantification(baseEndUserImpact, bgpFlowspecRuleset, ddosPacketTracePath, realPacketTracePath, prefixLengthWeight, complexityWeight, effectivenessWeight, endUserImpactWeight, maxComplexity)
    
    currentResult['impactQuantification'] = currentImpactQuantification

    results.append(currentResult.copy())
 
print(results)

f = open(fingerprintId + '.results.json', 'w+')
f.write(json.dumps(results))
f.close()