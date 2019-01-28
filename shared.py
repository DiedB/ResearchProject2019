from itertools import groupby, count

def calculateComplexity(bgpFlowspecRule):
    totalComplexity = 0

    for field in bgpFlowspecRule:
        if (field == 'type2' or field == 'type9'):
            totalComplexity += 1
        elif (field == 'type3' or field == 'type5' or field == 'type6' or field == 'type7'):
            valuesList = bgpFlowspecRule[field]
            complexity = 0
            for k, g in groupby(valuesList, lambda n, c=count(): n-next(c)):
                if len(list(g)) > 1:
                    complexity += 2
                else:
                    complexity += 1
            totalComplexity += complexity

    return totalComplexity
