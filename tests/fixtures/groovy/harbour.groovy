// Berth report for Saltmere Harbour.
package saltmere

import groovy.json.JsonOutput

class Berth {
    int number
    String vessel
}

def report(List<Berth> berths) {
    println JsonOutput.toJson(berths)
}

report([new Berth(number: 3, vessel: 'Tern')])
