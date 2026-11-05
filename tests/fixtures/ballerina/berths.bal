// Berth service for Saltmere Harbour.
import ballerina/http;

type Berth record {|
    int number;
    string vessel;
|};

service /berths on new http:Listener(9090) {
    resource function get count() returns int {
        return 12;
    }
}

public function main() {
    io:println("ready");
}
