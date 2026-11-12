// Saltmere harbour graph
CREATE CONSTRAINT boat_name FOR (b:Boat) REQUIRE b.name IS UNIQUE;
LOAD CSV WITH HEADERS FROM 'file:///berths.csv' AS row
MERGE (b:Boat {name: row.boat})
MERGE (s:Berth {number: toInteger(row.berth)})
MERGE (b)-[:MOORED_AT]->(s);
/* boats that share a berth */
MATCH (a:Boat)-[:MOORED_AT]->(s:Berth)<-[:MOORED_AT]-(b:Boat) RETURN a.name, b.name, s.number;
