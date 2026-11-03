// The few nodes that, if secured, cut off the most routes.
//
// Counted over the enumerated routes rather than as betweenness centrality.
// Betweenness scores a node against all shortest paths in the graph,
// including the great majority that start and end somewhere nobody cares
// about. The number a defender can act on is "this is on 5 of the 12 ways
// in", and that is a count.
//
// route[1..-1] is the interior, because a route necessarily runs through
// its own source and target, so scoring those tells you only what you
// already asked for.

MATCH path = (a:Entity {zone: 'untrusted'})-[*1..4]->(b:Entity {crown: true})
WITH DISTINCT [n IN nodes(path) | n.key] AS route
WITH collect(route) AS routes, count(*) AS total
UNWIND routes AS route
UNWIND route[1..-1] AS node
WITH total, node, count(*) AS through
RETURN node, through, toFloat(through) / total AS share
ORDER BY through DESC, node ASC
LIMIT 10;
