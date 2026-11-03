// Every route from untrusted ground to a crown jewel, ordered by how much
// work it costs an attacker rather than by how many hops it is.
//
// `reduce` sums the per-step effort along the path. That is the whole
// difference between this and a shortest-path query: on the sample estate
// every route is two hops, so hop count ranks them identically, and effort
// separates a dormant entitlement (2.0) from a landed exploit (5.0).
//
// The collapse near the end matters. Two nodes can be joined by more than
// one relationship, for example an entitlement AND an observed use, and
// that is one ROUTE through the estate rather than two. Without it, Cypher
// reported 13 routes where the Python engine reported 12, which is how the
// difference was found.
//
// Plain Cypher. No GDS and no APOC, neither of which ships with Community.

MATCH path = (a:Entity {zone: 'untrusted'})-[*1..4]->(b:Entity {crown: true})
WITH [n IN nodes(path) | n.key] AS route,
     [r IN relationships(path) | type(r)] AS edges,
     reduce(total = 0.0, r IN relationships(path) | total + r.cost) AS cost
ORDER BY cost ASC
WITH route, head(collect(edges)) AS edges, min(cost) AS cost
RETURN route, edges, cost
ORDER BY cost ASC, size(route) ASC
LIMIT 400;
