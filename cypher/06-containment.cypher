// What one cut actually buys, asked of the graph rather than inferred from a
// count. Plain Cypher. No GDS, no APOC.
//
// 02-choke-points.cypher ranks nodes by how many routes run through them.
// That number is necessary and it is not sufficient, because it says nothing
// about the far end of the path. A node can carry most of the routes and
// protect nothing, if every route it carries ends at a crown jewel that other
// routes still reach. And it says nothing about effort: removing most of the
// routes while leaving the attacker's cheapest option exactly as cheap is a
// result a team wants before the change meeting, not after it.
//
// So this query makes each cut and asks again. For every interior node it
// reports the routes that survive, what the cheapest surviving route costs,
// and which crown jewels nothing can reach any more.
//
// The route collapse on lines 27-29 is the same one the path query needs: two
// nodes can be joined by both an entitlement and an observed use, which is one
// route through the estate and not two. The in-memory engine and Cypher
// disagreed on the route count until that was added.

MATCH path = (a:Entity {zone: 'untrusted'})-[*1..4]->(b:Entity {crown: true})
WITH [n IN nodes(path) | n.key] AS route,
     reduce(total = 0.0, r IN relationships(path) | total + r.cost) AS cost
WITH route, min(cost) AS cost
WITH collect({route: route, cost: cost, target: last(route)}) AS routes

// The before picture, computed once.
UNWIND routes AS before_row
WITH routes,
     count(*)                        AS routes_before,
     min(before_row.cost)            AS cheapest_before,
     collect(DISTINCT before_row.target) AS jewels_before

// Every interior node is a candidate cut. route[1..-1] drops the two ends,
// because a route necessarily runs through its own source and target.
UNWIND routes AS counted_row
UNWIND counted_row.route[1..-1] AS candidate
WITH routes, routes_before, cheapest_before, jewels_before,
     candidate, count(*) AS routes_counted_through

// Make the cut: keep only the routes that do not pass through the candidate.
WITH routes_before, cheapest_before, jewels_before, candidate,
     routes_counted_through,
     [x IN routes WHERE NOT candidate IN x.route] AS survivors

RETURN candidate,
       routes_counted_through,
       routes_before,
       size(survivors)                        AS routes_after,
       routes_before - size(survivors)        AS routes_removed,
       cheapest_before,
       // Seeded from the first survivor rather than from a large constant, so
       // an empty list is reported as null instead of as a sentinel cost.
       CASE WHEN size(survivors) = 0 THEN null
            ELSE reduce(m = head(survivors).cost, x IN survivors |
                        CASE WHEN x.cost < m THEN x.cost ELSE m END)
       END                                    AS cheapest_after,
       // jewels_before is already distinct, so membership is all that is
       // needed on the right-hand side.
       [t IN jewels_before
          WHERE NOT t IN [x IN survivors | x.target]] AS crown_jewels_cut_off,
       size(survivors) = 0                    AS fully_contained
ORDER BY routes_removed DESC, candidate ASC
LIMIT 10;
