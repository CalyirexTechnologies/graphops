// If one node is compromised right now, what is in reach, by hop.
//
// UNDIRECTED on purpose. Compromise does not respect the direction a
// relationship happened to be recorded in. If an identity acted from an
// address, holding the address tells you about the identity just as much
// as the reverse.
//
// min(length(path)) reports each node at the SHALLOWEST hop that reaches
// it and never again. Without that, a node reachable in one hop also
// appears at three because some longer walk arrives there too, which makes
// the one-hop list look larger than the danger it describes.

:param id => 'asset-orders';

MATCH path = (origin:Entity {id: $id})-[*1..3]-(m:Entity)
WHERE m.id <> $id
WITH m, min(length(path)) AS hop
RETURN hop, count(m) AS count, collect(m.key) AS members
ORDER BY hop ASC;
