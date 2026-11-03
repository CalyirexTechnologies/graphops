// Which crown jewels sit inside the blast radius of a given node.
//
// This is the line that turns "sixteen systems are in reach" into "this is
// a reportable breach", which is the distinction an analyst actually needs
// in the first minute of an incident.

:param id => 'asset-orders';

MATCH path = (origin:Entity {id: $id})-[*1..3]-(m:Entity {crown: true})
WITH m, min(length(path)) AS hop
RETURN m.key AS crown_jewel, m.kind AS kind, hop
ORDER BY hop ASC, crown_jewel ASC;
