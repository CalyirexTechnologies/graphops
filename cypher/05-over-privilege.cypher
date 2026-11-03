// Access that policy grants and nobody has ever exercised.
//
// ENTITLED edges come from the identity provider and say what a principal
// is ALLOWED to reach. CALLED and SERVES edges come from logs and say what
// it actually reached. An entitlement with no matching use is standing
// access that buys the business nothing and buys an attacker a free step,
// because whoever takes the credential inherits the whole grant rather
// than the part its owner needed.
//
// This is the pre-incident finding. Nobody has to be attacked for it to be
// worth fixing.

MATCH (i:Entity)-[:ENTITLED]->(target:Entity)
WHERE NOT (i)-[:CALLED|SERVES]->(target)
RETURN i.key AS identity,
       target.key AS may_reach,
       target.crown AS reaches_crown_jewel
ORDER BY reaches_crown_jewel DESC, identity ASC;
