package postgres

// observationGroups seeks distinct indexed identities instead of scanning every
// retained version. Eligibility is checked by the caller's lateral latest-value
// query, so an ineligible newer value cannot hide older point-in-time evidence.
// assets is a fixed SQL expression supplied only by repository code.
func observationGroups(assets string) string {
	return `WITH RECURSIVE observation_groups AS (
 SELECT a.asset_id, first.key, first.resource_hash
 FROM unnest(` + assets + `) AS a(asset_id)
 CROSS JOIN LATERAL (
  SELECT key,resource_hash FROM observation WHERE asset_id=a.asset_id
  ORDER BY key,resource_hash LIMIT 1
 ) first
 UNION ALL
 SELECT g.asset_id, next.key, next.resource_hash
 FROM observation_groups g
 CROSS JOIN LATERAL (
  SELECT key,resource_hash FROM observation
  WHERE asset_id=g.asset_id AND (key,resource_hash)>(g.key,g.resource_hash)
  ORDER BY key,resource_hash LIMIT 1
 ) next
 ) `
}
