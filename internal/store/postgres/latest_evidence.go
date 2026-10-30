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

// consoleObservationGroups limits identity discovery to measurements displayed by
// the server console. Unrelated retained history must not expand console work.
// Timestamp eligibility remains in the caller's latest-value lookup.
func consoleObservationGroups(assets string) string {
	return `WITH RECURSIVE console_groups AS (
 SELECT a.asset_id,k.key,first.resource_hash
 FROM unnest(` + assets + `) AS a(asset_id)
 CROSS JOIN unnest(ARRAY['linux.load.1m','linux.service.runtime','vicidial.discovery.snapshot','linux.baseline.status','linux.baseline.cpu_percent','linux.baseline.units','linux.mem.available_bytes','linux.mem.total_bytes']) AS k(key)
 CROSS JOIN LATERAL (
  SELECT resource_hash FROM observation WHERE asset_id=a.asset_id AND key=k.key
  ORDER BY resource_hash LIMIT 1
 ) first
 UNION ALL
 SELECT g.asset_id,g.key,next.resource_hash
 FROM console_groups g
 CROSS JOIN LATERAL (
  SELECT resource_hash FROM observation
  WHERE asset_id=g.asset_id AND key=g.key AND resource_hash>g.resource_hash
  ORDER BY resource_hash LIMIT 1
 ) next
 ), observation_groups AS (
 SELECT asset_id,key,resource_hash FROM console_groups
 UNION ALL
 SELECT a.asset_id,k.key,collection_resource_hash('/')
 FROM unnest(` + assets + `) AS a(asset_id)
 CROSS JOIN unnest(ARRAY['linux.filesystem.identifier','linux.filesystem.total_bytes','linux.filesystem.used_bytes','linux.filesystem.available_bytes','linux.filesystem.utilization_percent']) AS k(key)
 ) `
}
