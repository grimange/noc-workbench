-- The seven-collector Linux profile includes independent SSH handshakes and
-- persistence between commands. Its full attempt needs the same bounded budget
-- as expanded SSH profiles; API source schedules retain their 20-second limit.
ALTER TABLE collection_schedule DROP CONSTRAINT collection_schedule_budget_seconds_check;
ALTER TABLE collection_schedule ADD CONSTRAINT collection_schedule_budget_seconds_check
 CHECK (budget_seconds BETWEEN 1 AND 20 OR
        (budget_seconds BETWEEN 21 AND 40 AND source_id IS NULL AND profile_id IS NOT NULL AND cardinality(collector_ids) BETWEEN 7 AND 12));
UPDATE collection_schedule SET budget_seconds=40,revision=revision+1
 WHERE source_id IS NULL AND profile_id IS NOT NULL
 AND cardinality(collector_ids) BETWEEN 7 AND 8 AND budget_seconds=20;
