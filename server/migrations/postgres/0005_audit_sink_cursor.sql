-- Audit export sinks. Postgres mirror of the sqlite migration.
-- One row per configured sink (`webhook`, later `syslog`). `last_seq` is the
-- highest audit_log.seq the sink has ACKNOWLEDGED; delivery resumes after it on
-- restart. It only advances after an ack, so a crash between the ack and this
-- write re-sends that batch (at-least-once; receivers dedupe on seq).
CREATE TABLE audit_sink_cursor (
  sink       TEXT   PRIMARY KEY,
  last_seq   BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
