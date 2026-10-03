// Limits shared by the client's multi-host exec runs (Fleet, guided key rotation).

/** How many hosts run at once. Bounded (instead of the core's "all in
 *  parallel") so Stop has a real queue of not-yet-started hosts to cut. */
export const EXEC_CONCURRENCY = 8;
/** Per-host command deadline, seconds. */
export const EXEC_TIMEOUT_SECS = 30;
