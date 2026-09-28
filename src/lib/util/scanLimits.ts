// A leaf module (no imports), so the pure header texts can share the
// scan's limits with scanStore without loading it.

/** The most addresses one scan probes: larger subnets are sampled evenly
 * down to this many (spec 3.1, 1.7). The backend takes it as max_hosts. */
export const MAX_SCAN_HOSTS = 4096;
