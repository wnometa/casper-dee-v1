/*
# Link findings to scan jobs

1. Modified Tables
- `findings` gains a nullable `scan_job_id` column referencing `scan_jobs`.
  - ON DELETE SET NULL so deleting a scan doesn't lose the finding itself.
  - Nullable because seed findings and manually-created findings have no scan.

2. Security
- No policy changes. Existing findings policies already cover the column.

3. Important Notes
- Non-destructive: adds one nullable column only.
- Lets the scanner edge function write findings linked to the scan that produced them.
*/

ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS scan_job_id uuid REFERENCES scan_jobs(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS findings_scan_job_id_idx ON findings(scan_job_id);
