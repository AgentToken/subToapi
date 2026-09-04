-- Backfill system-managed Codex fingerprint seeds for ALL OpenAI OAuth accounts.
--
-- Issue #5786 ("全载体缺失"): off-mode outbound requests whose client carries no
-- installation identity are backfilled with the account-canonical installation,
-- which is derived from this persistent seed. Extend 225 (which only covered
-- accounts with convergence enabled) to every OpenAI OAuth account so the
-- backfill works without requiring convergence to be switched on first.
-- Setup-token accounts are intentionally excluded: their identity namespace
-- keeps using the bearer-token fingerprint, unchanged from previous releases.
-- Idempotent: valid canonical seeds are preserved on rerun.
UPDATE accounts
SET extra = jsonb_set(
    COALESCE(extra, '{}'::jsonb),
    '{codex_fingerprint_seed}',
    to_jsonb(gen_random_uuid()::text),
    true
)
WHERE deleted_at IS NULL
  AND platform = 'openai'
  AND type = 'oauth'
  AND (
      extra->>'codex_fingerprint_seed' IS NULL
      OR btrim(extra->>'codex_fingerprint_seed') = ''
      OR NOT (
          extra->>'codex_fingerprint_seed' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
          AND extra->>'codex_fingerprint_seed' <> '00000000-0000-0000-0000-000000000000'
      )
  );
