-- After the upgrade: every row of seed.sql is there with the same values. Fails (raises) on the first difference.
do $$
declare
  missing text[] := array[]::text[];
begin
  if not exists (select 1 from organization where id = 'org_upgrade' and name = 'Upgrade check') then
    missing := missing || 'organization'; end if;
  if not exists (select 1 from "user" where id = 'usr_upgrade' and email = 'upgrade-check@example.com') then
    missing := missing || 'user'; end if;
  if not exists (select 1 from membership where organization_id = 'org_upgrade' and user_id = 'usr_upgrade' and role = 'owner') then
    missing := missing || 'membership'; end if;
  if not exists (select 1 from repository where id = 'repo_upgrade' and organization_id = 'org_upgrade'
      and url = 'https://git.example.test/team/upgrade-app.git' and auth_kind = 'none') then
    missing := missing || 'repository'; end if;
  if not exists (select 1 from scan where id = 'scan_upgrade' and state = 'succeeded') then
    missing := missing || 'scan'; end if;
  if not exists (select 1 from finding where id = 'fnd_upgrade' and state = 'open' and severity = 'critical'
      and severity_rank = 5 and fixed_in = '["1.0.1"]'::jsonb and package_name = 'left-pad'
      and first_seen_at = '2026-01-02T03:04:05Z') then
    missing := missing || 'finding'; end if;
  if not exists (select 1 from repository_package where id = 'pkg_upgrade' and name = 'left-pad' and version = '1.0.0') then
    missing := missing || 'repository_package'; end if;
  if not exists (select 1 from audit_log where action = 'repository.created' and target_id = 'repo_upgrade') then
    missing := missing || 'audit_log'; end if;
  if cardinality(missing) > 0 then
    raise exception 'rows changed or lost in the upgrade: %', array_to_string(missing, ', ');
  end if;
end $$;
select 'kept: organization, user, membership, repository, scan, finding, package, audit log; '
  || count(*) || ' migrations applied' from drizzle.__drizzle_migrations;
