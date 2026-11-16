-- Data the release before is given in the upgrade test (scripts/upgrade-check/run.sh). Only columns that every release since
-- 0.1.0 has: migrations are forward-only and additive (AGENTS.md rule 2), so this stays valid for the release before any later one.
-- Example values only (example.com, example.test); nothing here is real.
begin;
insert into organization (id, name) values ('org_upgrade', 'Upgrade check');
insert into "user" (id, name, email) values ('usr_upgrade', 'Upgrade check', 'upgrade-check@example.com');
insert into membership (organization_id, user_id, role) values ('org_upgrade', 'usr_upgrade', 'owner');
insert into repository (id, organization_id, name, url, auth_kind)
  values ('repo_upgrade', 'org_upgrade', 'upgrade-app', 'https://git.example.test/team/upgrade-app.git', 'none');
insert into scan (id, organization_id, repository_id, state, trigger)
  values ('scan_upgrade', 'org_upgrade', 'repo_upgrade', 'succeeded', 'manual');
insert into vulnerability (id, severity) values ('CVE-2099-0001', 'critical');
insert into finding (id, organization_id, repository_id, vulnerability_id, dedup_key, package_name, package_version,
    package_type, fixed_in, severity, severity_rank, state, first_seen_scan_id, last_seen_scan_id, first_seen_at, last_seen_at)
  values ('fnd_upgrade', 'org_upgrade', 'repo_upgrade', 'CVE-2099-0001', 'upgrade-check', 'left-pad', '1.0.0', 'npm',
    '["1.0.1"]', 'critical', 5, 'open', 'scan_upgrade', 'scan_upgrade', '2026-01-02T03:04:05Z', '2026-01-02T03:04:05Z');
insert into repository_package (id, organization_id, repository_id, scan_id, name, version, type)
  values ('pkg_upgrade', 'org_upgrade', 'repo_upgrade', 'scan_upgrade', 'left-pad', '1.0.0', 'npm');
insert into audit_log (organization_id, actor_user_id, action, target_type, target_id)
  values ('org_upgrade', 'usr_upgrade', 'repository.created', 'repository', 'repo_upgrade');
commit;
select 'seeded ' || count(*) || ' migrations applied' from drizzle.__drizzle_migrations;
