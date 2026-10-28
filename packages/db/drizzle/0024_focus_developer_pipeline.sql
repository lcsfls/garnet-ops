-- Focus on the developer pipeline (ADR 0025). Forward-only and additive: no table, column or index is
-- dropped (that waits for 1.0). This migration deletes the DATA of the modules that were removed in
-- 0.0.4: servers, Proxmox VE, UniFi, Wazuh/XDR, the attack overview (GeoIP, OSINT) and external exposure.
--
-- Most important for security: every stored credential of those modules is deleted here, so nothing
-- sealed for a removed integration stays in the database. Repository deploy keys, forge tokens, the
-- AI key, notification secrets and the LDAP secrets are not touched.

-- 1. The rows of the removed modules, including stored source IP addresses and attack events
--    (personal data). One statement, so the foreign keys between these tables need no ordering.
TRUNCATE TABLE
	"host_access_key",
	"host_setup_link",
	"host",
	"host_package",
	"host_inventory_run",
	"host_finding",
	"proxmox_cluster",
	"proxmox_node",
	"proxmox_guest",
	"proxmox_storage",
	"proxmox_sync_run",
	"unifi_connection",
	"unifi_site",
	"unifi_device",
	"unifi_sync_run",
	"unifi_threat_event",
	"exposure_settings",
	"exposure_asset",
	"exposure_run",
	"exposure_finding",
	"exposure_port",
	"exposure_discovery",
	"wazuh_connection",
	"wazuh_endpoint",
	"wazuh_agent",
	"wazuh_snapshot",
	"wazuh_fim_event",
	"wazuh_source_ip",
	"wazuh_attack_window",
	"wazuh_live_state",
	"wazuh_attack_event",
	"wazuh_sync_run",
	"wazuh_summary",
	"geoip_dataset",
	"geoip_country_range",
	"geoip_asn_range",
	"attack_settings",
	"attack_osint_result",
	"attack_summary";
--> statement-breakpoint
-- 2. Sealed secrets that only a removed module used (SSH access key for servers, Proxmox token, UniFi API key
--    and IPS password, Wazuh API and indexer passwords, OSINT API key, and the never-used NetBird token).
DELETE FROM "secret" WHERE "purpose" IN (
	'host-ssh-key',
	'proxmox-token',
	'unifi-api-key',
	'unifi-ips-password',
	'wazuh-api-password',
	'wazuh-indexer-password',
	'osint-api-key',
	'netbird-token'
);
--> statement-breakpoint
-- 3. Personal notifications and preferences of event types that no longer exist. The certificate event
--    stays (the directory sign-in still uses it), but the notifications that came from Proxmox and Wazuh go.
DELETE FROM "user_notification" WHERE "event" IN (
	'infra.host_key_changed',
	'infra.sync_blocked',
	'unifi.certificate_changed',
	'unifi.device_offline',
	'unifi.firmware_update_available',
	'exposure.certificate_expiring',
	'exposure.verification_lost',
	'exposure.new_open_port',
	'exposure.risky_service'
) OR "title_key" IN ('certificateChangedProxmox', 'certificateChangedXdr');
--> statement-breakpoint
DELETE FROM "notification_preference" WHERE "event" IN (
	'infra.host_key_changed',
	'infra.sync_blocked',
	'unifi.certificate_changed',
	'unifi.device_offline',
	'unifi.firmware_update_available',
	'exposure.certificate_expiring',
	'exposure.verification_lost',
	'exposure.new_open_port',
	'exposure.risky_service'
);
--> statement-breakpoint
-- 4. One audit entry per organisation says that this happened. Older audit entries of the removed
--    modules stay as they are. A fresh installation has no organisation yet and gets no entry.
INSERT INTO "audit_log" ("organization_id", "action", "target_type", "data")
SELECT "id", 'system.modules_removed', 'system', '{"adr":"0025","version":"0.0.4"}'::jsonb
FROM "organization";
