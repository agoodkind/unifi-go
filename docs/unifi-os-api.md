# UniFi OS lab HTTP endpoints

UniFi OS Server on this lab answers HTTPS on TCP 11443. Network Application JSON after login uses the `/proxy/network` prefix. These shapes were observed on UniFi OS Server 5.1.42 with Network Application 10.6.101.

## Session

`POST /api/auth/login` creates the session. The request body is JSON:

```json
{
  "username": "string",
  "password": "string"
}
```

The response is `200` with `Content-Type: application/json`. The body is a user object. Login includes every member of `GET /api/users/self`, plus `deviceToken` and `ssoAuth`.

The response sets cookie `TOKEN` (`HttpOnly`, `Secure`, `SameSite=None`, path `/`). It also sends headers `X-Csrf-Token`, `X-Updated-Csrf-Token`, and `X-Token-Expire-Time`. Mutating requests include `X-Csrf-Token` and the `TOKEN` cookie.

## UniFi OS

| Method | Path | Status | Body |
| --- | --- | --- | --- |
| POST | `/api/auth/login` | 200 | user object |
| GET | `/api/users/self` | 200 | user object |
| GET | `/api/system` | 200 | system object |
| POST | `/api/setup` | 200 | first-run wizard (once) |

`GET /api/users/self` members: `accessMask`, `alias`, `avatar`, `avatar_relative_path`, `avatar_rpath2`, `cloud_access_granted`, `create_time`, `email`, `email_is_null`, `email_status`, `employee_number`, `extras`, `first_name`, `full_name`, `groups`, `id`, `isMember`, `isOwner`, `isSuperAdmin`, `last_name`, `local_account_exist`, `login_time`, `maskedEmail`, `nfc_card_status`, `nfc_card_type`, `nfc_display_id`, `nfc_token`, `only_local_account`, `org_role`, `org_user_id`, `password_revision`, `permissionMask`, `permissions`, `phone`, `role`, `roleId`, `roles`, `scopes`, `sso_account`, `sso_picture`, `sso_username`, `sso_uuid`, `status`, `ucorePermission`, `uid_account_status`, `uid_sso_account`, `uid_sso_id`, `unique_id`, `update_time`, `user_email`, `username`.

`id` and `unique_id` are the same UUID string. `role` is `"owner"` for the local owner. `local_account_exist` is `true`.

`GET /api/system` members: `anonymous_device_id`, `apps`, `autoBackupEnabled`, `cpu`, `debugEnabled`, `deviceErrorCode`, `deviceId`, `deviceState`, `devices`, `directConnectDomain`, `directRemoteConnectionState`, `emailServiceProvider`, `features`, `firmware`, `firmwareDownload`, `hardware`, `hasInternet`, `hostname`, `internetRequired`, `ip`, `isInternalUser`, `isLutronSystemDetected`, `isSetup`, `isStacked`, `ispInfo`, `latestUpdate`, `latestUpdateCheck`, `lcmSettings`, `ledSettings`, `ledStatus`, `location`, `mac`, `memory`, `name`, `network`, `nightMode`, `now`, `owner`, `portStatus`, `ports`, `publicIp`, `settings`, `setupDuration`, `setupType`, `setup_device_id`, `sfpAggregation`, `sfpWanPort`, `sfpWanPorts`, `ssh`, `storage`, `timezone`, `ucore_version`, `uidb`, `unadoptedUnifiOSDevices`, `updateSchedule`, `uptime`, `ustorage`, `wakeOnLan`, `wans`.

`isSetup` is `true` after the wizard. `name` is `"UOS Server"`. `apps` is an object with `apps` and `controllers`. `firmware` is an object with `autoUpdate`, `channels`, `lastUpdateContext`, `latest`, `latestByChannel`, `progress`, `releaseChannel`, `schedule`, `token`, `unvrFlashStorageMigrationState`, `update`, `updatedFrom`.

`POST /api/setup` accepts JSON with `analytics`, `email`, `enableRemoteAdmin`, `hostname`, `localPassword`, `password`, `timezone`, `username`. That call returned `200` during first run.

## Network Application envelope

Every Network JSON path below returns:

```json
{
  "meta": {
    "rc": "ok"
  },
  "data": []
}
```

`meta.rc` is `"ok"` or `"error"`. Failed calls also set `meta.msg` to a string such as `"api.err.Invalid"` or `"api.err.NotFound"`.

| Method | Path | Status | `data` |
| --- | --- | --- | --- |
| GET | `/proxy/network/api/s/default/stat/sysinfo` | 200 | one sysinfo object |
| GET | `/proxy/network/api/self/sites` | 200 | site objects |
| GET | `/proxy/network/api/s/default/stat/device` | 200 | device objects |
| GET | `/proxy/network/api/s/default/rest/setting` | 200 | setting objects |
| POST | `/proxy/network/upload/backup` | 200 | one backup info object |
| POST | `/proxy/network/api/s/default/cmd/backup` | 200 | command result |

## Sysinfo

`GET /proxy/network/api/s/default/stat/sysinfo` returns one object in `data` with: `anonymous_controller_id`, `autobackup`, `build`, `data_retention_days`, `data_retention_time_in_hours_for_5minutes_scale`, `data_retention_time_in_hours_for_daily_scale`, `data_retention_time_in_hours_for_hourly_scale`, `data_retention_time_in_hours_for_monthly_scale`, `data_retention_time_in_hours_for_others`, `debug_device`, `debug_mgmt`, `debug_sdn`, `debug_setting_preference`, `debug_system`, `default_site_device_auth_password_alert`, `has_webrtc_support`, `hostname`, `https_port`, `image_maps_use_google_engine`, `inform_port`, `ip_addrs`, `is_cloud_console`, `live_chat`, `name`, `override_inform_host`, `portal_http_port`, `previous_version`, `radius_disconnect_running`, `sso_app_id`, `store_enabled`, `timezone`, `unsupported_device_count`, `unsupported_device_list`, `update_available`, `update_downloaded`, `uptime`, `version`.

`version` is `"10.6.101"`. `inform_port` is `8080`. `https_port` is `8443`. `override_inform_host` is `true`.

## Sites

`GET /proxy/network/api/self/sites` returns site objects with `_id`, `anonymous_id`, `attr_hidden_id`, `attr_no_delete`, `desc`, `device_count`, `external_id`, `name`, `role`, `role_hotspot`.

`name` is `"default"` for the restored site. `_id` is the destination `site_id` for restore.

## Devices

`GET /proxy/network/api/s/default/stat/device` returns four device objects. Each object has 158 members. Observed members: `name`, `model`, `mac`, `adopted`, `state`, `ip`, `last_seen`, `uptime`.

`adopted` is `true`. `state` is `0` when the device is not informing and `1` when it is.

## Settings

`GET /proxy/network/api/s/default/rest/setting` returns 37 objects. Each object has `key`. Current keys: `super_identity`, `super_mgmt`, `super_cloudaccess`, `super_fwupdate`, `super_fabric_system_log`, `connectivity`, `element_adopt`, `guest_access`, `ntp`, `mgmt`, `dpi`, `lcm`, `usg`, `ugw`, `rsyslogd`, `dashboard`, `global_switch`, `teleport`, `magic_site_to_site_vpn`, `radio_ai`, `ips`, `ips_suppression`, `doh`, `ether_lighting`, `peer_to_peer`, `global_nat`, `netflow`, `mdns`, `traffic_flow`, `global_network`, `igmp_snooping`, `usg_geo`, `device_supervision`, `country`, `locale`, `openvpn`, `ssl_inspection`.

The `super_mgmt` object members are `_id`, `autobackup_cron_expr`, `autobackup_days`, `autobackup_enabled`, `autobackup_max_files`, `autobackup_post_actions`, `autobackup_timezone`, `backup_to_cloud_enabled`, `data_retention_setting_preference`, `data_retention_time_in_hours_for_5minutes_scale`, `data_retention_time_in_hours_for_daily_scale`, `data_retention_time_in_hours_for_hourly_scale`, `data_retention_time_in_hours_for_monthly_scale`, `data_retention_time_in_hours_for_others`, `discoverable`, `enable_analytics`, `key`, `minimum_usable_hd_space`, `multiple_sites_enabled`, `override_inform_host`, `override_inform_host_location`, `time_series_per_client_stats_enabled`.

`override_inform_host` is a boolean. `override_inform_host_location` is a string IPv4 address.

## Backup upload and restore

`POST /proxy/network/upload/backup` is `multipart/form-data`. The file field name is `file`. The uploaded `.unf` produced `data[0]`:

```json
{
  "backup_id": "uuid",
  "filename": "string",
  "filesize": 0,
  "purpose": "application_backup",
  "sites": [
    {
      "_id": "string",
      "anonymous_id": "uuid",
      "name": "string",
      "external_id": "uuid",
      "desc": "string",
      "attr_hidden_id": "string",
      "attr_no_delete": true
    }
  ],
  "timestamp": 0,
  "version": "string",
  "warnings": {}
}
```

`purpose` for the Docker Network backup was `"application_backup"`. `version` was `"10.6.101"`. `filesize` was `3947168`.

`POST /proxy/network/api/s/default/cmd/backup` with `{"cmd":"list-backups"}` returns `meta.rc` `"ok"` and `data` as the backup catalog. A `.unf` copied onto disk without this upload does not appear in that catalog.

`POST /proxy/network/api/s/default/cmd/backup` restore body:

```json
{
  "cmd": "restore",
  "backup_id": "uuid",
  "site_id": "string"
}
```

That call returned `meta.rc` `"ok"` and `data` `[]`. `unifi.service` then restarted. `backup_id` is the upload `data[0].backup_id`. `site_id` is the live default site `_id` from `/proxy/network/api/self/sites`.

## Inform

`GET /inform` on TCP 8080 returns `400`. The Network Application inform servlet listens on that port. Devices POST to `/inform`.

Sysinfo `inform_port` is `8080`.
