package migration

import (
	"context"

	"gorm.io/gorm"
)

// name_server_groups
func FillEmptyNameserverGroupJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update name_server_groups set name_servers='[]' where id in (select id from name_server_groups where name_servers='' or name_servers=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update name_server_groups set groups='[]' where id in (select id from name_server_groups where groups='' or groups=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update name_server_groups set domains='[]' where id in (select id from name_server_groups where domains='' or domains=null order by id asc)`)
		return res.Error
	})
}

func FillEmptyPeerJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update peers set ip='{}' where id in (select id from peers where ip='' or ip=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set ipv6='{}' where id in (select id from peers where ipv6='' or ipv6=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set meta_network_addresses='[]' where id in (select id from peers where meta_network_addresses='' or meta_network_addresses=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set meta_environment='{}' where id in (select id from peers where meta_environment='' or meta_environment=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set meta_flags='{}' where id in (select id from peers where meta_flags='' or meta_flags=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set meta_files='[]' where id in (select id from peers where meta_files='' or meta_files=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set meta_capabilities='[]' where id in (select id from peers where meta_capabilities='' or meta_capabilities=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set location_connection_ip='{}' where id in (select id from peers where location_connection_ip='' or location_connection_ip=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update peers set extra_dns_labels='[]' where id in (select id from peers where extra_dns_labels='' or extra_dns_labels=null order by id asc)`)
		return res.Error
	})
}

func FillEmptySettingsJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update accounts set settings_jwt_allow_groups='[]' where id in (select id from accounts where settings_jwt_allow_groups='' or settings_jwt_allow_groups=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update accounts set settings_network_range='{}' where id in (select id from accounts where settings_network_range='' or settings_network_range=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update accounts set settings_network_range_v6='{}' where id in (select id from accounts where settings_network_range_v6='' or settings_network_range_v6=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update accounts set settings_peer_expose_groups='[]' where id in (select id from accounts where settings_peer_expose_groups='' or settings_peer_expose_groups=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update accounts set settings_ipv6_enabled_groups='[]' where id in (select id from accounts where settings_ipv6_enabled_groups='' or settings_ipv6_enabled_groups=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update accounts set settings_extra_integrated_validator_groups='[]' where id in (select id from accounts where settings_extra_integrated_validator_groups='' or settings_extra_integrated_validator_groups=null order by id asc)`)
		return res.Error
	})
}

func FillEmptyPolicyRuleJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update policy_rules set destinations='[]' where id in (select id from policy_rules where destinations='' or destinations=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update policy_rules set destination_resource='{}' where id in (select id from policy_rules where destination_resource='' or destination_resource=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update policy_rules set sources='[]' where id in (select id from policy_rules where sources='' or sources=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update policy_rules set source_resource='{}' where id in (select id from policy_rules where source_resource='' or source_resource=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update policy_rules set ports='[]' where id in (select id from policy_rules where ports='' or ports=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update policy_rules set port_ranges='[]' where id in (select id from policy_rules where port_ranges='' or port_ranges=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update policy_rules set authorized_groups='{}' where id in (select id from policy_rules where authorized_groups='' or authorized_groups=null order by id asc)`)
		return res.Error
	})
}

func FillEmptyRouteJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update routes set network='{}' where id in (select id from routes where network='' or network=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update routes set domains='[]' where id in (select id from routes where domains='' or domains=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update routes set peer_groups='[]' where id in (select id from routes where peer_groups='' or peer_groups=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update routes set groups='[]' where id in (select id from routes where groups='' or groups=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update routes set access_control_groups='[]' where id in (select id from routes where access_control_groups='' or access_control_groups=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		return res.Error
	})
}

func FillEmptyServiceJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update services set auth='{}' where id in (select id from services where auth='' or auth=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update services set restrictions='{}' where id in (select id from services where restrictions='' or restrictions=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update services set access_groups='{}' where id in (select id from services where access_groups='' or access_groups=null order by id asc)`)
		return res.Error
	})
}

func FillEmptyServiceTargetsJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update targets set custom_headers='{}' where id in (select id from targets where custom_headers='' or custom_headers=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update targets set middlewares='{}' where id in (select id from targets where middlewares='' or middlewares=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update targets set capture_content_types='{}' where id in (select id from targets where capture_content_types='' or capture_content_types=null order by id asc)`)
		return res.Error
	})
}

func FillEmptyAccountNetworkJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update accounts set network_net='{}' where id in (select id from accounts where network_net='' or network_net=null order by id asc)`)
		if res.Error != nil {
			return res.Error
		}
		res = tx.Exec(`update accounts set network_net_v6='{}' where id in (select id from accounts where network_net_v6='' or network_net_v6=null order by id asc)`)
		return res.Error
	})
}

func FillEmptyNetworkResourceJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update network_resources set prefix='{}' where id in (select id from network_resources where prefix='' or prefix=null order by id asc)`)
		return res.Error
	})
}

func FillEmptyNetworkRouterJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update network_routers set peer_groups='[]' where id in (select id from network_routers where peer_groups='' or peer_groups=null order by id asc)`)
		return res.Error
	})
}

func FillEmptyAccountDnsSettingsJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update accounts set dns_settings_disabled_management_groups='[]' where id in (select id from accounts where dns_settings_disabled_management_groups='' or dns_settings_disabled_management_groups=null order by id asc)`)
		return res.Error
	})
}

func FillEmptyUserJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update users set auto_groups='[]' where id in (select id from users where auto_groups='' or auto_groups=null order by id asc)`)
		return res.Error
	})
}

func FillEmptyPostureCheckJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update posture_checks set checks='{}' where id in (select id from posture_checks where checks='' or checks=null order by id asc)`)
		return res.Error
	})
}

func FillEmptySetupKeyJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update setup_keys set auto_groups='[]' where id in (select id from setup_keys where auto_groups='' or auto_groups=null order by id asc)`)
		return res.Error
	})
}

func FillEmptyUserInvitesJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update user_invites set auto_groups='[]' where id in (select id from user_invites where auto_groups='' or auto_groups=null order by id asc)`)
		return res.Error
	})
}

func FillEmptyGroupJsonColumns(ctx context.Context, db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`update groups set resources='[]' where id in (select id from groups where resources='' or resources=null order by id asc)`)
		return res.Error
	})
}
