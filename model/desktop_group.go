package model

import (
	"errors"
	"slices"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// This private option stores compatibility order, not native permissions.
// default reserves ID 1; other groups are numbered from 2. Deletion compacts
// positions as requested. These IDs are NOT durable identities: clients must
// refresh their selection after deletion. Native tokens and authorization
// must continue to use group names, never persist these numeric IDs.
const desktopGroupRegistryKey = "DesktopGroupRegistry"

func isDesktopGroupOption(key string) bool {
	return key == "GroupRatio" || key == "group_ratio_setting.group_ratio"
}

// GetDesktopGroupIDs reads the shared, persisted compatibility order. It does
// not reconcile from a process cache, which could be stale on another instance.
func GetDesktopGroupIDs() (map[string]int64, error) {
	var option Option
	err := DB.Where(&Option{Key: desktopGroupRegistryKey}).First(&option).Error
	if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && option.Value == "") {
		err = DB.Transaction(func(tx *gorm.DB) error {
			var lockErr error
			option, lockErr = lockDesktopGroupRegistry(tx)
			return lockErr
		})
	}
	if err != nil {
		return nil, err
	}
	var names []string
	if err := common.UnmarshalJsonStr(option.Value, &names); err != nil {
		return nil, err
	}
	if names == nil {
		return nil, errors.New("invalid desktop group registry")
	}
	ids := make(map[string]int64, len(names))
	nextID := int64(2)
	for _, name := range names {
		if _, exists := ids[name]; exists || name == "" || name == "auto" {
			return nil, errors.New("invalid desktop group registry")
		}
		if name == "default" {
			ids[name] = 1
			continue
		}
		ids[name] = nextID
		nextID++
	}
	return ids, nil
}

// The first write serializes competing registry/config changes on all three
// databases, including SQLite (which cannot upgrade concurrent read locks).
func lockDesktopGroupRegistry(tx *gorm.DB) (Option, error) {
	option := Option{Key: desktopGroupRegistryKey}
	if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&option).Error; err != nil {
		return option, err
	}
	if err := tx.Model(&Option{}).Where(&Option{Key: desktopGroupRegistryKey}).
		UpdateColumn("value", gorm.Expr("value")).Error; err != nil {
		return option, err
	}
	if err := tx.Where(&Option{Key: desktopGroupRegistryKey}).First(&option).Error; err != nil {
		return option, err
	}
	if option.Value != "" {
		return option, nil
	}
	// Upgrade an existing installation using its actual group configuration.
	groups := ratio_setting.GetGroupRatioCopy()
	for _, key := range []string{"group_ratio_setting.group_ratio", "GroupRatio"} {
		var config Option
		err := tx.Where(&Option{Key: key}).First(&config).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			continue
		}
		if err != nil {
			return option, err
		}
		// Replace instead of merging with in-memory defaults (vip/svip may not
		// exist in the installation's saved configuration).
		groups = nil
		if err := common.UnmarshalJsonStr(config.Value, &groups); err != nil {
			return option, err
		}
		break
	}
	value, err := common.Marshal(groups)
	if err != nil {
		return option, err
	}
	option.Value = "[]"
	err = reconcileDesktopGroupRegistry(tx, &option, string(value))
	return option, err
}

// Keep creation order, remove deleted groups and append new ones. A JSON object
// has no creation order, so names added in the same batch are sorted once.
func reconcileDesktopGroupRegistry(tx *gorm.DB, option *Option, value string) error {
	var groups map[string]float64
	if err := common.UnmarshalJsonStr(value, &groups); err != nil {
		return err
	}
	if groups == nil {
		return errors.New("group configuration must be an object")
	}
	var previous []string
	if err := common.UnmarshalJsonStr(option.Value, &previous); err != nil {
		return err
	}
	if previous == nil {
		return errors.New("invalid desktop group registry")
	}
	names := make([]string, 0, len(groups))
	if _, exists := groups["default"]; exists {
		names = append(names, "default")
	}
	seen := make(map[string]bool, len(previous))
	for _, name := range previous {
		if seen[name] || name == "" || name == "auto" {
			return errors.New("invalid desktop group registry")
		}
		seen[name] = true
		if name == "default" {
			continue
		}
		if _, exists := groups[name]; exists {
			names = append(names, name)
		}
	}
	added := make([]string, 0)
	for name := range groups {
		if name == "" {
			return errors.New("group name must not be empty")
		}
		if name != "default" && name != "auto" && !seen[name] {
			added = append(added, name)
		}
	}
	slices.Sort(added)
	names = append(names, added...)
	encoded, err := common.Marshal(names)
	if err != nil {
		return err
	}
	option.Value = string(encoded)
	return tx.Model(&Option{}).Where(&Option{Key: desktopGroupRegistryKey}).Update("value", option.Value).Error
}
