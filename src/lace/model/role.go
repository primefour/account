package model

import (
	"encoding/json"
	"io"
	"strings"
)

const (
	SYSTEM_USER_ROLE_ID          = "system_user"
	SYSTEM_ADMIN_ROLE_ID         = "system_admin"
	ROLE_NAME_MAX_LENGTH         = 64
	ROLE_DISPLAY_NAME_MAX_LENGTH = 128
	ROLE_DESCRIPTION_MAX_LENGTH  = 1024
)

type Role struct {
	Id            string   `json:"id"`
	Name          string   `json:"name"`
	DisplayName   string   `json:"display_name"`
	Description   string   `json:"description"`
	CreateAt      int64    `json:"create_at"`
	UpdateAt      int64    `json:"update_at"`
	DeleteAt      int64    `json:"delete_at"`
	Permissions   []string `json:"permissions"`
	SchemeManaged bool     `json:"scheme_managed"`
	BuiltIn       bool     `json:"built_in"`
}

func (role *Role) ToJson() string {
	b, _ := json.Marshal(role)
	return string(b)
}

func RoleFromJson(data io.Reader) *Role {
	var role *Role
	json.NewDecoder(data).Decode(&role)
	return role
}

func RoleListToJson(r []*Role) string {
	b, _ := json.Marshal(r)
	return string(b)
}

func RoleListFromJson(data io.Reader) []*Role {
	var roles []*Role
	json.NewDecoder(data).Decode(&roles)
	return roles
}

func (role *Role) IsValid() bool {
	if len(role.Id) != 26 {
		return false
	}

	return role.IsValidWithoutId()
}

func (role *Role) IsValidWithoutId() bool {
	if !IsValidRoleName(role.Name) {
		return false
	}

	if len(role.DisplayName) == 0 || len(role.DisplayName) > ROLE_DISPLAY_NAME_MAX_LENGTH {
		return false
	}

	if len(role.Description) > ROLE_DESCRIPTION_MAX_LENGTH {
		return false
	}

	return true
}

func IsValidRoleName(roleName string) bool {
	if len(roleName) <= 0 || len(roleName) > ROLE_NAME_MAX_LENGTH {
		return false
	}

	if strings.TrimLeft(roleName, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
		return false
	}

	return true
}

func MakeDefaultRoles() map[string]*Role {
	roles := make(map[string]*Role)

	roles[SYSTEM_USER_ROLE_ID] = &Role{
		Name:          "system_user",
		DisplayName:   "authentication.roles.global_user.name",
		Description:   "authentication.roles.global_user.description",
		SchemeManaged: true,
		BuiltIn:       true,
	}

	roles[SYSTEM_ADMIN_ROLE_ID] = &Role{
		Name:        "system_admin",
		DisplayName: "authentication.roles.global_admin.name",
		Description: "authentication.roles.global_admin.description",
		// System admins can do anything channel and team admins can do
		// plus everything members of teams and channels can do to all teams
		// and channels on the system
		SchemeManaged: true,
		BuiltIn:       true,
	}

	return roles
}
