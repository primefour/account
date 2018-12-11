package model

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	USER_NAME_MIN_LENGTH     = 5
	USER_NAME_MAX_LENGTH     = 26
	PASSWORD_MAXIMUM_LENGTH  = 26
	PASSWORD_MINIMUM_LENGTH  = 8
	USER_PASSWORD_MAX_LENGTH = PASSWORD_MAXIMUM_LENGTH
	USER_EMAIL_MAX_LENGTH    = 255
	USER_NICKNAME_MAX_RUNES  = 255
)

type UsersStats struct {
	TotalUsersCount int64
}

type User struct {
	Id                 string    `json:"Id"`
	CreateAt           int64     `json:"create_at,omitempty"`
	UpdateAt           int64     `json:"update_at,omitempty"`
	DeleteAt           int64     `json:"delete_at"`
	Username           string    `json:"username"`
	Password           string    `json:"password,omitempty"`
	Email              string    `json:"email"`
	EmailVerified      bool      `json:"email_verified,omitempty"`
	Name               string    `json:"name"`
	Roles              string    `json:"roles"`
	LastPasswordUpdate int64     `json:"last_password_update,omitempty"`
	LastPictureUpdate  int64     `json:"last_picture_update,omitempty"`
	FailedAttempts     int       `json:"failed_attempts,omitempty"`
	Locale             string    `json:"locale"`
	Props              StringMap `json:"props,omitempty"`
}

// HashPassword generates a hash using the bcrypt.GenerateFromPassword
func HashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		panic(err)
	}

	return string(hash)
}

// ComparePassword compares the hash
func ComparePassword(hash string, password string) bool {

	if len(password) == 0 || len(hash) == 0 {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

var validUsernameChars = regexp.MustCompile(`^[a-z0-9\.\-_]+$`)

func IsValidUsername(s string) bool {
	if len(s) < USER_NAME_MIN_LENGTH || len(s) > USER_NAME_MAX_LENGTH {
		return false
	}

	if !validUsernameChars.MatchString(s) {
		return false
	}

	return true
}

func NormalizeUsername(username string) string {
	return strings.ToLower(username)
}

func NormalizeEmail(email string) string {
	return strings.ToLower(email)
}

func CleanUsername(s string) string {
	s = NormalizeUsername(strings.Replace(s, " ", "-", -1))

	s = strings.TrimSpace(s)

	for _, c := range s {
		char := fmt.Sprintf("%c", c)
		if !validUsernameChars.MatchString(char) {
			s = strings.Replace(s, char, "-", -1)
		}
	}

	s = strings.Trim(s, "-")

	if !IsValidUsername(s) {
		s = "a" + NewId()
	}

	return s
}

// PreSave will set the Id and Username if missing.  It will also fill
// in the CreateAt, UpdateAt times.  It will also hash the password.  It should
// be run before saving the user to the db.
func (u *User) PreSave() {
	if u.Id == "" {
		u.Id = NewId()
	}

	if u.Username == "" {
		u.Username = NewId()
	}

	u.Username = NormalizeUsername(u.Username)
	u.Email = NormalizeEmail(u.Email)

	u.CreateAt = GetMillis()
	u.UpdateAt = u.CreateAt

	u.LastPasswordUpdate = u.CreateAt

	if u.Locale == "" {
		u.Locale = DEFAULT_LOCALE
	}

	if u.Props == nil {
		u.Props = make(map[string]string)
	}

	if len(u.Password) > 0 {
		u.Password = HashPassword(u.Password)
	}
}

// PreUpdate should be run before updating the user in the db.
func (u *User) PreUpdate() {
	u.Username = NormalizeUsername(u.Username)
	u.Email = NormalizeEmail(u.Email)
	u.UpdateAt = GetMillis()
}

// IsValid validates the user and returns an error if it isn't configured
// correctly.
func (u *User) IsValid() *AppError {

	if len(u.Id) != 26 {
		return InvalidUserError("id", "")
	}

	if u.CreateAt == 0 {
		return InvalidUserError("create_at", u.Id)
	}

	if u.UpdateAt == 0 {
		return InvalidUserError("update_at", u.Id)
	}

	if !IsValidUsername(u.Username) {
		return InvalidUserError("username", u.Id)
	}

	if len(u.Email) > USER_EMAIL_MAX_LENGTH || len(u.Email) == 0 || !IsValidEmail(u.Email) {
		return InvalidUserError("email", u.Id)
	}

	if utf8.RuneCountInString(u.Name) > USER_NICKNAME_MAX_RUNES {
		return InvalidUserError("nickname", u.Id)
	}

	if len(u.Password) > USER_PASSWORD_MAX_LENGTH {
		return InvalidUserError("password_limit", u.Id)
	}

	return nil
}

func (u *User) Sanitize(ind map[string]bool) {

}

func InvalidUserError(fieldName string, userId string) *AppError {
	id := fmt.Sprintf("model.user.is_valid.%s.app_error", fieldName)
	details := ""
	if userId != "" {
		details = "user_id=" + userId
	}
	return NewAppError("User.IsValid", id, nil, details, http.StatusBadRequest)
}

func (u *User) MakeNonNil() {
	if u.Props == nil {
		u.Props = make(map[string]string)
	}
}

// UserFromJson will decode the input and return a User
func UserFromJson(data io.Reader) *User {
	var user *User
	json.NewDecoder(data).Decode(&user)
	return user
}

func UserMapToJson(u map[string]*User) string {
	b, _ := json.Marshal(u)
	return string(b)
}

func UserMapFromJson(data io.Reader) map[string]*User {
	var users map[string]*User
	json.NewDecoder(data).Decode(&users)
	return users
}

func UserListToJson(u []*User) string {
	b, _ := json.Marshal(u)
	return string(b)
}

// ToJson convert a User to a json string
func (u *User) ToJson() string {
	b, _ := json.Marshal(u)
	return string(b)
}

func UserListFromJson(data io.Reader) []*User {
	var users []*User
	json.NewDecoder(data).Decode(&users)
	return users
}

func (u *User) GetRoles() []string {
	return strings.Fields(u.Roles)
}

func (u *User) GetRawRoles() string {
	return u.Roles
}

func IsValidUserRoles(userRoles string) bool {

	return true
}
