package mysqlstore

import (
	"fmt"
	"lace/mlog"
	"lace/model"
	"lace/store"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	PROFILE_BY_IDS_CACHE_SEC = 900 // 15 mins
)

var (
	USER_SEARCH_TYPE_NAMES = []string{"Username", "Name"}
	USER_SEARCH_TYPE_ALL   = []string{"Username", "Name", "Email"}
)

type MySQLUserStore struct {
	MySQLStore *MySQLStore
}

func NewMySQLUserStore(mysqldb *MySQLStore) store.UserProvider {
	us := &MySQLUserStore{
		MySQLStore: mysqldb,
	}

	for _, db := range mysqldb.GetAllConns() {
		table := db.AddTableWithName(model.User{}, "Users").SetKeys(false, "Id")
		table.ColMap("Id").SetMaxSize(26)
		table.ColMap("Username").SetMaxSize(64).SetUnique(true)
		table.ColMap("Password").SetMaxSize(128)
		table.ColMap("Email").SetMaxSize(128).SetUnique(true)
		table.ColMap("Name").SetMaxSize(64)
		table.ColMap("Roles").SetMaxSize(256)
		table.ColMap("Props").SetMaxSize(4000)
		table.ColMap("Locale").SetMaxSize(5)
	}

	err := mysqldb.GetMaster().CreateTablesIfNotExists()
	if err != nil {
		mlog.Critical(fmt.Sprintf("create table failed %v ", err))
		os.Exit(EXIT_CREATE_TABLE)
		time.Sleep(time.Second)
	}
	us.CreateIndexesIfNotExists()
	return us
}

func (us MySQLUserStore) CreateIndexesIfNotExists() {
	us.MySQLStore.CreateIndexIfNotExists("idx_users_email", "Users", "Email")
	us.MySQLStore.CreateIndexIfNotExists("idx_users_update_at", "Users", "UpdateAt")
	us.MySQLStore.CreateIndexIfNotExists("idx_users_create_at", "Users", "CreateAt")
	us.MySQLStore.CreateIndexIfNotExists("idx_users_delete_at", "Users", "DeleteAt")
	us.MySQLStore.CreateFullTextIndexIfNotExists("idx_users_all_txt", "Users", strings.Join(USER_SEARCH_TYPE_ALL, ", "))
	us.MySQLStore.CreateFullTextIndexIfNotExists("idx_users_names_txt", "Users", strings.Join(USER_SEARCH_TYPE_NAMES, ", "))
}

func (us MySQLUserStore) Save(user *model.User) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if len(user.Id) > 0 {
			result.Err = model.NewAppError("MySQLUserStore", "MySQLUserStore.Save", nil, "user_id="+user.Id, http.StatusBadRequest)
			return
		}

		user.PreSave()

		if result.Err = user.IsValid(); result.Err != nil {
			return
		}

		if err := us.MySQLStore.GetMaster().Insert(user); err != nil {
			if IsUniqueConstraintError(err, []string{"Email", "users_email_key", "idx_users_email_unique"}) {
				result.Err = model.NewAppError("MySQLUserStore.Save", "store.sql_user.save.email_exists.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusBadRequest)
			} else if IsUniqueConstraintError(err, []string{"Username", "users_username_key", "idx_users_username_unique"}) {
				result.Err = model.NewAppError("MySQLUserStore.Save", "store.sql_user.save.username_exists.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusBadRequest)
			} else {
				result.Err = model.NewAppError("MySQLUserStore.Save", "store.sql_user.save.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusInternalServerError)
			}
		} else {
			result.Data = user
		}
	})
}

func (us MySQLUserStore) Update(user *model.User, trustedUpdateData bool) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		user.PreUpdate()
		if result.Err = user.IsValid(); result.Err != nil {
			return
		}

		if oldUserResult, err := us.MySQLStore.GetMaster().Get(model.User{}, user.Id); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.Update", "store.sql_user.update.finding.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusInternalServerError)
		} else if oldUserResult == nil {
			result.Err = model.NewAppError("MySQLUserStore.Update", "store.sql_user.update.find.app_error", nil, "user_id="+user.Id, http.StatusBadRequest)
		} else {
			oldUser := oldUserResult.(*model.User)
			user.CreateAt = oldUser.CreateAt
			user.Password = oldUser.Password
			user.LastPasswordUpdate = oldUser.LastPasswordUpdate
			user.LastPictureUpdate = oldUser.LastPictureUpdate
			user.EmailVerified = oldUser.EmailVerified
			user.FailedAttempts = oldUser.FailedAttempts

			if !trustedUpdateData {
				user.Roles = oldUser.Roles
				user.DeleteAt = oldUser.DeleteAt
			}

			if user.Username != oldUser.Username {
				result.Err = model.NewAppError("MySQLUserStore.Update", "store.sql_user.update.can_not_change_ldap.app_error", nil, "user_id="+user.Id, http.StatusBadRequest)
				return
			}

			if user.Email != oldUser.Email {
				user.EmailVerified = false
			}

			if count, err := us.MySQLStore.GetMaster().Update(user); err != nil {
				if IsUniqueConstraintError(err, []string{"Email", "users_email_key", "idx_users_email_unique"}) {
					result.Err = model.NewAppError("MySQLUserStore.Update", "store.sql_user.update.email_taken.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusBadRequest)
				} else if IsUniqueConstraintError(err, []string{"Username", "users_username_key", "idx_users_username_unique"}) {
					result.Err = model.NewAppError("MySQLUserStore.Update", "store.sql_user.update.username_taken.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusBadRequest)
				} else {
					result.Err = model.NewAppError("MySQLUserStore.Update", "store.sql_user.update.updating.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusInternalServerError)
				}
			} else if count != 1 {
				result.Err = model.NewAppError("MySQLUserStore.Update", "store.sql_user.update.app_error", nil, fmt.Sprintf("user_id=%v, count=%v", user.Id, count), http.StatusInternalServerError)
			} else {
				user.Sanitize(map[string]bool{})
				oldUser.Sanitize(map[string]bool{})
				result.Data = [2]*model.User{user, oldUser}
			}
		}
	})
}

func (us MySQLUserStore) UpdateLastPictureUpdate(userId string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		curTime := model.GetMillis()
		if _, err := us.MySQLStore.GetMaster().Exec("UPDATE Users SET LastPictureUpdate = :Time, UpdateAt = :Time WHERE Id = :UserId", map[string]interface{}{"Time": curTime, "UserId": userId}); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.UpdateUpdateAt", "store.sql_user.update_last_picture_update.app_error", nil, "user_id="+userId, http.StatusInternalServerError)
		} else {
			result.Data = userId
		}
	})
}

func (us MySQLUserStore) ResetLastPictureUpdate(userId string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if _, err := us.MySQLStore.GetMaster().Exec("UPDATE Users SET LastPictureUpdate = :Time, UpdateAt = :Time WHERE Id = :UserId", map[string]interface{}{"Time": 0, "UserId": userId}); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.UpdateUpdateAt", "store.sql_user.update_last_picture_update.app_error", nil, "user_id="+userId, http.StatusInternalServerError)
		} else {
			result.Data = userId
		}
	})
}

func (us MySQLUserStore) UpdateUpdateAt(userId string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		curTime := model.GetMillis()

		if _, err := us.MySQLStore.GetMaster().Exec("UPDATE Users SET UpdateAt = :Time WHERE Id = :UserId", map[string]interface{}{"Time": curTime, "UserId": userId}); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.UpdateUpdateAt", "store.sql_user.update_update.app_error", nil, "user_id="+userId, http.StatusInternalServerError)
		} else {
			result.Data = userId
		}
	})
}

func (us MySQLUserStore) UpdatePassword(userId, hashedPassword string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		updateAt := model.GetMillis()

		if _, err := us.MySQLStore.GetMaster().Exec("UPDATE Users SET Password = :Password, LastPasswordUpdate = :LastPasswordUpdate, UpdateAt = :UpdateAt, AuthData = NULL, AuthService = '', EmailVerified = true, FailedAttempts = 0 WHERE Id = :UserId", map[string]interface{}{"Password": hashedPassword, "LastPasswordUpdate": updateAt, "UpdateAt": updateAt, "UserId": userId}); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.UpdatePassword", "store.sql_user.update_password.app_error", nil, "id="+userId+", "+err.Error(), http.StatusInternalServerError)
		} else {
			result.Data = userId
		}
	})
}

func (us MySQLUserStore) UpdateFailedPasswordAttempts(userId string, attempts int) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if _, err := us.MySQLStore.GetMaster().Exec("UPDATE Users SET FailedAttempts = :FailedAttempts WHERE Id = :UserId", map[string]interface{}{"FailedAttempts": attempts, "UserId": userId}); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.UpdateFailedPasswordAttempts", "store.sql_user.update_failed_pwd_attempts.app_error", nil, "user_id="+userId, http.StatusInternalServerError)
		} else {
			result.Data = userId
		}
	})
}

func (us MySQLUserStore) Get(id string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if obj, err := us.MySQLStore.GetReplica().Get(model.User{}, id); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.Get", "store.sql_user.get.app_error", nil, "user_id="+id+", "+err.Error(), http.StatusInternalServerError)
		} else if obj == nil {
			result.Err = model.NewAppError("MySQLUserStore.Get", "MISSING_ACCOUNT_ERROR", nil, "user_id="+id, http.StatusNotFound)
		} else {
			result.Data = obj.(*model.User)
		}
	})
}

func (us MySQLUserStore) GetAll() store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		var data []*model.User
		if _, err := us.MySQLStore.GetReplica().Select(&data, "SELECT * FROM Users"); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.GetAll", "store.sql_user.get.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		result.Data = data
	})
}

func (us MySQLUserStore) GetAllAfter(limit int, afterId string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		var data []*model.User
		if _, err := us.MySQLStore.GetReplica().Select(&data, "SELECT * FROM Users WHERE Id > :AfterId ORDER BY Id LIMIT :Limit", map[string]interface{}{"AfterId": afterId, "Limit": limit}); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.GetAllAfter", "store.sql_user.get.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		result.Data = data
	})
}

func (s MySQLUserStore) GetEtagForAllProfiles() store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		updateAt, err := s.MySQLStore.GetReplica().SelectInt("SELECT UpdateAt FROM Users ORDER BY UpdateAt DESC LIMIT 1")
		if err != nil {
			result.Data = fmt.Sprintf("%v.%v", model.CurrentVersion, model.GetMillis())
		} else {
			result.Data = fmt.Sprintf("%v.%v", model.CurrentVersion, updateAt)
		}
	})
}

func (us MySQLUserStore) GetAllProfiles(offset int, limit int) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		var users []*model.User

		if _, err := us.MySQLStore.GetReplica().Select(&users, "SELECT * FROM Users ORDER BY Username ASC LIMIT :Limit OFFSET :Offset", map[string]interface{}{"Offset": offset, "Limit": limit}); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.GetAllProfiles", "store.sql_user.get_profiles.app_error", nil, err.Error(), http.StatusInternalServerError)
		} else {

			for _, u := range users {
				u.Sanitize(map[string]bool{})
			}

			result.Data = users
		}
	})
}

func (us MySQLUserStore) GetProfileByIds(userIds []string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		users := []*model.User{}
		props := make(map[string]interface{})
		idQuery := ""

		for index, userId := range userIds {
			if len(idQuery) > 0 {
				idQuery += ", "
			}
			props["userId"+strconv.Itoa(index)] = userId
			idQuery += ":userId" + strconv.Itoa(index)
		}

		if _, err := us.MySQLStore.GetReplica().Select(&users, "SELECT * FROM Users WHERE Users.Id IN ("+idQuery+")", props); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.GetProfileByIds", "store.sql_user.get_profiles.app_error", nil, err.Error(), http.StatusInternalServerError)
		} else {
			result.Data = users
		}
	})
}

func (us MySQLUserStore) GetByEmail(email string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		email = strings.ToLower(email)

		user := model.User{}

		if err := us.MySQLStore.GetReplica().SelectOne(&user, "SELECT * FROM Users WHERE Email = :Email", map[string]interface{}{"Email": email}); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.GetByEmail", "MISSING_ACCOUNT_ERROR", nil, "email="+email+", "+err.Error(), http.StatusInternalServerError)
		}

		result.Data = &user
	})
}

func (us MySQLUserStore) GetByUsername(username string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		user := model.User{}

		if err := us.MySQLStore.GetReplica().SelectOne(&user, "SELECT * FROM Users WHERE Username = :Username", map[string]interface{}{"Username": username}); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.GetByUsername", "store.sql_user.get_by_username.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		result.Data = &user
	})
}

func (us MySQLUserStore) GetForLogin(loginId string, allowSignInWithUsername, allowSignInWithEmail bool) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		params := map[string]interface{}{
			"LoginId":                 loginId,
			"AllowSignInWithUsername": allowSignInWithUsername,
			"AllowSignInWithEmail":    allowSignInWithEmail,
		}

		users := []*model.User{}
		if _, err := us.MySQLStore.GetReplica().Select(
			&users,
			`SELECT
				*
			FROM
				Users
			WHERE
				(:AllowSignInWithUsername AND Username = :LoginId)
				OR (:AllowSignInWithEmail AND Email = :LoginId)`,
			params); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.GetForLogin", "store.sql_user.get_for_login.app_error", nil, err.Error(), http.StatusInternalServerError)
		} else if len(users) == 1 {
			result.Data = users[0]
		} else if len(users) > 1 {
			result.Err = model.NewAppError("MySQLUserStore.GetForLogin", "store.sql_user.get_for_login.multiple_users", nil, "", http.StatusInternalServerError)
		} else {
			result.Err = model.NewAppError("MySQLUserStore.GetForLogin", "store.sql_user.get_for_login.app_error", nil, "", http.StatusInternalServerError)
		}
	})
}

func (us MySQLUserStore) VerifyEmail(userId string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if _, err := us.MySQLStore.GetMaster().Exec("UPDATE Users SET EmailVerified = true WHERE Id = :UserId", map[string]interface{}{"UserId": userId}); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.VerifyEmail", "store.sql_user.verify_email.app_error", nil, "userId="+userId+", "+err.Error(), http.StatusInternalServerError)
		}

		result.Data = userId
	})
}

func (us MySQLUserStore) GetTotalUsersCount() store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if count, err := us.MySQLStore.GetReplica().SelectInt("SELECT COUNT(Id) FROM Users"); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.GetTotalUsersCount", "store.sql_user.get_total_users_count.app_error", nil, err.Error(), http.StatusInternalServerError)
		} else {
			result.Data = count
		}
	})
}

func (us MySQLUserStore) PermanentDelete(userId string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if _, err := us.MySQLStore.GetMaster().Exec("DELETE FROM Users WHERE Id = :UserId", map[string]interface{}{"UserId": userId}); err != nil {
			result.Err = model.NewAppError("MySQLUserStore.PermanentDelete", "store.sql_user.permanent_delete.app_error", nil, "userId="+userId+", "+err.Error(), http.StatusInternalServerError)
		}
	})
}

var escapeLikeSearchChar = []string{
	"%",
	"_",
}

var ignoreLikeSearchChar = []string{
	"*",
}

var spaceFulltextSearchChar = []string{
	"<",
	">",
	"+",
	"-",
	"(",
	")",
	"~",
	":",
	"*",
	"\"",
	"!",
	"@",
}

func generateSearchQuery(searchQuery string, terms []string, fields []string, parameters map[string]interface{}, isPostgreSQL bool) string {
	searchTerms := []string{}
	for i, term := range terms {
		searchFields := []string{}
		for _, field := range fields {
			if isPostgreSQL {
				searchFields = append(searchFields, fmt.Sprintf("lower(%s) LIKE lower(%s) escape '*' ", field, fmt.Sprintf(":Term%d", i)))
			} else {
				searchFields = append(searchFields, fmt.Sprintf("%s LIKE %s escape '*' ", field, fmt.Sprintf(":Term%d", i)))
			}
		}
		searchTerms = append(searchTerms, fmt.Sprintf("(%s)", strings.Join(searchFields, " OR ")))
		parameters[fmt.Sprintf("Term%d", i)] = fmt.Sprintf("%s%%", strings.TrimLeft(term, "@"))
	}

	searchClause := strings.Join(searchTerms, " AND ")
	return strings.Replace(searchQuery, "SEARCH_CLAUSE", fmt.Sprintf(" AND %s ", searchClause), 1)
}
