package mysqlstore

import (
	"database/sql"
	"net/http"

	"fmt"
	"lace/mlog"
	"lace/model"
	"lace/store"
	"os"
	"time"
)

type SqlTokenStore struct {
	MySQLStore *MySQLStore
}

func NewMySQLTokenStore(sqlStore *MySQLStore) store.TokenProvider {
	s := &SqlTokenStore{sqlStore}

	for _, db := range sqlStore.GetAllConns() {
		table := db.AddTableWithName(model.Token{}, "Tokens").SetKeys(false, "Token")
		table.ColMap("Token").SetMaxSize(64)
		table.ColMap("Type").SetMaxSize(64)
		table.ColMap("Extra").SetMaxSize(128)
	}

	err := sqlStore.GetMaster().CreateTablesIfNotExists()
	if err != nil {
		mlog.Critical(fmt.Sprintf("create table failed %v ", err))
		os.Exit(EXIT_CREATE_TABLE)
		time.Sleep(time.Second)
	}

	s.CreateIndexesIfNotExists()
	return s
}

func (s SqlTokenStore) CreateIndexesIfNotExists() {
}

func (s SqlTokenStore) Save(token *model.Token) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if result.Err = token.IsValid(); result.Err != nil {
			return
		}

		if err := s.MySQLStore.GetMaster().Insert(token); err != nil {
			result.Err = model.NewAppError("SqlTokenStore.Save", "store.sql_recover.save.app_error", nil, "", http.StatusInternalServerError)
		}
	})
}

func (s SqlTokenStore) Delete(token string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if _, err := s.MySQLStore.GetMaster().Exec("DELETE FROM Tokens WHERE Token = :Token", map[string]interface{}{"Token": token}); err != nil {
			result.Err = model.NewAppError("SqlTokenStore.Delete", "store.sql_recover.delete.app_error", nil, "", http.StatusInternalServerError)
		}
	})
}

func (s SqlTokenStore) GetByToken(tokenString string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		token := model.Token{}

		if err := s.MySQLStore.GetReplica().SelectOne(&token, "SELECT * FROM Tokens WHERE Token = :Token", map[string]interface{}{"Token": tokenString}); err != nil {
			if err == sql.ErrNoRows {
				result.Err = model.NewAppError("SqlTokenStore.GetByToken", "store.sql_recover.get_by_code.app_error", nil, err.Error(), http.StatusBadRequest)
			} else {
				result.Err = model.NewAppError("SqlTokenStore.GetByToken", "store.sql_recover.get_by_code.app_error", nil, err.Error(), http.StatusInternalServerError)
			}
		}

		result.Data = &token
	})
}

func (s SqlTokenStore) Cleanup() {
	mlog.Debug("Cleaning up token store.")
	deltime := model.GetMillis() - model.MAX_TOKEN_EXIPRY_TIME
	if _, err := s.MySQLStore.GetMaster().Exec("DELETE FROM Tokens WHERE CreateAt < :DelTime", map[string]interface{}{"DelTime": deltime}); err != nil {
		mlog.Error("Unable to cleanup token store.")
	}
}
