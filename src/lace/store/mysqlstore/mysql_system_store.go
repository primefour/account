package mysqlstore

import (
	"fmt"
	"lace/mlog"
	"lace/model"
	"lace/store"
	"net/http"
	"os"
	"time"
)

type SqlSystemStore struct {
	MySQLStore *MySQLStore
}

func NewSqlSystemStore(sqlStore *MySQLStore) store.SystemProvider {
	s := &SqlSystemStore{
		MySQLStore: sqlStore,
	}

	for _, db := range sqlStore.GetAllConns() {
		table := db.AddTableWithName(model.System{}, "Systems").SetKeys(false, "Name")
		table.ColMap("Name").SetMaxSize(64)
		table.ColMap("Value").SetMaxSize(1024)
	}

	err := sqlStore.GetMaster().CreateTablesIfNotExists()
	if err != nil {
		mlog.Critical(fmt.Sprintf("Error creating database tables: %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_CREATE_TABLE)
	}

	s.CreateIndexesIfNotExists()
	return s
}

func (s SqlSystemStore) CreateIndexesIfNotExists() {

}

func (s SqlSystemStore) Save(system *model.System) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if err := s.MySQLStore.GetMaster().Insert(system); err != nil {
			result.Err = model.NewAppError("SqlSystemStore.Save", "store.sql_system.save.app_error", nil, err.Error(), http.StatusInternalServerError)
		}
	})
}

func (s SqlSystemStore) SaveOrUpdate(system *model.System) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if err := s.MySQLStore.GetReplica().SelectOne(&model.System{}, "SELECT * FROM Systems WHERE Name = :Name", map[string]interface{}{"Name": system.Name}); err == nil {
			if _, err := s.MySQLStore.GetMaster().Update(system); err != nil {
				result.Err = model.NewAppError("SqlSystemStore.SaveOrUpdate", "store.sql_system.update.app_error", nil, err.Error(), http.StatusInternalServerError)
			}
		} else {
			if err := s.MySQLStore.GetMaster().Insert(system); err != nil {
				result.Err = model.NewAppError("SqlSystemStore.SaveOrUpdate", "store.sql_system.save.app_error", nil, err.Error(), http.StatusInternalServerError)
			}
		}
	})
}

func (s SqlSystemStore) Update(system *model.System) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if _, err := s.MySQLStore.GetMaster().Update(system); err != nil {
			result.Err = model.NewAppError("SqlSystemStore.Update", "store.sql_system.update.app_error", nil, err.Error(), http.StatusInternalServerError)
		}
	})
}

func (s SqlSystemStore) Get() store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		var systems []model.System
		props := make(model.StringMap)
		if _, err := s.MySQLStore.GetReplica().Select(&systems, "SELECT * FROM Systems"); err != nil {
			result.Err = model.NewAppError("SqlSystemStore.Get", "store.sql_system.get.app_error", nil, err.Error(), http.StatusInternalServerError)
		} else {
			for _, prop := range systems {
				props[prop.Name] = prop.Value
			}

			result.Data = props
		}
	})
}

func (s SqlSystemStore) GetByName(name string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		var system model.System
		if err := s.MySQLStore.GetReplica().SelectOne(&system, "SELECT * FROM Systems WHERE Name = :Name", map[string]interface{}{"Name": name}); err != nil {
			result.Err = model.NewAppError("SqlSystemStore.GetByName", "store.sql_system.get_by_name.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		result.Data = &system
	})
}

func (s SqlSystemStore) PermanentDeleteByName(name string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		var system model.System
		if _, err := s.MySQLStore.GetMaster().Exec("DELETE FROM Systems WHERE Name = :Name", map[string]interface{}{"Name": name}); err != nil {
			result.Err = model.NewAppError("SqlSystemStore.PermanentDeleteByName", "store.sql_system.permanent_delete_by_name.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		result.Data = &system
	})
}
