package mysqlstore

import (
	"database/sql"
	"fmt"
	"lace/mlog"
	"lace/model"
	"lace/store"
	"lace/utils"
	"net/http"
	"os"
	"time"
)

type SqlFileInfoStore struct {
	MySQLStore *MySQLStore
}

const (
	FILE_INFO_CACHE_SIZE = 25000
	FILE_INFO_CACHE_SEC  = 1800 // 30 minutes
)

var fileInfoCache *utils.Cache = utils.NewLru(FILE_INFO_CACHE_SIZE)

func (fs SqlFileInfoStore) ClearCaches() {
	fileInfoCache.Purge()
}

func NewMySQLFileInfoStore(mysqlStore *MySQLStore) store.FileInfoProvider {
	s := &SqlFileInfoStore{
		MySQLStore: mysqlStore,
	}

	for _, db := range mysqlStore.GetAllConns() {
		table := db.AddTableWithName(model.FileInfo{}, "FileInfo").SetKeys(false, "Id")
		table.ColMap("Id").SetMaxSize(26)
		table.ColMap("CreatorId").SetMaxSize(26)
		table.ColMap("Path").SetMaxSize(512)
		table.ColMap("ThumbnailPath").SetMaxSize(512)
		table.ColMap("PreviewPath").SetMaxSize(512)
		table.ColMap("Name").SetMaxSize(256)
		table.ColMap("Extension").SetMaxSize(64)
		table.ColMap("MimeType").SetMaxSize(256)
	}

	err := mysqlStore.GetMaster().CreateTablesIfNotExists()
	if err != nil {
		mlog.Critical(fmt.Sprintf("Error creating database tables: %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_CREATE_TABLE)
	}
	s.CreateIndexesIfNotExists()
	return s
}

func (fs SqlFileInfoStore) CreateIndexesIfNotExists() {
	fs.MySQLStore.CreateIndexIfNotExists("idx_fileinfo_update_at", "FileInfo", "UpdateAt")
	fs.MySQLStore.CreateIndexIfNotExists("idx_fileinfo_create_at", "FileInfo", "CreateAt")
	fs.MySQLStore.CreateIndexIfNotExists("idx_fileinfo_delete_at", "FileInfo", "DeleteAt")
}

func (fs SqlFileInfoStore) Save(info *model.FileInfo) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		info.PreSave()
		if result.Err = info.IsValid(); result.Err != nil {
			return
		}

		if err := fs.MySQLStore.GetMaster().Insert(info); err != nil {
			result.Err = model.NewAppError("SqlFileInfoStore.Save", "store.sql_file_info.save.app_error", nil, err.Error(), http.StatusInternalServerError)
		} else {
			result.Data = info
		}
	})
}

func (fs SqlFileInfoStore) Get(id string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		info := &model.FileInfo{}

		if err := fs.MySQLStore.GetReplica().SelectOne(info,
			`SELECT
				*
			FROM
				FileInfo
			WHERE
				Id = :Id
				AND DeleteAt = 0`, map[string]interface{}{"Id": id}); err != nil {
			if err == sql.ErrNoRows {
				result.Err = model.NewAppError("SqlFileInfoStore.Get", "store.sql_file_info.get.app_error", nil, "id="+id+", "+err.Error(), http.StatusNotFound)
			} else {
				result.Err = model.NewAppError("SqlFileInfoStore.Get", "store.sql_file_info.get.app_error", nil, "id="+id+", "+err.Error(), http.StatusInternalServerError)
			}
		} else {
			result.Data = info
		}
	})
}

func (fs SqlFileInfoStore) GetByPath(path string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		info := &model.FileInfo{}

		if err := fs.MySQLStore.GetReplica().SelectOne(info,
			`SELECT
				*
			FROM
				FileInfo
			WHERE
				Path = :Path
				AND DeleteAt = 0
			LIMIT 1`, map[string]interface{}{"Path": path}); err != nil {
			result.Err = model.NewAppError("SqlFileInfoStore.GetByPath", "store.sql_file_info.get_by_path.app_error", nil, "path="+path+", "+err.Error(), http.StatusInternalServerError)
		} else {
			result.Data = info
		}
	})
}

func (fs SqlFileInfoStore) GetForUser(userId string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		var infos []*model.FileInfo

		dbmap := fs.MySQLStore.GetReplica()

		if _, err := dbmap.Select(&infos,
			`SELECT
				*
			FROM
				FileInfo
			WHERE
				CreatorId = :CreatorId
				AND DeleteAt = 0
			ORDER BY
				CreateAt`, map[string]interface{}{"CreatorId": userId}); err != nil {
			result.Err = model.NewAppError("SqlFileInfoStore.GetForUser",
				"store.sql_file_info.get_for_user_id.app_error", nil, "creator_id="+userId+", "+err.Error(), http.StatusInternalServerError)
		} else {
			result.Data = infos
		}
	})
}

func (fs SqlFileInfoStore) PermanentDelete(fileId string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		if _, err := fs.MySQLStore.GetMaster().Exec(
			`DELETE FROM
				FileInfo
			WHERE
				Id = :FileId`, map[string]interface{}{"FileId": fileId}); err != nil {
			result.Err = model.NewAppError("SqlFileInfoStore.PermanentDelete",
				"store.sql_file_info.permanent_delete.app_error", nil, "file_id="+fileId+", err="+err.Error(), http.StatusInternalServerError)
		}
	})
}

func (s SqlFileInfoStore) PermanentDeleteBatch(endTime int64, limit int64) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		var query string
		query = "DELETE from FileInfo WHERE CreateAt < :EndTime LIMIT :Limit"

		sqlResult, err := s.MySQLStore.GetMaster().Exec(query, map[string]interface{}{"EndTime": endTime, "Limit": limit})
		if err != nil {
			result.Err = model.NewAppError("SqlFileInfoStore.PermanentDeleteBatch", "store.sql_file_info.permanent_delete_batch.app_error", nil, ""+err.Error(), http.StatusInternalServerError)
		} else {
			rowsAffected, err1 := sqlResult.RowsAffected()
			if err1 != nil {
				result.Err = model.NewAppError("SqlFileInfoStore.PermanentDeleteBatch", "store.sql_file_info.permanent_delete_batch.app_error", nil, ""+err.Error(), http.StatusInternalServerError)
				result.Data = int64(0)
			} else {
				result.Data = rowsAffected
			}
		}
	})
}

func (s SqlFileInfoStore) PermanentDeleteByUser(userId string) store.StoreChannel {
	return store.Do(func(result *store.StoreResult) {
		query := "DELETE from FileInfo WHERE CreatorId = :CreatorId"

		sqlResult, err := s.MySQLStore.GetMaster().Exec(query, map[string]interface{}{"CreatorId": userId})
		if err != nil {
			result.Err = model.NewAppError("SqlFileInfoStore.PermanentDeleteByUser", "store.sql_file_info.PermanentDeleteByUser.app_error", nil, ""+err.Error(), http.StatusInternalServerError)
		} else {
			rowsAffected, err1 := sqlResult.RowsAffected()
			if err1 != nil {
				result.Err = model.NewAppError("SqlFileInfoStore.PermanentDeleteByUser", "store.sql_file_info.PermanentDeleteByUser.app_error", nil, ""+err.Error(), http.StatusInternalServerError)
				result.Data = int64(0)
			} else {
				result.Data = rowsAffected
			}
		}
	})
}
