package mysqlstore

import (
	"context"
	dbsql "database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-sql-driver/mysql"
	gorp "gopkg.in/gorp.v2"
	"lace/mlog"
	"lace/model"
	"lace/store"
	sqltrace "log"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const (
	INDEX_TYPE_FULL_TEXT = "full_text"
	INDEX_TYPE_DEFAULT   = "default"
	DB_PING_ATTEMPTS     = 18
	DB_PING_TIMEOUT_SECS = 10
)

const (
	EXIT_GENERIC_FAILURE             = 1
	EXIT_CREATE_TABLE                = 100
	EXIT_DB_OPEN                     = 101
	EXIT_PING                        = 102
	EXIT_NO_DRIVER                   = 103
	EXIT_TABLE_EXISTS                = 104
	EXIT_TABLE_EXISTS_MYSQL          = 105
	EXIT_COLUMN_EXISTS               = 106
	EXIT_DOES_COLUMN_EXISTS_POSTGRES = 107
	EXIT_DOES_COLUMN_EXISTS_MYSQL    = 108
	EXIT_DOES_COLUMN_EXISTS_MISSING  = 109
	EXIT_CREATE_COLUMN_POSTGRES      = 110
	EXIT_CREATE_COLUMN_MYSQL         = 111
	EXIT_CREATE_COLUMN_MISSING       = 112
	EXIT_REMOVE_COLUMN               = 113
	EXIT_RENAME_COLUMN               = 114
	EXIT_MAX_COLUMN                  = 115
	EXIT_ALTER_COLUMN                = 116
	EXIT_CREATE_INDEX_POSTGRES       = 117
	EXIT_CREATE_INDEX_MYSQL          = 118
	EXIT_CREATE_INDEX_FULL_MYSQL     = 119
	EXIT_CREATE_INDEX_MISSING        = 120
	EXIT_REMOVE_INDEX_POSTGRES       = 121
	EXIT_REMOVE_INDEX_MYSQL          = 122
	EXIT_REMOVE_INDEX_MISSING        = 123
	EXIT_REMOVE_TABLE                = 134
	EXIT_CREATE_INDEX_SQLITE         = 135
	EXIT_REMOVE_INDEX_SQLITE         = 136
	EXIT_TABLE_EXISTS_SQLITE         = 137
	EXIT_DOES_COLUMN_EXISTS_SQLITE   = 138
)

type MySQLStore struct {
	rrCounter      int64
	srCounter      int64
	master         *gorp.DbMap
	replicas       []*gorp.DbMap
	searchReplicas []*gorp.DbMap
	user           store.UserProvider
	token          store.TokenProvider
	fileInfo       store.FileInfoProvider
	session        store.SessionProvider
	settings       *model.SqlSettings
	lockedToMaster bool
}

func UpgradeDatabase(mysqlStore *MySQLStore) {

}

func NewMySQLStore(settings *model.SqlSettings) store.MySQLProvider {
	mysqlStore := &MySQLStore{
		rrCounter: 0,
		srCounter: 0,
		settings:  settings,
	}

	mysqlStore.initConnection()

	mysqlStore.user = NewMySQLUserStore(mysqlStore)
	mysqlStore.token = NewMySQLTokenStore(mysqlStore)
	mysqlStore.fileInfo = NewMySQLFileInfoStore(mysqlStore)
	mysqlStore.session = NewMySQLSessonStore(mysqlStore)

	err := mysqlStore.GetMaster().CreateTablesIfNotExists()
	if err != nil {
		mlog.Critical(fmt.Sprintf("Error creating database tables: %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_CREATE_TABLE)
	}

	UpgradeDatabase(mysqlStore)
	return mysqlStore
}

//create a mysql connection pool
func setupConnection(con_type string, dataSource string, settings *model.SqlSettings) *gorp.DbMap {
	db, err := dbsql.Open(*settings.DriverName, dataSource)
	if err != nil {
		mlog.Critical(fmt.Sprintf("Failed to open SQL connection to err:%v", err.Error()))
		time.Sleep(time.Second)
		os.Exit(EXIT_DB_OPEN)
	}

	for i := 0; i < DB_PING_ATTEMPTS; i++ {
		mlog.Info(fmt.Sprintf("Pinging SQL %v database", con_type))
		ctx, cancel := context.WithTimeout(context.Background(), DB_PING_TIMEOUT_SECS*time.Second)
		defer cancel()
		err = db.PingContext(ctx)
		if err == nil {
			break
		} else {
			if i == DB_PING_ATTEMPTS-1 {
				mlog.Critical(fmt.Sprintf("Failed to ping DB, server will exit err=%v", err))
				time.Sleep(time.Second)
				os.Exit(EXIT_PING)
			} else {
				mlog.Error(fmt.Sprintf("Failed to ping DB retrying in %v seconds err=%v", DB_PING_TIMEOUT_SECS, err))
				time.Sleep(DB_PING_TIMEOUT_SECS * time.Second)
			}
		}
	}

	db.SetMaxIdleConns(*settings.MaxIdleConns)
	db.SetMaxOpenConns(*settings.MaxOpenConns)
	db.SetConnMaxLifetime(time.Duration(*settings.ConnMaxLifetimeMilliseconds) * time.Millisecond)

	var dbmap *gorp.DbMap
	//connectionTimeout := time.Duration(*settings.QueryTimeout) * time.Second
	dbmap = &gorp.DbMap{Db: db, TypeConverter: mattermConverter{},
		Dialect: gorp.MySQLDialect{Engine: "InnoDB", Encoding: "UTF8MB4"}}
	//QueryTimeout: connectionTimeout}

	if settings.Trace {
		dbmap.TraceOn("", sqltrace.New(os.Stdout, "sql-trace:", sqltrace.Lmicroseconds))
	}

	return dbmap
}

func (s *MySQLStore) initConnection() {
	s.master = setupConnection("master", *s.settings.DataSource, s.settings)

	if len(s.settings.DataSourceReplicas) > 0 {
		s.replicas = make([]*gorp.DbMap, len(s.settings.DataSourceReplicas))
		for i, replica := range s.settings.DataSourceReplicas {
			s.replicas[i] = setupConnection(fmt.Sprintf("replica-%v", i), replica, s.settings)
		}
	}

	if len(s.settings.DataSourceSearchReplicas) > 0 {
		s.searchReplicas = make([]*gorp.DbMap, len(s.settings.DataSourceSearchReplicas))
		for i, replica := range s.settings.DataSourceSearchReplicas {
			s.searchReplicas[i] = setupConnection(fmt.Sprintf("search-replica-%v", i), replica, s.settings)
		}
	}
}

func (ss *MySQLStore) DriverName() string {
	return *ss.settings.DriverName
}

func (ss *MySQLStore) GetCurrentSchemaVersion() string {
	version, _ := ss.GetMaster().SelectStr("SELECT Value FROM Systems WHERE Name='Version'")
	return version
}

func (ss *MySQLStore) GetMaster() *gorp.DbMap {
	return ss.master
}

func (ss *MySQLStore) GetSearchReplica() *gorp.DbMap {
	if len(ss.settings.DataSourceSearchReplicas) == 0 {
		return ss.GetReplica()
	}

	rrNum := atomic.AddInt64(&ss.srCounter, 1) % int64(len(ss.searchReplicas))
	return ss.searchReplicas[rrNum]
}

func (ss *MySQLStore) GetReplica() *gorp.DbMap {
	if len(ss.settings.DataSourceReplicas) == 0 || ss.lockedToMaster {
		return ss.GetMaster()
	}

	rrNum := atomic.AddInt64(&ss.rrCounter, 1) % int64(len(ss.replicas))
	return ss.replicas[rrNum]
}

func (ss *MySQLStore) TotalMasterDbConnections() int {
	return ss.GetMaster().Db.Stats().OpenConnections
}

func (ss *MySQLStore) TotalReadDbConnections() int {
	if len(ss.settings.DataSourceReplicas) == 0 {
		return 0
	}

	count := 0
	for _, db := range ss.replicas {
		count = count + db.Db.Stats().OpenConnections
	}

	return count
}

func (ss *MySQLStore) TotalSearchDbConnections() int {
	if len(ss.settings.DataSourceSearchReplicas) == 0 {
		return 0
	}

	count := 0
	for _, db := range ss.searchReplicas {
		count = count + db.Db.Stats().OpenConnections
	}

	return count
}

func (ss *MySQLStore) DoesTableExist(tableName string) bool {
	count, err := ss.GetMaster().SelectInt(
		`SELECT
		COUNT(0) AS table_exists
		FROM
		information_schema.TABLES
		WHERE
		TABLE_SCHEMA = DATABASE()
		AND TABLE_NAME = ?
		`,
		tableName,
	)

	if err != nil {
		mlog.Critical(fmt.Sprintf("Failed to check if table exists %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_TABLE_EXISTS_MYSQL)
	}

	return count > 0

}

func (ss *MySQLStore) DoesColumnExist(tableName string, columnName string) bool {
	count, err := ss.GetMaster().SelectInt(
		`SELECT
		COUNT(0) AS column_exists
		FROM
		information_schema.COLUMNS
		WHERE
		TABLE_SCHEMA = DATABASE()
		AND TABLE_NAME = ?
		AND COLUMN_NAME = ?`,
		tableName,
		columnName,
	)

	if err != nil {
		mlog.Critical(fmt.Sprintf("Failed to check if column exists %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_DOES_COLUMN_EXISTS_MYSQL)
	}

	return count > 0

}

func (ss *MySQLStore) DoesTriggerExist(triggerName string) bool {
	count, err := ss.GetMaster().SelectInt(`
	SELECT
	COUNT(0)
	FROM
	information_schema.triggers
	WHERE
	trigger_schema = DATABASE()
	AND	trigger_name = ?
	`, triggerName)

	if err != nil {
		mlog.Critical(fmt.Sprintf("Failed to check if trigger exists %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_GENERIC_FAILURE)
	}

	return count > 0

}

func (ss *MySQLStore) CreateColumnIfNotExists(tableName string, columnName string, mySqlColType string, postgresColType string, defaultValue string) bool {

	if ss.DoesColumnExist(tableName, columnName) {
		return false
	}
	_, err := ss.GetMaster().Exec("ALTER TABLE " + tableName + " ADD " + columnName + " " + mySqlColType + " DEFAULT '" + defaultValue + "'")
	if err != nil {
		mlog.Critical(fmt.Sprintf("Failed to create column %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_CREATE_COLUMN_MYSQL)
	}

	return true

}

func (ss *MySQLStore) CreateColumnIfNotExistsNoDefault(tableName string, columnName string, mySqlColType string, postgresColType string) bool {

	if ss.DoesColumnExist(tableName, columnName) {
		return false
	}
	_, err := ss.GetMaster().Exec("ALTER TABLE " + tableName + " ADD " + columnName + " " + mySqlColType)
	if err != nil {
		mlog.Critical(fmt.Sprintf("Failed to create column %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_CREATE_COLUMN_MYSQL)
	}
	return true

}

func (ss *MySQLStore) RemoveColumnIfExists(tableName string, columnName string) bool {

	if !ss.DoesColumnExist(tableName, columnName) {
		return false
	}

	_, err := ss.GetMaster().Exec("ALTER TABLE " + tableName + " DROP COLUMN " + columnName)
	if err != nil {
		mlog.Critical(fmt.Sprintf("Failed to drop column %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_REMOVE_COLUMN)
	}

	return true
}

func (ss *MySQLStore) RemoveTableIfExists(tableName string) bool {
	if !ss.DoesTableExist(tableName) {
		return false
	}

	_, err := ss.GetMaster().Exec("DROP TABLE " + tableName)
	if err != nil {
		mlog.Critical(fmt.Sprintf("Failed to drop table %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_REMOVE_TABLE)
	}

	return true
}

func (ss *MySQLStore) RenameColumnIfExists(tableName string, oldColumnName string, newColumnName string, colType string) bool {
	if !ss.DoesColumnExist(tableName, oldColumnName) {
		return false
	}

	var err error
	_, err = ss.GetMaster().Exec("ALTER TABLE " + tableName + " CHANGE " + oldColumnName + " " + newColumnName + " " + colType)
	if err != nil {
		mlog.Critical(fmt.Sprintf("Failed to rename column %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_RENAME_COLUMN)
	}

	return true
}

func (ss *MySQLStore) GetMaxLengthOfColumnIfExists(tableName string, columnName string) string {
	if !ss.DoesColumnExist(tableName, columnName) {
		return ""
	}
	var result string
	var err error
	result, err = ss.GetMaster().SelectStr("SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.columns WHERE table_name = '" + tableName + "' AND COLUMN_NAME = '" + columnName + "'")

	if err != nil {
		mlog.Critical(fmt.Sprintf("Failed to get max length of column %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_MAX_COLUMN)
	}

	return result
}

func (ss *MySQLStore) AlterColumnTypeIfExists(tableName string, columnName string, mySqlColType string, postgresColType string) bool {
	if !ss.DoesColumnExist(tableName, columnName) {
		return false
	}
	var err error
	_, err = ss.GetMaster().Exec("ALTER TABLE " + tableName + " MODIFY " + columnName + " " + mySqlColType)
	if err != nil {
		mlog.Critical(fmt.Sprintf("Failed to alter column type %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_ALTER_COLUMN)
	}

	return true
}

func (ss *MySQLStore) CreateUniqueIndexIfNotExists(indexName string, tableName string, columnName string) bool {
	return ss.createIndexIfNotExists(indexName, tableName, []string{columnName}, INDEX_TYPE_DEFAULT, true)
}

func (ss *MySQLStore) CreateIndexIfNotExists(indexName string, tableName string, columnName string) bool {
	return ss.createIndexIfNotExists(indexName, tableName, []string{columnName}, INDEX_TYPE_DEFAULT, false)
}

func (ss *MySQLStore) CreateCompositeIndexIfNotExists(indexName string, tableName string, columnNames []string) bool {
	return ss.createIndexIfNotExists(indexName, tableName, columnNames, INDEX_TYPE_DEFAULT, false)
}

func (ss *MySQLStore) CreateFullTextIndexIfNotExists(indexName string, tableName string, columnName string) bool {
	return ss.createIndexIfNotExists(indexName, tableName, []string{columnName}, INDEX_TYPE_FULL_TEXT, false)
}

func (ss *MySQLStore) createIndexIfNotExists(indexName string, tableName string, columnNames []string, indexType string, unique bool) bool {
	uniqueStr := ""
	if unique {
		uniqueStr = "UNIQUE "
	}

	count, err := ss.GetMaster().SelectInt("SELECT COUNT(0) AS index_exists FROM information_schema.statistics WHERE TABLE_SCHEMA = DATABASE() and table_name = ? AND index_name = ?", tableName, indexName)
	if err != nil {
		mlog.Critical(fmt.Sprintf("Failed to check index %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_CREATE_INDEX_MYSQL)
	}

	if count > 0 {
		return false
	}

	fullTextIndex := ""
	if indexType == INDEX_TYPE_FULL_TEXT {
		fullTextIndex = " FULLTEXT "
	}

	_, err = ss.GetMaster().Exec("CREATE  " + uniqueStr + fullTextIndex + " INDEX " + indexName + " ON " + tableName + " (" + strings.Join(columnNames, ", ") + ")")
	if err != nil {
		mlog.Critical(fmt.Sprintf("Failed to create index %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_CREATE_INDEX_FULL_MYSQL)
	}

	return true
}

func (ss *MySQLStore) RemoveIndexIfExists(indexName string, tableName string) bool {

	count, err := ss.GetMaster().SelectInt("SELECT COUNT(0) AS index_exists FROM information_schema.statistics WHERE TABLE_SCHEMA = DATABASE() and table_name = ? AND index_name = ?", tableName, indexName)
	if err != nil {
		mlog.Critical(fmt.Sprintf("Failed to check index %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_REMOVE_INDEX_MYSQL)
	}

	if count <= 0 {
		return false
	}

	_, err = ss.GetMaster().Exec("DROP INDEX " + indexName + " ON " + tableName)
	if err != nil {
		mlog.Critical(fmt.Sprintf("Failed to remove index %v", err))
		time.Sleep(time.Second)
		os.Exit(EXIT_REMOVE_INDEX_MYSQL)
	}

	return true
}

func IsUniqueConstraintError(err error, indexName []string) bool {
	unique := false
	if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1062 {
		unique = true
	}

	field := false
	for _, contain := range indexName {
		if strings.Contains(err.Error(), contain) {
			field = true
			break
		}
	}

	return unique && field
}

func (ss *MySQLStore) GetAllConns() []*gorp.DbMap {
	all := make([]*gorp.DbMap, len(ss.replicas)+1)
	copy(all, ss.replicas)
	all[len(ss.replicas)] = ss.master
	return all
}

func (ss *MySQLStore) Close() {
	mlog.Info("Closing SqlStore")
	ss.master.Db.Close()
	for _, replica := range ss.replicas {
		replica.Db.Close()
	}
}

func (ss *MySQLStore) LockToMaster() {
	ss.lockedToMaster = true
}

func (ss *MySQLStore) UnlockFromMaster() {
	ss.lockedToMaster = false
}

func (ss *MySQLStore) User() store.UserProvider {
	return ss.user
}

func (ss *MySQLStore) Token() store.TokenProvider {
	return ss.token
}

func (ss *MySQLStore) FileInfo() store.FileInfoProvider {
	return ss.fileInfo
}

func (ss *MySQLStore) Session() store.SessionProvider {
	return ss.session
}

func (ss *MySQLStore) DropAllTables() {
	ss.master.TruncateTables()
}

type mattermConverter struct{}

func (me mattermConverter) ToDb(val interface{}) (interface{}, error) {

	switch t := val.(type) {
	case model.StringMap:
		return model.MapToJson(t), nil
	case map[string]string:
		return model.MapToJson(model.StringMap(t)), nil
	case model.StringArray:
		return model.ArrayToJson(t), nil
	case model.StringInterface:
		return model.StringInterfaceToJson(t), nil
	case map[string]interface{}:
		return model.StringInterfaceToJson(model.StringInterface(t)), nil
	}

	return val, nil
}

func (me mattermConverter) FromDb(target interface{}) (gorp.CustomScanner, bool) {
	switch target.(type) {
	case *model.StringMap:
		binder := func(holder, target interface{}) error {
			s, ok := holder.(*string)
			if !ok {
				return errors.New("store.sql.convert_string_map")
			}
			b := []byte(*s)
			return json.Unmarshal(b, target)
		}
		return gorp.CustomScanner{Holder: new(string), Target: target, Binder: binder}, true
	case *map[string]string:
		binder := func(holder, target interface{}) error {
			s, ok := holder.(*string)
			if !ok {
				return errors.New("store.sql.convert_string_map")
			}
			b := []byte(*s)
			return json.Unmarshal(b, target)
		}
		return gorp.CustomScanner{Holder: new(string), Target: target, Binder: binder}, true
	case *model.StringArray:
		binder := func(holder, target interface{}) error {
			s, ok := holder.(*string)
			if !ok {
				return errors.New("store.sql.convert_string_array")
			}
			b := []byte(*s)
			return json.Unmarshal(b, target)
		}
		return gorp.CustomScanner{Holder: new(string), Target: target, Binder: binder}, true
	case *model.StringInterface:
		binder := func(holder, target interface{}) error {
			s, ok := holder.(*string)
			if !ok {
				return errors.New("store.sql.convert_string_interface")
			}
			b := []byte(*s)
			return json.Unmarshal(b, target)
		}
		return gorp.CustomScanner{Holder: new(string), Target: target, Binder: binder}, true
	case *map[string]interface{}:
		binder := func(holder, target interface{}) error {
			s, ok := holder.(*string)
			if !ok {
				return errors.New("store.sql.convert_string_interface")
			}
			b := []byte(*s)
			return json.Unmarshal(b, target)
		}
		return gorp.CustomScanner{Holder: new(string), Target: target, Binder: binder}, true
	}

	return gorp.CustomScanner{}, false
}

func init() {
	mlog.Debug("++register mysql creator")
	store.RegisterProviderCreator(NewMySQLStore)
}
