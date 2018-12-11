package store

import (
	"fmt"
	gorp "gopkg.in/gorp.v2"
	"lace/mlog"
	"lace/model"
	//	"reflect"
	"time"
)

type StoreResult struct {
	Data interface{}
	Err  *model.AppError
}

type StoreChannel chan StoreResult

func Do(f func(result *StoreResult)) StoreChannel {
	storeChannel := make(StoreChannel, 1)
	go func() {
		result := StoreResult{}
		f(&result)
		storeChannel <- result
		close(storeChannel)
	}()
	return storeChannel
}

func Must(sc StoreChannel) interface{} {
	r := <-sc
	if r.Err != nil {
		time.Sleep(time.Second)
		panic(r.Err)
	}

	return r.Data
}

type SessionProvider interface {
	Save(session *model.Session) StoreChannel
	Get(sessionIdOrToken string) StoreChannel
	GetSessions(userId string) StoreChannel
	GetSessionsWithActiveDeviceIds(userId string) StoreChannel
	Remove(sessionIdOrToken string) StoreChannel
	RemoveAllSessions() StoreChannel
	PermanentDeleteSessionsByUser(teamId string) StoreChannel
	UpdateLastActivityAt(sessionId string, time int64) StoreChannel
	UpdateRoles(userId string, roles string) StoreChannel
	UpdateDeviceId(id string, deviceId string, expiresAt int64) StoreChannel
	AnalyticsSessionCount() StoreChannel
	Cleanup(expiryTime int64, batchSize int64)
}

type UserProvider interface {
	Save(user *model.User) StoreChannel
	Update(user *model.User, allowRoleUpdate bool) StoreChannel
	UpdateLastPictureUpdate(userId string) StoreChannel
	ResetLastPictureUpdate(userId string) StoreChannel
	UpdateUpdateAt(userId string) StoreChannel
	UpdatePassword(userId, newPassword string) StoreChannel
	Get(id string) StoreChannel
	GetAll() StoreChannel
	GetAllProfiles(offset int, limit int) StoreChannel
	GetProfileByIds(userId []string) StoreChannel
	GetByEmail(email string) StoreChannel
	GetByUsername(username string) StoreChannel
	GetForLogin(loginId string, allowSignInWithUsername, allowSignInWithEmail bool) StoreChannel
	VerifyEmail(userId string) StoreChannel
	UpdateFailedPasswordAttempts(userId string, attempts int) StoreChannel
	GetTotalUsersCount() StoreChannel
	PermanentDelete(userId string) StoreChannel
}

type TokenProvider interface {
	Save(recovery *model.Token) StoreChannel
	Delete(token string) StoreChannel
	GetByToken(token string) StoreChannel
	Cleanup()
}

type FileInfoProvider interface {
	Save(info *model.FileInfo) StoreChannel
	Get(id string) StoreChannel
	GetByPath(path string) StoreChannel
	GetForUser(userId string) StoreChannel
	PermanentDelete(fileId string) StoreChannel
	PermanentDeleteBatch(endTime int64, limit int64) StoreChannel
	PermanentDeleteByUser(userId string) StoreChannel
	ClearCaches()
}

type RoleProvider interface {
	Save(role *model.Role) StoreChannel
	Get(roleId string) StoreChannel
	GetByName(name string) StoreChannel
	GetByNames(names []string) StoreChannel
	Delete(roldId string) StoreChannel
	PermanentDeleteAll() StoreChannel
}

type Provider interface {
	User() UserProvider
	Token() TokenProvider
	FileInfo() FileInfoProvider
	Role() RoleProvider
	Session() SessionProvider
	Close()
	LockToMaster()
	UnlockFromMaster()
	DropAllTables()
	TotalMasterDbConnections() int
	TotalReadDbConnections() int
	TotalSearchDbConnections() int
}

type SystemProvider interface {
	Save(system *model.System) StoreChannel
	SaveOrUpdate(system *model.System) StoreChannel
	Update(system *model.System) StoreChannel
	Get() StoreChannel
	GetByName(name string) StoreChannel
	PermanentDeleteByName(name string) StoreChannel
}

type MySQLProvider interface {
	DriverName() string
	GetCurrentSchemaVersion() string
	GetMaster() *gorp.DbMap
	GetSearchReplica() *gorp.DbMap
	GetReplica() *gorp.DbMap
	TotalMasterDbConnections() int
	TotalReadDbConnections() int
	TotalSearchDbConnections() int
	DoesTableExist(tablename string) bool
	DoesColumnExist(tableName string, columName string) bool
	DoesTriggerExist(triggerName string) bool
	CreateColumnIfNotExists(tableName string, columnName string, mySqlColType string, postgresColType string, defaultValue string) bool
	CreateColumnIfNotExistsNoDefault(tableName string, columnName string, mySqlColType string, postgresColType string) bool
	RemoveColumnIfExists(tableName string, columnName string) bool
	RemoveTableIfExists(tableName string) bool
	RenameColumnIfExists(tableName string, oldColumnName string, newColumnName string, colType string) bool
	GetMaxLengthOfColumnIfExists(tableName string, columnName string) string
	AlterColumnTypeIfExists(tableName string, columnName string, mySqlColType string, postgresColType string) bool
	CreateUniqueIndexIfNotExists(indexName string, tableName string, columnName string) bool
	CreateIndexIfNotExists(indexName string, tableName string, columnName string) bool
	CreateCompositeIndexIfNotExists(indexName string, tableName string, columnNames []string) bool
	CreateFullTextIndexIfNotExists(indexName string, tableName string, columnName string) bool
	RemoveIndexIfExists(indexName string, tableName string) bool
	GetAllConns() []*gorp.DbMap
	Close()
	LockToMaster()
	UnlockFromMaster()
	User() UserProvider
	Token() TokenProvider
	FileInfo() FileInfoProvider
	Session() SessionProvider
}

type MySQLCreatorFunc func(settings *model.SqlSettings) MySQLProvider

var mysqlCreator MySQLCreatorFunc

const (
	MYSQL_PROVIDER = "mysql"
)

func RegisterProviderCreator(creator MySQLCreatorFunc) {
	mysqlCreator = creator
}

type ServiceProvider struct {
	MySQLProvider MySQLProvider
}

func (sp *ServiceProvider) NewMySQLProvider(setting *model.SqlSettings) MySQLProvider {
	mlog.Debug(fmt.Sprintf("GetMySQLProvider settings %v ", *setting))
	if sp.MySQLProvider == nil {
		mlog.Debug(fmt.Sprintf("GetMySQLProvider settings %v to create mysql provider", *setting))
		sp.MySQLProvider = mysqlCreator(setting)
	}
	return sp.MySQLProvider
}

func (sp *ServiceProvider) GetMySQLProvider() MySQLProvider {
	if sp.MySQLProvider == nil {
		mlog.Warn("GetMySQLProvider mysql provider is nil")
	}
	return sp.MySQLProvider
}
