package model

const (
	DATABASE_DRIVER_MYSQL            = "mysql"
	SQL_SETTINGS_DEFAULT_DATA_SOURCE = "root:@tcp(localhost:3306)/datasource?charset=utf8mb4,utf8&readTimeout=30s&writeTimeout=30s"
	FILE_SETTINGS_DEFAULT_DIRECTORY  = "./data/"
	DEFAULT_LOCALE                   = "en"
	IMAGE_DRIVER_LOCAL               = "local"
)

func NewInt64(value int64) *int64 {
	return &value
}

func NewString(value string) *string {
	return &value
}

func NewInt(value int) *int {
	return &value
}

func NewBool(value bool) *bool {
	return &value
}

type ServiceSettings struct {
	SqlSettings   *SqlSettings
	LogSettings   *LogSettings
	LoginSettings *LoginSettings
	FileSettings  *FileSettings
}

func (ss *ServiceSettings) SetDefaults() {
	if ss.SqlSettings == nil {
		ss.SqlSettings = new(SqlSettings)
		ss.SqlSettings.SetDefaults()
	}
	if ss.LogSettings == nil {
		ss.LogSettings = new(LogSettings)
		ss.LogSettings.SetDefaults()
	}
}

type LoginSettings struct {
	EnableSignInWithEmail       *bool
	EnableSignUpWithEmail       *bool
	EnableUserCreation          *bool
	EnableOpenServer            *bool
	EnableSignInWithUsername    *bool
	MaximumLoginAttempts        int
	SessionCacheInMinutes       int64
	SessionIdleTimeoutInMinutes int64
	SessionLengthWebInDays      int
	SessionLengthMobileInDays   int
}

type SqlSettings struct {
	DriverName                  *string
	DataSource                  *string
	DataSourceReplicas          []string
	DataSourceSearchReplicas    []string
	MaxIdleConns                *int
	ConnMaxLifetimeMilliseconds *int
	MaxOpenConns                *int
	Trace                       bool
	AtRestEncryptKey            string
	QueryTimeout                *int
}

func (s *SqlSettings) SetDefaults() {
	if s.DriverName == nil {
		s.DriverName = NewString(DATABASE_DRIVER_MYSQL)
	}

	if s.DataSource == nil {
		s.DataSource = NewString(SQL_SETTINGS_DEFAULT_DATA_SOURCE)
	}

	if len(s.AtRestEncryptKey) == 0 {
		s.AtRestEncryptKey = NewRandomString(32)
	}

	if s.MaxIdleConns == nil {
		s.MaxIdleConns = NewInt(20)
	}

	if s.MaxOpenConns == nil {
		s.MaxOpenConns = NewInt(300)
	}

	if s.ConnMaxLifetimeMilliseconds == nil {
		s.ConnMaxLifetimeMilliseconds = NewInt(3600000)
	}

	if s.QueryTimeout == nil {
		s.QueryTimeout = NewInt(30)
	}
}

type LogSettings struct {
	EnableConsole bool
	ConsoleLevel  string
	ConsoleJson   *bool
	EnableFile    bool
	FileLevel     string
	FileJson      *bool
	FileLocation  string
}

func (s *LogSettings) SetDefaults() {
	s.EnableConsole = true
	s.ConsoleLevel = "debug"
	s.FileLevel = "debug"

	if s.ConsoleJson == nil {
		s.ConsoleJson = NewBool(true)
	}

	if s.FileJson == nil {
		s.FileJson = NewBool(true)
	}

	if len(s.FileLocation) == 0 {
		s.FileLocation = "./"
	}
}

type FileSettings struct {
	EnableFileAttachments *bool
	EnableMobileUpload    *bool
	EnableMobileDownload  *bool
	MaxFileSize           *int64
	DriverName            *string
	EnablePublicLink      bool
	PublicLinkSalt        *string
	InitialFont           string
}

func (s *FileSettings) SetDefaults() {
	if s.DriverName == nil {
		s.DriverName = NewString(IMAGE_DRIVER_LOCAL)
	}

	if s.EnableFileAttachments == nil {
		s.EnableFileAttachments = NewBool(true)
	}

	if s.EnableMobileUpload == nil {
		s.EnableMobileUpload = NewBool(true)
	}

	if s.EnableMobileDownload == nil {
		s.EnableMobileDownload = NewBool(true)
	}

	if s.MaxFileSize == nil {
		s.MaxFileSize = NewInt64(52428800) // 50 MB
	}

	if s.PublicLinkSalt == nil || len(*s.PublicLinkSalt) == 0 {
		s.PublicLinkSalt = NewString(NewRandomString(32))
	}

	if s.InitialFont == "" {
		// Defaults to "nunito-bold.ttf"
		s.InitialFont = "nunito-bold.ttf"
	}
}
