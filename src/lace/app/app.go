package app

import (
	"lace/mlog"
	"lace/model"
	"lace/store"
	"lace/utils"
	"strings"
)

type App struct {
	ServiceProvider store.ServiceProvider
	ServiceSettings model.ServiceSettings
	Roles           map[string]*model.Role
	sessionCache    *utils.Cache
	Log             *mlog.Logger
}

func NewApp() *App {
	app := &App{
		Roles:        model.MakeDefaultRoles(),
		sessionCache: utils.NewLru(model.SESSION_CACHE_SIZE),
	}
	return app
}

func MloggerConfigFromLoggerConfig(s *model.LogSettings) *mlog.LoggerConfiguration {
	return &mlog.LoggerConfiguration{
		EnableConsole: s.EnableConsole,
		ConsoleJson:   *s.ConsoleJson,
		ConsoleLevel:  strings.ToLower(s.ConsoleLevel),
		EnableFile:    s.EnableFile,
		FileJson:      *s.FileJson,
		FileLevel:     strings.ToLower(s.FileLevel),
		FileLocation:  s.FileLocation,
	}
}

func (app *App) Initialize() {
	app.ServiceSettings.SetDefaults()
	app.ServiceProvider.NewMySQLProvider(app.ServiceSettings.SqlSettings)
	app.Log = mlog.NewLogger(MloggerConfigFromLoggerConfig(app.Config().LogSettings))
}

func (app *App) Config() *model.ServiceSettings {
	return &app.ServiceSettings
}

func (app *App) UserProvider() store.UserProvider {
	return app.ServiceProvider.GetMySQLProvider().User()
}

func (app *App) SessionProvider() store.SessionProvider {
	return app.ServiceProvider.GetMySQLProvider().Session()
}

func (app *App) FileInfoProvider() store.FileInfoProvider {
	return app.ServiceProvider.GetMySQLProvider().FileInfo()
}

func (app *App) TokenProvider() store.TokenProvider {
	return app.ServiceProvider.GetMySQLProvider().Token()
}

func (a *App) GetCookieDomain() string {
	return ""
}

func (a *App) GetSiteURL() string {
	return ""
}
