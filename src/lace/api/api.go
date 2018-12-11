package api

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"lace/app"
	"lace/mlog"
	"lace/model"
	"lace/utils"
	"net/http"
	"strconv"
	"strings"
)

const (
	PAGE_DEFAULT          = 0
	PER_PAGE_DEFAULT      = 60
	PER_PAGE_MAXIMUM      = 200
	LOGS_PER_PAGE_DEFAULT = 10000
	LOGS_PER_PAGE_MAXIMUM = 10000
)

type LaceApi struct {
	Engin          *gin.Engine
	ApiRoot        *gin.RouterGroup
	Users          *gin.RouterGroup
	User           *gin.RouterGroup
	UserByUsername *gin.RouterGroup
	UserByEmail    *gin.RouterGroup
	App            *app.App
}

type Handler struct {
	App            *app.App
	HandleFunc     func(*Context, http.ResponseWriter, *http.Request)
	RequireSession bool
	TrustRequester bool
	RequireMfa     bool
	IsStatic       bool
}

type Context struct {
	App           *app.App
	GinContext    *gin.Context
	Log           *mlog.Logger
	Session       model.Session
	Params        *Params
	Err           *model.AppError
	RequestId     string
	IpAddress     string
	Path          string
	siteURLHeader string
}

type Params struct {
	UserId    string
	InviteId  string
	TokenId   string
	FileId    string
	Filename  string
	AppId     string
	Email     string
	Username  string
	Service   string
	RoleId    string
	RoleName  string
	Scope     string
	Page      int
	PerPage   int
	Permanent bool
}

func (api *LaceApi) ApiHandler(h func(*Context, http.ResponseWriter, *http.Request)) gin.HandlerFunc {
	return func(ginC *gin.Context) {
		//now := time.Now()
		r := ginC.Request
		w := ginC.Writer
		mlog.Debug(fmt.Sprintf("%v - %v", r.Method, r.URL.Path))

		c := &Context{}
		c.App = api.App
		c.RequestId = model.NewId()
		c.IpAddress = utils.GetIpAddress(r)
		c.Params = ParamsFromRequest(ginC)
		c.Path = r.URL.Path
		c.Log = c.App.Log
		c.GinContext = ginC
		token, tokenLocation := app.ParseAuthTokenFromRequest(r)

		siteURLHeader := app.GetProtocol(r) + "://" + r.Host
		c.SetSiteURLHeader(siteURLHeader)
		w.Header().Set(utils.HEADER_REQUEST_ID, c.RequestId)
		// All api response bodies will be JSON formatted by default
		c.GinContext.Header("Content-Type", "application/json")
		if r.Method == "GET" {
			c.GinContext.Header("Expires", "0")
		}

		if len(token) != 0 {
			session, err := c.App.GetSession(token)
			if err != nil {
				c.Log.Info("Invalid session", mlog.Err(err))
				if err.StatusCode == http.StatusInternalServerError {
					c.Err = err
				}
			} else if tokenLocation == app.TokenLocationQueryString {
				c.Err = model.NewAppError("ServeHTTP", "api.context.token_provided.app_error", nil, "token="+token, http.StatusUnauthorized)
			} else {
				c.Session = *session
			}
		}

		c.Log = c.App.Log.With(
			mlog.String("path", c.Path),
			mlog.String("request_id", c.RequestId),
			mlog.String("ip_addr", c.IpAddress),
			mlog.String("user_id", c.Session.UserId),
			mlog.String("method", r.Method),
		)

		if c.Err == nil {
			h(c, w, r)
		}

		// Handle errors that have occurred
		if c.Err != nil {
			c.Err.RequestId = c.RequestId

			if c.Err.Message == "api.context.session_expired.app_error" {
				c.LogInfo(c.Err)
			} else {
				c.LogError(c.Err)
			}

			c.Err.Where = r.URL.Path

			if c.Err.StatusCode >= 500 {
				c.Err.Message = "Internal Server Error"
				c.Err.DetailedError = ""
				c.Err.StatusCode = 500
				c.Err.Where = ""
			}

			w.WriteHeader(c.Err.StatusCode)
			w.Write([]byte(c.Err.ToJson()))
		}
	}
}

func (api *LaceApi) ApiSessionRequired(h func(*Context, http.ResponseWriter, *http.Request)) gin.HandlerFunc {
	return func(ginC *gin.Context) {
		//now := time.Now()
		r := ginC.Request
		w := ginC.Writer
		mlog.Debug(fmt.Sprintf("%v - %v", r.Method, r.URL.Path))

		c := &Context{}
		c.App = api.App
		c.RequestId = model.NewId()
		c.IpAddress = utils.GetIpAddress(r)
		c.Params = ParamsFromRequest(ginC)
		c.Path = r.URL.Path
		c.Log = c.App.Log
		c.GinContext = ginC

		token, tokenLocation := app.ParseAuthTokenFromRequest(r)

		// CSRF Check
		if tokenLocation == app.TokenLocationCookie {
			if r.Header.Get(utils.HEADER_REQUESTED_WITH) != utils.HEADER_REQUESTED_WITH_XML {
				c.Err = model.NewAppError("ServeHTTP", "api.context.session_expired.app_error", nil, "token="+token+" Appears to be a CSRF attempt", http.StatusUnauthorized)
				token = ""
			}
		}

		siteURLHeader := app.GetProtocol(r) + "://" + r.Host
		c.SetSiteURLHeader(siteURLHeader)
		c.GinContext.Header(utils.HEADER_REQUEST_ID, c.RequestId)

		// All api response bodies will be JSON formatted by default
		c.GinContext.Header("Content-Type", "application/json")

		if r.Method == "GET" {
			c.GinContext.Header("Expires", "0")
		}

		if len(token) != 0 {
			session, err := c.App.GetSession(token)

			if err != nil {
				c.Log.Info("Invalid session", mlog.Err(err))
				if err.StatusCode == http.StatusInternalServerError {
					c.Err = err
				} else {
					c.RemoveSessionCookie(w, r)
					c.Err = model.NewAppError("ServeHTTP", "api.context.session_expired.app_error", nil, "token="+token, http.StatusUnauthorized)
				}
			} else if tokenLocation == app.TokenLocationQueryString {
				c.Err = model.NewAppError("ServeHTTP", "api.context.token_provided.app_error", nil, "token="+token, http.StatusUnauthorized)
			} else {
				c.Session = *session
			}
		}

		c.Log = c.App.Log.With(
			mlog.String("path", c.Path),
			mlog.String("request_id", c.RequestId),
			mlog.String("ip_addr", c.IpAddress),
			mlog.String("user_id", c.Session.UserId),
			mlog.String("method", r.Method),
		)

		if c.Err == nil {
			c.SessionRequired()
		}

		if c.Err == nil {
			h(c, w, r)
		}

		// Handle errors that have occurred
		if c.Err != nil {
			c.Err.RequestId = c.RequestId

			if c.Err.Message == "api.context.session_expired.app_error" {
				c.LogInfo(c.Err)
			} else {
				c.LogError(c.Err)
			}

			c.Err.Where = r.URL.Path

			if c.Err.StatusCode >= 500 {
				c.Err.Message = "Internal Server Error"
				c.Err.DetailedError = ""
				c.Err.StatusCode = 500
				c.Err.Where = ""
			}

			w.WriteHeader(c.Err.StatusCode)
			w.Write([]byte(c.Err.ToJson()))
		}
	}
}

func Init(app *app.App) *LaceApi {
	api := &LaceApi{
		Engin: gin.Default(),
		App:   app,
	}
	api.ApiRoot = api.Engin.Group(utils.API_URL_SUFFIX)
	api.Users = api.ApiRoot.Group("/users")
	api.User = api.ApiRoot.Group("/users/user/")
	api.UserByUsername = api.Users.Group("/username/:username")
	api.UserByEmail = api.Users.Group("/email/:email")
	api.InitUser()
	return api
}

func ParamsFromRequest(rh *gin.Context) *Params {
	ps := rh.Params
	props := make(map[string]string)
	for _, entry := range ps {
		props[entry.Key] = entry.Value
		mlog.Debug(fmt.Sprintf("%s :%s ", entry.Key, entry.Value))
	}
	params := &Params{}
	r := rh.Request
	query := r.URL.Query()

	if val, ok := props["user_id"]; ok {
		params.UserId = val
	}

	if val, ok := props["invite_id"]; ok {
		params.InviteId = val
	}

	if val, ok := props["token_id"]; ok {
		params.TokenId = val
	}

	if val, ok := props["file_id"]; ok {
		params.FileId = val
	}

	params.Filename = query.Get("filename")

	if val, ok := props["app_id"]; ok {
		params.AppId = val
	}

	if val, ok := props["email"]; ok {
		params.Email = val
	}

	if val, ok := props["username"]; ok {
		params.Username = val
	}

	if val, ok := props["role_id"]; ok {
		params.RoleId = val
	}

	if val, ok := props["role_name"]; ok {
		params.RoleName = val
	}

	params.Scope = query.Get("scope")

	if val, err := strconv.Atoi(query.Get("page")); err != nil || val < 0 {
		params.Page = PAGE_DEFAULT
	} else {
		params.Page = val
	}

	if val, err := strconv.ParseBool(query.Get("permanent")); err == nil {
		params.Permanent = val
	}

	if val, err := strconv.Atoi(query.Get("per_page")); err != nil || val < 0 {
		params.PerPage = PER_PAGE_DEFAULT
	} else if val > PER_PAGE_MAXIMUM {
		params.PerPage = PER_PAGE_MAXIMUM
	} else {
		params.PerPage = val
	}

	return params
}

func (c *Context) LogError(err *model.AppError) {
	// Filter out 404s, endless reconnects and browser compatibility errors
	if err.StatusCode == http.StatusNotFound {
		c.LogDebug(err)
	} else {
		c.Log.Error("",
			mlog.String("err_where", err.Where),
			mlog.Int("http_code", err.StatusCode),
			mlog.String("err_details", err.DetailedError),
		)
	}
}

func (c *Context) LogInfo(err *model.AppError) {
	// Filter out 401s
	if err.StatusCode == http.StatusUnauthorized {
		c.LogDebug(err)
	} else {
		c.Log.Info("",
			mlog.String("err_where", err.Where),
			mlog.Int("http_code", err.StatusCode),
			mlog.String("err_details", err.DetailedError),
		)
	}
}

func (c *Context) LogDebug(err *model.AppError) {
	c.Log.Debug("",
		mlog.String("err_where", err.Where),
		mlog.Int("http_code", err.StatusCode),
		mlog.String("err_details", err.DetailedError),
	)
}

func (c *Context) IsSystemAdmin() bool {
	//return c.App.SessionHasPermissionTo(c.Session, model.PERMISSION_MANAGE_SYSTEM)
	return true
}

func (c *Context) SessionRequired() {
	if len(c.Session.UserId) == 0 {
		c.Err = model.NewAppError("", "api.context.session_expired.app_error", nil, "UserRequired", http.StatusUnauthorized)
		return
	}
}

func (c *Context) RemoveSessionCookie(w http.ResponseWriter, r *http.Request) {
	c.GinContext.SetCookie(model.SESSION_COOKIE_TOKEN, "", -1, "/", "", false, true)
}

func (c *Context) SetInvalidParam(parameter string) {
	c.Err = NewInvalidParamError(parameter)
}

func (c *Context) SetInvalidUrlParam(parameter string) {
	c.Err = NewInvalidUrlParamError(parameter)
}

func NewInvalidParamError(parameter string) *model.AppError {
	err := model.NewAppError("Context", "api.context.invalid_body_param.app_error", map[string]interface{}{"Name": parameter}, "", http.StatusBadRequest)
	return err
}
func NewInvalidUrlParamError(parameter string) *model.AppError {
	err := model.NewAppError("Context", "api.context.invalid_url_param.app_error", map[string]interface{}{"Name": parameter}, "", http.StatusBadRequest)
	return err
}

func (c *Context) SetSiteURLHeader(url string) {
	c.siteURLHeader = strings.TrimRight(url, "/")
}

func (c *Context) GetSiteURLHeader() string {
	return c.siteURLHeader
}

func (c *Context) RequireUserId() *Context {
	if c.Err != nil {
		return c
	}

	if len(c.Params.UserId) != 26 {
		c.SetInvalidUrlParam("user_id")
	}
	return c
}

func (c *Context) RequireInviteId() *Context {
	if c.Err != nil {
		return c
	}

	if len(c.Params.InviteId) == 0 {
		c.SetInvalidUrlParam("invite_id")
	}
	return c
}

func (c *Context) RequireTokenId() *Context {
	if c.Err != nil {
		return c
	}

	if len(c.Params.TokenId) != 26 {
		c.SetInvalidUrlParam("token_id")
	}
	return c
}

func (c *Context) RequireUsername() *Context {
	if c.Err != nil {
		return c
	}

	if !model.IsValidUsername(c.Params.Username) {
		c.SetInvalidParam("username")
	}

	return c
}

func (c *Context) RequireFileId() *Context {
	if c.Err != nil {
		return c
	}

	if len(c.Params.FileId) != 26 {
		c.SetInvalidUrlParam("file_id")
	}

	return c
}

func (c *Context) RequireFilename() *Context {
	if c.Err != nil {
		return c
	}

	if len(c.Params.Filename) == 0 {
		c.SetInvalidUrlParam("filename")
	}

	return c
}

func (c *Context) RequireEmail() *Context {
	if c.Err != nil {
		return c
	}

	if !model.IsValidEmail(c.Params.Email) {
		c.SetInvalidUrlParam("email")
	}

	return c
}

func (c *Context) RequireRoleId() *Context {
	if c.Err != nil {
		return c
	}

	if len(c.Params.RoleId) != 26 {
		c.SetInvalidUrlParam("role_id")
	}
	return c
}

func (c *Context) RequireRoleName() *Context {
	if c.Err != nil {
		return c
	}

	if !model.IsValidRoleName(c.Params.RoleName) {
		c.SetInvalidUrlParam("role_name")
	}

	return c
}

func ReturnStatusOK(w http.ResponseWriter) {
	m := make(map[string]string)
	m[utils.STATUS] = utils.STATUS_OK
	w.Write([]byte(model.MapToJson(m)))
}
