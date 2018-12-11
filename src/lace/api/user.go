package api

import (
	"fmt"
	"io"
	"io/ioutil"
	"lace/model"
	"net/http"
)

func (api *LaceApi) InitUser() {
	api.Users.POST("", api.ApiHandler(createUser))
	api.Users.GET("", api.ApiSessionRequired(getUsers))
	api.Users.POST("/login", api.ApiHandler(login))
	api.Users.POST("/logout", api.ApiHandler(logout))
	api.User.PUT("/password", api.ApiSessionRequired(updatePassword))
	api.User.GET("/image", api.ApiSessionRequired(getProfileImage))
	api.User.POST("/image", api.ApiSessionRequired(setProfileImage))
	api.User.GET("", api.ApiSessionRequired(getUser))
	api.User.PUT("", api.ApiSessionRequired(updateUser))
	api.User.DELETE("", api.ApiSessionRequired(deleteUser))
}

func createUser(c *Context, w http.ResponseWriter, r *http.Request) {
	user := model.UserFromJson(r.Body)
	if user == nil {
		c.SetInvalidParam("user")
		return
	}

	tokenId := r.URL.Query().Get("t")
	inviteId := r.URL.Query().Get("iid")

	// No permission check required

	var ruser *model.User
	var err *model.AppError
	if len(tokenId) > 0 {
		ruser, err = c.App.CreateUserWithToken(user, tokenId)
	} else if len(inviteId) > 0 {
		ruser, err = c.App.CreateUserWithInviteId(user, inviteId)
	} else if c.IsSystemAdmin() {
		ruser, err = c.App.CreateUserAsAdmin(user)
	} else {
		ruser, err = c.App.CreateUserFromSignup(user)
	}

	if err != nil {
		c.Err = err
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(ruser.ToJson()))
}

func getUser(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireUserId()
	if c.Err != nil {
		return
	}

	// No permission check required

	var user *model.User
	var err *model.AppError

	if user, err = c.App.GetUser(c.Params.UserId); err != nil {
		c.Err = err
		return
	}

	if c.Session.UserId == user.Id {
		user.Sanitize(map[string]bool{})
	} else {
		c.App.SanitizeProfile(user, c.IsSystemAdmin())
	}
	c.App.UpdateLastActivityAtIfNeeded(c.Session)
	w.Write([]byte(user.ToJson()))
}

func getUserByUsername(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireUsername()
	if c.Err != nil {
		return
	}

	// No permission check required

	var user *model.User
	var err *model.AppError

	if user, err = c.App.GetUserByUsername(c.Params.Username); err != nil {
		c.Err = err
		return
	}

	if c.Session.UserId == user.Id {
		user.Sanitize(map[string]bool{})
	} else {
		c.App.SanitizeProfile(user, c.IsSystemAdmin())
	}
	w.Write([]byte(user.ToJson()))
}

func getUserByEmail(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireEmail()
	if c.Err != nil {
		return
	}

	// No permission check required

	var user *model.User
	var err *model.AppError

	if user, err = c.App.GetUserByEmail(c.Params.Email); err != nil {
		c.Err = err
		return
	}

	c.App.SanitizeProfile(user, c.IsSystemAdmin())
	w.Write([]byte(user.ToJson()))
}

func getProfileImage(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireUserId()
	if c.Err != nil {
		return
	}

	users, err := c.App.GetUsersByIds([]string{c.Params.UserId}, c.IsSystemAdmin())
	if err != nil {
		c.Err = err
		return
	}

	if len(users) == 0 {
		c.Err = model.NewAppError("getProfileImage", "api.user.get_profile_image.not_found.app_error", nil, "", http.StatusNotFound)
		return
	}

	user := users[0]

	var img []byte
	img, readFailed, err := c.App.GetProfileImage(user)
	if err != nil {
		c.Err = err
		return
	}

	if readFailed {
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%v, public", 5*60)) // 5 mins
	} else {
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%v, public", 24*60*60)) // 24 hrs
	}

	w.Header().Set("Content-Type", "image/png")
	w.Write(img)
}

func setProfileImage(c *Context, w http.ResponseWriter, r *http.Request) {
	defer io.Copy(ioutil.Discard, r.Body)

	c.RequireUserId()
	if c.Err != nil {
		return
	}

	if len(*c.App.Config().FileSettings.DriverName) == 0 {
		c.Err = model.NewAppError("uploadProfileImage", "api.user.upload_profile_user.storage.app_error", nil, "", http.StatusNotImplemented)
		return
	}

	if r.ContentLength > *c.App.Config().FileSettings.MaxFileSize {
		c.Err = model.NewAppError("uploadProfileImage", "api.user.upload_profile_user.too_large.app_error", nil, "", http.StatusRequestEntityTooLarge)
		return
	}

	if err := r.ParseMultipartForm(*c.App.Config().FileSettings.MaxFileSize); err != nil {
		c.Err = model.NewAppError("uploadProfileImage", "api.user.upload_profile_user.parse.app_error", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	m := r.MultipartForm

	imageArray, ok := m.File["image"]
	if !ok {
		c.Err = model.NewAppError("uploadProfileImage", "api.user.upload_profile_user.no_file.app_error", nil, "", http.StatusBadRequest)
		return
	}

	if len(imageArray) <= 0 {
		c.Err = model.NewAppError("uploadProfileImage", "api.user.upload_profile_user.array.app_error", nil, "", http.StatusBadRequest)
		return
	}

	imageData := imageArray[0]

	if err := c.App.SetProfileImage(c.Params.UserId, imageData); err != nil {
		c.Err = err
		return
	}

	ReturnStatusOK(w)
}

func getTotalUsersStats(c *Context, w http.ResponseWriter, r *http.Request) {
	if c.Err != nil {
		return
	}

	_, err := c.App.GetTotalUsersStats()
	if err != nil {
		c.Err = err
		return
	}
}

func getUsers(c *Context, w http.ResponseWriter, r *http.Request) {
	var profiles []*model.User
	var err *model.AppError
	profiles, err = c.App.GetUsersPage(c.Params.Page, c.Params.PerPage, c.IsSystemAdmin())
	if err != nil {
		c.Err = err
		return
	}
	c.App.UpdateLastActivityAtIfNeeded(c.Session)
	w.Write([]byte(model.UserListToJson(profiles)))
}

func getUsersByIds(c *Context, w http.ResponseWriter, r *http.Request) {
	userIds := model.ArrayFromJson(r.Body)

	if len(userIds) == 0 {
		c.SetInvalidParam("user_ids")
		return
	}

	// No permission check required

	users, err := c.App.GetUsersByIds(userIds, c.IsSystemAdmin())
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(model.UserListToJson(users)))
}

func getUsersByNames(c *Context, w http.ResponseWriter, r *http.Request) {
	usernames := model.ArrayFromJson(r.Body)

	if len(usernames) == 0 {
		c.SetInvalidParam("usernames")
		return
	}

	// No permission check required

	users, err := c.App.GetUsersByUsernames(usernames, c.IsSystemAdmin())
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(model.UserListToJson(users)))
}

func updateUser(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireUserId()
	if c.Err != nil {
		return
	}

	user := model.UserFromJson(r.Body)
	if user == nil {
		c.SetInvalidParam("user")
		return
	}

	ruser, err := c.App.UpdateUserAsUser(user, c.IsSystemAdmin())
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(ruser.ToJson()))
}

func deleteUser(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireUserId()
	if c.Err != nil {
		return
	}

	/*
		userId := c.Params.UserId
			var user *model.User
			var err *model.AppError

			if user, err = c.App.GetUser(userId); err != nil {
				c.Err = err
				return
			}
	*/

	ReturnStatusOK(w)
}

func updatePassword(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireUserId()
	if c.Err != nil {
		return
	}

	props := model.MapFromJson(r.Body)

	newPassword := props["new_password"]

	var err *model.AppError
	if c.Params.UserId == c.Session.UserId {
		currentPassword := props["current_password"]
		if len(currentPassword) <= 0 {
			c.SetInvalidParam("current_password")
			return
		}

		err = c.App.UpdatePasswordAsUser(c.Params.UserId, currentPassword, newPassword)
	} else {
		err = model.NewAppError("updatePassword", "api.user.update_password.context.app_error", nil, "", http.StatusForbidden)
	}

	if err != nil {
		c.Err = err
		return
	}
	ReturnStatusOK(w)
}

func resetPassword(c *Context, w http.ResponseWriter, r *http.Request) {
	props := model.MapFromJson(r.Body)

	token := props["token"]
	if len(token) != model.TOKEN_SIZE {
		c.SetInvalidParam("token")
		return
	}

	newPassword := props["new_password"]

	if err := c.App.ResetPasswordFromToken(token, newPassword); err != nil {
		c.Err = err
		return
	}

	ReturnStatusOK(w)
}

func sendPasswordReset(c *Context, w http.ResponseWriter, r *http.Request) {
	props := model.MapFromJson(r.Body)

	email := props["email"]
	if len(email) == 0 {
		c.SetInvalidParam("email")
		return
	}

	_, err := c.App.SendPasswordReset(email, c.App.GetSiteURL())
	if err != nil {
		c.Err = err
		return
	}

	ReturnStatusOK(w)
}

func login(c *Context, w http.ResponseWriter, r *http.Request) {

	props := model.MapFromJson(r.Body)

	id := props["id"]
	loginId := props["login_id"]
	password := props["password"]
	deviceId := props["device_id"]

	user, err := c.App.AuthenticateUserForLogin(id, loginId, password)

	if err != nil {
		c.Err = err
		return
	}

	var session *model.Session
	session, err = c.App.DoLogin(w, r, user, deviceId)
	if err != nil {
		c.Err = err
		return
	}

	c.Session = *session
	user.Sanitize(map[string]bool{})
	w.Write([]byte(user.ToJson()))
}

func logout(c *Context, w http.ResponseWriter, r *http.Request) {
	Logout(c, w, r)
}

func Logout(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RemoveSessionCookie(w, r)
	if c.Session.Id != "" {
		if err := c.App.RevokeSessionById(c.Session.Id); err != nil {
			c.Err = err
			return
		}
	}

	ReturnStatusOK(w)
}
