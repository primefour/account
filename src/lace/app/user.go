package app

import (
	"bytes"
	//b64 "encoding/base64"
	"fmt"
	//"hash/fnv"
	//"image"
	//"image/color"
	//"image/draw"
	//_ "image/gif"
	//_ "image/jpeg"
	//"image/png"
	//"io"
	//"io/ioutil"
	"mime/multipart"
	"net/http"
	//"path/filepath"
	//"strconv"
	"strings"

	//"github.com/disintegration/imaging"
	//"github.com/golang/freetype"
	//"github.com/golang/freetype/truetype"
	"lace/mlog"
	"lace/model"
	//"lace/store"
	"lace/utils"
)

const (
	TOKEN_TYPE_PASSWORD_RECOVERY  = "password_recovery"
	TOKEN_TYPE_VERIFY_EMAIL       = "verify_email"
	TOKEN_TYPE_TEAM_INVITATION    = "team_invitation"
	PASSWORD_RECOVER_EXPIRY_TIME  = 1000 * 60 * 60      // 1 hour
	TEAM_INVITATION_EXPIRY_TIME   = 1000 * 60 * 60 * 48 // 48 hours
	IMAGE_PROFILE_PIXEL_DIMENSION = 128
)

func (a *App) CreateUserWithToken(user *model.User, tokenId string) (*model.User, *model.AppError) {
	if err := a.IsUserSignUpAllowed(); err != nil {
		return nil, err
	}

	result := <-a.TokenProvider().GetByToken(tokenId)
	if result.Err != nil {
		return nil, model.NewAppError("CreateUserWithToken", "api.user.create_user.signup_link_invalid.app_error", nil, result.Err.Error(), http.StatusBadRequest)
	}

	token := result.Data.(*model.Token)
	if token.Type != TOKEN_TYPE_TEAM_INVITATION {
		return nil, model.NewAppError("CreateUserWithToken", "api.user.create_user.signup_link_invalid.app_error", nil, "", http.StatusBadRequest)
	}

	if model.GetMillis()-token.CreateAt >= TEAM_INVITATION_EXPIRY_TIME {
		a.DeleteToken(token)
		return nil, model.NewAppError("CreateUserWithToken", "api.user.create_user.signup_link_expired.app_error", nil, "", http.StatusBadRequest)
	}

	tokenData := model.MapFromJson(strings.NewReader(token.Extra))

	user.Email = tokenData["email"]
	user.EmailVerified = true

	var ruser *model.User
	var err *model.AppError
	if ruser, err = a.CreateUser(user); err != nil {
		return nil, err
	}

	if err := a.DeleteToken(token); err != nil {
		return nil, err
	}

	return ruser, nil
}

func (a *App) CreateUserWithInviteId(user *model.User, inviteId string) (*model.User, *model.AppError) {
	if err := a.IsUserSignUpAllowed(); err != nil {
		return nil, err
	}
	user.EmailVerified = false
	var ruser *model.User
	var err *model.AppError
	if ruser, err = a.CreateUser(user); err != nil {
		return nil, err
	}

	return ruser, nil
}

func (a *App) CreateUserAsAdmin(user *model.User) (*model.User, *model.AppError) {
	ruser, err := a.CreateUser(user)
	if err != nil {
		return nil, err
	}

	return ruser, nil
}

func (a *App) CreateUserFromSignup(user *model.User) (*model.User, *model.AppError) {
	if err := a.IsUserSignUpAllowed(); err != nil {
		return nil, err
	}

	if !a.IsFirstUserAccount() && !*a.Config().LoginSettings.EnableOpenServer {
		err := model.NewAppError("CreateUserFromSignup", "api.user.create_user.no_open_server", nil, "email="+user.Email, http.StatusForbidden)
		return nil, err
	}

	user.EmailVerified = false

	ruser, err := a.CreateUser(user)
	if err != nil {
		return nil, err
	}

	return ruser, nil
}

func (a *App) IsUserSignUpAllowed() *model.AppError {
	if !*a.Config().LoginSettings.EnableSignUpWithEmail ||
		!*a.Config().LoginSettings.EnableUserCreation {
		err := model.NewAppError("IsUserSignUpAllowed", "api.user.create_user.signup_email_disabled.app_error", nil, "", http.StatusNotImplemented)
		return err
	}
	return nil
}

func (a *App) IsFirstUserAccount() bool {
	if a.SessionCacheLength() == 0 {
		if cr := <-a.UserProvider().GetTotalUsersCount(); cr.Err != nil {
			mlog.Error(fmt.Sprint(cr.Err))
			return false
		} else {
			count := cr.Data.(int64)
			if count <= 0 {
				return true
			}
		}
	}

	return false
}

func (a *App) CreateUser(user *model.User) (*model.User, *model.AppError) {
	user.Roles = model.SYSTEM_USER_ROLE_ID

	// Below is a special case where the first user in the entire
	// system is granted the system_admin role
	if result := <-a.UserProvider().GetTotalUsersCount(); result.Err != nil {
		return nil, result.Err
	} else {
		count := result.Data.(int64)
		if count <= 0 {
			user.Roles = model.SYSTEM_ADMIN_ROLE_ID + " " + model.SYSTEM_USER_ROLE_ID
		}
	}

	user.Locale = model.DEFAULT_LOCALE

	if ruser, err := a.createUser(user); err != nil {
		return nil, err
	} else {
		return ruser, nil
	}
}

func (a *App) IsPasswordValid(password string) *model.AppError {
	return utils.IsPasswordValid(password)
}

func (a *App) createUser(user *model.User) (*model.User, *model.AppError) {
	user.MakeNonNil()

	if err := a.IsPasswordValid(user.Password); err != nil {
		return nil, err
	}

	if result := <-a.UserProvider().Save(user); result.Err != nil {
		mlog.Error(fmt.Sprintf("Couldn't save the user err=%v", result.Err))
		return nil, result.Err
	} else {
		ruser := result.Data.(*model.User)

		if user.EmailVerified {
			if err := a.VerifyUserEmail(ruser.Id); err != nil {
				mlog.Error(fmt.Sprintf("Failed to set email verified err=%v", err))
			}
		}
		ruser.Sanitize(map[string]bool{})
		return ruser, nil
	}
}

// Check if the username is already used by another user.
//Return false if the username is invalid.
func (a *App) IsUsernameTaken(name string) bool {

	if !model.IsValidUsername(name) {
		return false
	}

	if result := <-a.UserProvider().GetByUsername(name); result.Err != nil {
		return false
	}

	return true
}

func (a *App) GetUser(userId string) (*model.User, *model.AppError) {
	if result := <-a.UserProvider().Get(userId); result.Err != nil {
		return nil, result.Err
	} else {
		return result.Data.(*model.User), nil
	}
}

func (a *App) GetUserByUsername(username string) (*model.User, *model.AppError) {
	if result := <-a.UserProvider().GetByUsername(username); result.Err != nil {
		result.Err.StatusCode = http.StatusNotFound
		return nil, result.Err
	} else {
		return result.Data.(*model.User), nil
	}
}

func (a *App) GetUserByEmail(email string) (*model.User, *model.AppError) {

	if result := <-a.UserProvider().GetByEmail(email); result.Err != nil {
		result.Err.StatusCode = http.StatusNotFound
		return nil, result.Err
	} else if result.Err != nil {
		result.Err.StatusCode = http.StatusBadRequest
		return nil, result.Err
	} else {
		return result.Data.(*model.User), nil
	}
}

func (a *App) GetUsers(offset int, limit int) ([]*model.User, *model.AppError) {
	if result := <-a.UserProvider().GetAllProfiles(offset, limit); result.Err != nil {
		return nil, result.Err
	} else {
		return result.Data.([]*model.User), nil
	}
}

func (a *App) GetUsersMap(offset int, limit int, asAdmin bool) (map[string]*model.User, *model.AppError) {
	users, err := a.GetUsers(offset, limit)
	if err != nil {
		return nil, err
	}

	userMap := make(map[string]*model.User, len(users))

	for _, user := range users {
		a.SanitizeProfile(user, asAdmin)
		userMap[user.Id] = user
	}

	return userMap, nil
}

func (a *App) GetUsersPage(page int, perPage int, asAdmin bool) ([]*model.User, *model.AppError) {
	users, err := a.GetUsers(page*perPage, perPage)
	if err != nil {
		return nil, err
	}

	return a.sanitizeProfiles(users, asAdmin), nil
}

func (a *App) GetUsersEtag() string {
	return "GetUsersEtag"
}

func (a *App) GetUsersByIds(userIds []string, asAdmin bool) ([]*model.User, *model.AppError) {
	if result := <-a.UserProvider().GetProfileByIds(userIds); result.Err != nil {
		return nil, result.Err
	} else {
		users := result.Data.([]*model.User)
		return a.sanitizeProfiles(users, asAdmin), nil
	}
}

func (a *App) GetUsersByUsernames(usernames []string, asAdmin bool) ([]*model.User, *model.AppError) {
	/*
		if result := <-a.UserProvider().GetProfilesByUsernames(usernames, ""); result.Err != nil {
			return nil, result.Err
		} else {
			users := result.Data.([]*model.User)
			return a.sanitizeProfiles(users, asAdmin), nil
		}
	*/
	return nil, nil
}

func (a *App) sanitizeProfiles(users []*model.User, asAdmin bool) []*model.User {
	for _, u := range users {
		a.SanitizeProfile(u, asAdmin)
	}

	return users
}

func CreateProfileImage(username string, userId string, initialFont string) ([]byte, *model.AppError) {
	/*
		colors := []color.NRGBA{
			{197, 8, 126, 255},
			{227, 207, 18, 255},
			{28, 181, 105, 255},
			{35, 188, 224, 255},
			{116, 49, 196, 255},
			{197, 8, 126, 255},
			{197, 19, 19, 255},
			{250, 134, 6, 255},
			{227, 207, 18, 255},
			{123, 201, 71, 255},
			{28, 181, 105, 255},
			{35, 188, 224, 255},
			{116, 49, 196, 255},
			{197, 8, 126, 255},
			{197, 19, 19, 255},
			{250, 134, 6, 255},
			{227, 207, 18, 255},
			{123, 201, 71, 255},
			{28, 181, 105, 255},
			{35, 188, 224, 255},
			{116, 49, 196, 255},
			{197, 8, 126, 255},
			{197, 19, 19, 255},
			{250, 134, 6, 255},
			{227, 207, 18, 255},
			{123, 201, 71, 255},
		}

		h := fnv.New32a()
		h.Write([]byte(userId))
		seed := h.Sum32()

		initial := string(strings.ToUpper(username)[0])

		font, err := getFont(initialFont)
		if err != nil {
			return nil, model.NewAppError("CreateProfileImage", "api.user.create_profile_image.default_font.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		color := colors[int64(seed)%int64(len(colors))]
		dstImg := image.NewRGBA(image.Rect(0, 0, IMAGE_PROFILE_PIXEL_DIMENSION, IMAGE_PROFILE_PIXEL_DIMENSION))
		srcImg := image.White
		draw.Draw(dstImg, dstImg.Bounds(), &image.Uniform{color}, image.ZP, draw.Src)
		size := float64(IMAGE_PROFILE_PIXEL_DIMENSION / 2)

		c := freetype.NewContext()
		c.SetFont(font)
		c.SetFontSize(size)
		c.SetClip(dstImg.Bounds())
		c.SetDst(dstImg)
		c.SetSrc(srcImg)

		pt := freetype.Pt(IMAGE_PROFILE_PIXEL_DIMENSION/5, IMAGE_PROFILE_PIXEL_DIMENSION*2/3)
		_, err = c.DrawString(initial, pt)
		if err != nil {
			return nil, model.NewAppError("CreateProfileImage", "api.user.create_profile_image.initial.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		buf := new(bytes.Buffer)

		if imgErr := png.Encode(buf, dstImg); imgErr != nil {
			return nil, model.NewAppError("CreateProfileImage", "api.user.create_profile_image.encode.app_error", nil, imgErr.Error(), http.StatusInternalServerError)
		} else {
			return buf.Bytes(), nil
		}
	*/
	return nil, nil
}

/*
func getFont(initialFont string) (*truetype.Font, error) {
	// Some people have the old default font still set, so just treat that as if they're using the new default
	if initialFont == "luximbi.ttf" {
		initialFont = "nunito-bold.ttf"
	}

	fontDir, _ := "./font/"
	fontBytes, err := ioutil.ReadFile(filepath.Join(fontDir, initialFont))
	if err != nil {
		return nil, err
	}

	return freetype.ParseFont(fontBytes)
}
*/

func (a *App) GetProfileImage(user *model.User) ([]byte, bool, *model.AppError) {
	var img []byte
	readFailed := false

	if len(*a.Config().FileSettings.DriverName) == 0 {
		var err *model.AppError
		if img, err = CreateProfileImage(user.Username, user.Id, a.Config().FileSettings.InitialFont); err != nil {
			return nil, false, err
		}
	} else {
		path := "users/" + user.Id + "/profile.png"

		if data, err := a.ReadFile(path); err != nil {
			readFailed = true

			if img, err = CreateProfileImage(user.Username, user.Id, a.Config().FileSettings.InitialFont); err != nil {
				return nil, false, err
			}

			if user.LastPictureUpdate == 0 {
				if _, err := a.WriteFile(bytes.NewReader(img), path); err != nil {
					return nil, false, err
				}
			}

		} else {
			img = data
		}
	}

	return img, readFailed, nil
}

func (a *App) SetProfileImage(userId string, imageData *multipart.FileHeader) *model.AppError {
	file, err := imageData.Open()
	if err != nil {
		return model.NewAppError("SetProfileImage", "api.user.upload_profile_user.open.app_error", nil, err.Error(), http.StatusBadRequest)
	}
	defer file.Close()
	return a.SetProfileImageFromFile(userId, file)
}

func (a *App) SetProfileImageFromFile(userId string, file multipart.File) *model.AppError {
	/*
		// Decode image config first to check dimensions before loading the whole thing into memory later on
		config, _, err := image.DecodeConfig(file)
		if err != nil {
			return model.NewAppError("SetProfileImage", "api.user.upload_profile_user.decode_config.app_error", nil, err.Error(), http.StatusBadRequest)
		} else if config.Width*config.Height > model.MaxImageSize {
			return model.NewAppError("SetProfileImage", "api.user.upload_profile_user.too_large.app_error", nil, err.Error(), http.StatusBadRequest)
		}

		file.Seek(0, 0)

		// Decode image into Image object
		img, _, err := image.Decode(file)
		if err != nil {
			return model.NewAppError("SetProfileImage", "api.user.upload_profile_user.decode.app_error", nil, err.Error(), http.StatusBadRequest)
		}

		file.Seek(0, 0)

		orientation, _ := getImageOrientation(file)
		img = makeImageUpright(img, orientation)

		// Scale profile image
		profileWidthAndHeight := 128
		img = imaging.Fill(img, profileWidthAndHeight, profileWidthAndHeight, imaging.Center, imaging.Lanczos)

		buf := new(bytes.Buffer)
		err = png.Encode(buf, img)
		if err != nil {
			return model.NewAppError("SetProfileImage", "api.user.upload_profile_user.encode.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		path := "users/" + userId + "/profile.png"

		if _, err := a.WriteFile(buf, path); err != nil {
			return model.NewAppError("SetProfileImage", "api.user.upload_profile_user.upload_profile.app_error", nil, "", http.StatusInternalServerError)
		}

		<-a.UserProvider().UpdateLastPictureUpdate(userId)

		a.InvalidateCacheForUser(userId)

		if user, err := a.GetUser(userId); err != nil {
			mlog.Error(fmt.Sprintf("Error in getting users profile for id=%v forcing logout", userId), mlog.String("user_id", userId))
		}
	*/
	return nil
}

func checkUserLoginAttempts(user *model.User, max int) *model.AppError {
	if user.FailedAttempts >= max {
		return model.NewAppError("checkUserLoginAttempts", "api.user.check_user_login_attempts.too_many.app_error", nil, "user_id="+user.Id, http.StatusUnauthorized)
	}

	return nil
}

func checkUserNotDisabled(user *model.User) *model.AppError {
	if user.DeleteAt > 0 {
		return model.NewAppError("Login", "api.user.login.inactive.app_error", nil, "user_id="+user.Id, http.StatusUnauthorized)
	}
	return nil
}

// This to be used for places we check the users password when they are already logged in
func (a *App) doubleCheckPassword(user *model.User, password string) *model.AppError {
	if err := checkUserLoginAttempts(user, a.Config().LoginSettings.MaximumLoginAttempts); err != nil {
		return err
	}

	if err := a.checkUserPassword(user, password); err != nil {
		return err
	}

	return nil
}

func (a *App) checkUserPassword(user *model.User, password string) *model.AppError {
	if !model.ComparePassword(user.Password, password) {
		if result := <-a.UserProvider().UpdateFailedPasswordAttempts(user.Id, user.FailedAttempts+1); result.Err != nil {
			return result.Err
		}

		return model.NewAppError("checkUserPassword", "api.user.check_user_password.invalid.app_error", nil, "user_id="+user.Id, http.StatusUnauthorized)
	} else {
		if result := <-a.UserProvider().UpdateFailedPasswordAttempts(user.Id, 0); result.Err != nil {
			return result.Err
		}

		return nil
	}
}

func (a *App) UpdatePasswordAsUser(userId, currentPassword, newPassword string) *model.AppError {
	var user *model.User
	var err *model.AppError

	if user, err = a.GetUser(userId); err != nil {
		return err
	}

	if user == nil {
		err = model.NewAppError("updatePassword", "api.user.update_password.valid_account.app_error", nil, "", http.StatusBadRequest)
		return err
	}

	if err := a.doubleCheckPassword(user, currentPassword); err != nil {
		err = model.NewAppError("updatePassword", "api.user.update_password.incorrect.app_error", nil, "", http.StatusBadRequest)
		return err
	}

	return a.UpdatePasswordSendEmail(user, newPassword, "api.user.update_password.menu")
}

func (a *App) SanitizeProfile(user *model.User, asAdmin bool) {
}

func (a *App) UpdateUserAsUser(user *model.User, asAdmin bool) (*model.User, *model.AppError) {
	updatedUser, err := a.UpdateUser(user, true)
	if err != nil {
		return nil, err
	}

	return updatedUser, nil
}

func (a *App) InvalidateCacheForUser(userId string) {
}

func (a *App) UpdateUser(user *model.User, sendNotifications bool) (*model.User, *model.AppError) {

	if result := <-a.UserProvider().Update(user, false); result.Err != nil {
		return nil, result.Err
	} else {
		rusers := result.Data.([2]*model.User)
		a.InvalidateCacheForUser(user.Id)
		return rusers[0], nil
	}
}

func (a *App) UpdatePasswordByUserIdSendEmail(userId, newPassword, method string) *model.AppError {
	var user *model.User
	var err *model.AppError
	if user, err = a.GetUser(userId); err != nil {
		return err
	}

	return a.UpdatePasswordSendEmail(user, newPassword, method)
}

func (a *App) UpdatePassword(user *model.User, newPassword string) *model.AppError {
	if err := a.IsPasswordValid(newPassword); err != nil {
		return err
	}

	hashedPassword := model.HashPassword(newPassword)

	if result := <-a.UserProvider().UpdatePassword(user.Id, hashedPassword); result.Err != nil {
		return model.NewAppError("UpdatePassword", "api.user.update_password.failed.app_error", nil, result.Err.Error(), http.StatusInternalServerError)
	}

	return nil
}

func (a *App) UpdatePasswordSendEmail(user *model.User, newPassword, method string) *model.AppError {
	if err := a.UpdatePassword(user, newPassword); err != nil {
		return err
	}
	/*
		a.Go(func() {
			if err := a.SendPasswordChangeEmail(user.Email, method, user.Locale, a.GetSiteURL()); err != nil {
				mlog.Error(err.Error())
			}
		})
	*/

	return nil
}

func (a *App) ResetPasswordFromToken(userSuppliedTokenString, newPassword string) *model.AppError {
	var token *model.Token
	var err *model.AppError
	if token, err = a.GetPasswordRecoveryToken(userSuppliedTokenString); err != nil {
		return err
	} else {
		if model.GetMillis()-token.CreateAt >= PASSWORD_RECOVER_EXPIRY_TIME {
			return model.NewAppError("resetPassword", "api.user.reset_password.link_expired.app_error", nil, "", http.StatusBadRequest)
		}
	}

	var user *model.User
	if user, err = a.GetUser(token.Extra); err != nil {
		return err
	}

	if err := a.UpdatePasswordSendEmail(user, newPassword, "api.user.reset_password.method"); err != nil {
		return err
	}

	if err := a.DeleteToken(token); err != nil {
		mlog.Error(err.Error())
	}

	return nil
}

func (a *App) SendPasswordReset(email string, siteURL string) (bool, *model.AppError) {

	/*
		var user *model.User
		var err *model.AppError
		if user, err = a.GetUserByEmail(email); err != nil {
			return false, nil
		}

			var token *model.Token
			if token, err = a.CreatePasswordRecoveryToken(user.Id); err != nil {
				return false, err
			}
				if _, err := a.SendPasswordResetEmail(user.Email, token, user.Locale, siteURL); err != nil {
					return false, model.NewAppError("SendPasswordReset", "api.user.send_password_reset.send.app_error", nil, "err="+err.Message, http.StatusInternalServerError)
				}
	*/

	return true, nil
}

func (a *App) CreatePasswordRecoveryToken(userId string) (*model.Token, *model.AppError) {
	token := model.NewToken(TOKEN_TYPE_PASSWORD_RECOVERY, userId)
	if result := <-a.TokenProvider().Save(token); result.Err != nil {
		return nil, result.Err
	}

	return token, nil
}

func (a *App) GetPasswordRecoveryToken(token string) (*model.Token, *model.AppError) {
	if result := <-a.TokenProvider().GetByToken(token); result.Err != nil {
		return nil, model.NewAppError("GetPasswordRecoveryToken", "api.user.reset_password.invalid_link.app_error", nil, result.Err.Error(), http.StatusBadRequest)
	} else {
		token := result.Data.(*model.Token)
		if token.Type != TOKEN_TYPE_PASSWORD_RECOVERY {
			return nil, model.NewAppError("GetPasswordRecoveryToken", "api.user.reset_password.broken_token.app_error", nil, "", http.StatusBadRequest)
		}
		return token, nil
	}
}

func (a *App) DeleteToken(token *model.Token) *model.AppError {
	if result := <-a.TokenProvider().Delete(token.Token); result.Err != nil {
		return result.Err
	}

	return nil
}

func (a *App) UpdateUserRoles(userId string, newRoles string, sendWebSocketEvent bool) (*model.User, *model.AppError) {
	var user *model.User
	var err *model.AppError
	if user, err = a.GetUser(userId); err != nil {
		err.StatusCode = http.StatusBadRequest
		return nil, err
	}

	user.Roles = newRoles
	uchan := a.UserProvider().Update(user, true)
	schan := a.SessionProvider().UpdateRoles(user.Id, newRoles)

	var ruser *model.User
	if result := <-uchan; result.Err != nil {
		return nil, result.Err
	} else {
		ruser = result.Data.([2]*model.User)[0]
	}

	if result := <-schan; result.Err != nil {
		// soft error since the user roles were still updated
		mlog.Error(fmt.Sprint(result.Err))
	}

	a.ClearSessionCacheForUser(user.Id)

	return ruser, nil
}

func (a *App) PermanentDeleteUser(user *model.User) *model.AppError {
	mlog.Warn(fmt.Sprintf("Attempting to permanently delete account %v id=%v", user.Email, user.Id), mlog.String("user_id", user.Id))

	if result := <-a.SessionProvider().PermanentDeleteSessionsByUser(user.Id); result.Err != nil {
		return result.Err
	}

	/*
		fchan := a.FileInfoProvider().GetForUser(user.Id)

		var infos []*model.FileInfo
		if result := <-fchan; result.Err != nil {
			mlog.Warn("Error getting file list for user from FileInfoStore")
		} else {
			infos = result.Data.([]*model.FileInfo)
			for _, info := range infos {
				res, err := a.FileExists(info.Path)

				if err != nil {
					mlog.Warn(
						"Error checking existence of file",
						mlog.String("path", info.Path),
						mlog.Err(err),
					)
					continue
				}

				if !res {
					mlog.Warn("File not found", mlog.String("path", info.Path))
					continue
				}

				err = a.RemoveFile(info.Path)

				if err != nil {
					mlog.Warn(
						"Unable to remove file",
						mlog.String("path", info.Path),
						mlog.Err(err),
					)
				}
			}
		}
	*/

	if result := <-a.FileInfoProvider().PermanentDeleteByUser(user.Id); result.Err != nil {
		return result.Err
	}

	if result := <-a.UserProvider().PermanentDelete(user.Id); result.Err != nil {
		return result.Err
	}

	mlog.Warn(fmt.Sprintf("Permanently deleted account %v id=%v", user.Email, user.Id), mlog.String("user_id", user.Id))

	return nil
}

func (a *App) PermanentDeleteAllUsers() *model.AppError {
	if result := <-a.UserProvider().GetAll(); result.Err != nil {
		return result.Err
	} else {
		users := result.Data.([]*model.User)
		for _, user := range users {
			a.PermanentDeleteUser(user)
		}
	}

	return nil
}

func (a *App) SendEmailVerification(user *model.User) *model.AppError {

	/*
		token, err := a.CreateVerifyEmailToken(user.Id)
		if err != nil {
			return err
		}
			if _, err := a.GetStatus(user.Id); err != nil {
				return a.SendVerifyEmail(user.Email, user.Locale, a.GetSiteURL(), token.Token)
			} else {
				return a.SendEmailChangeVerifyEmail(user.Email, user.Locale, a.GetSiteURL(), token.Token)
			}
	*/
	return nil
}

func (a *App) VerifyEmailFromToken(userSuppliedTokenString string) *model.AppError {
	var token *model.Token
	var err *model.AppError
	if token, err = a.GetVerifyEmailToken(userSuppliedTokenString); err != nil {
		return err
	} else {
		if model.GetMillis()-token.CreateAt >= PASSWORD_RECOVER_EXPIRY_TIME {
			return model.NewAppError("resetPassword", "api.user.reset_password.link_expired.app_error", nil, "", http.StatusBadRequest)
		}
		if err := a.VerifyUserEmail(token.Extra); err != nil {
			return err
		}
		if err := a.DeleteToken(token); err != nil {
			mlog.Error(err.Error())
		}
	}

	return nil
}

func (a *App) CreateVerifyEmailToken(userId string) (*model.Token, *model.AppError) {
	token := model.NewToken(TOKEN_TYPE_VERIFY_EMAIL, userId)

	if result := <-a.TokenProvider().Save(token); result.Err != nil {
		return nil, result.Err
	}

	return token, nil
}

func (a *App) GetVerifyEmailToken(token string) (*model.Token, *model.AppError) {
	if result := <-a.TokenProvider().GetByToken(token); result.Err != nil {
		return nil, model.NewAppError("GetVerifyEmailToken", "api.user.verify_email.bad_link.app_error", nil, result.Err.Error(), http.StatusBadRequest)
	} else {
		token := result.Data.(*model.Token)
		if token.Type != TOKEN_TYPE_VERIFY_EMAIL {
			return nil, model.NewAppError("GetVerifyEmailToken", "api.user.verify_email.broken_token.app_error", nil, "", http.StatusBadRequest)
		}
		return token, nil
	}
}

func (a *App) GetTotalUsersStats() (*model.UsersStats, *model.AppError) {
	stats := &model.UsersStats{}

	if result := <-a.UserProvider().GetTotalUsersCount(); result.Err != nil {
		return nil, result.Err
	} else {
		stats.TotalUsersCount = result.Data.(int64)
	}
	return stats, nil
}

func (a *App) VerifyUserEmail(userId string) *model.AppError {
	return (<-a.UserProvider().VerifyEmail(userId)).Err
}
