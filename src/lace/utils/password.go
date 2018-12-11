package utils

import (
	"lace/model"
	"net/http"
)

func IsPasswordValid(password string) *model.AppError {
	if len(password) > model.PASSWORD_MAXIMUM_LENGTH || len(password) < model.PASSWORD_MINIMUM_LENGTH {
		return model.NewAppError("User.IsValid", "model.user.is_valid.pwd.app_error", map[string]interface{}{"Min": model.PASSWORD_MINIMUM_LENGTH}, "", http.StatusBadRequest)
	}

	return nil
}
