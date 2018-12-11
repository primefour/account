package app

import (
	"fmt"
	"lace/mlog"
	"lace/model"
	"lace/utils"
	"net/http"
	"strings"
)

type TokenLocation int

const (
	TokenLocationNotFound = iota
	TokenLocationHeader
	TokenLocationCookie
	TokenLocationQueryString
)

func (tl TokenLocation) String() string {
	switch tl {
	case TokenLocationNotFound:
		return "Not Found"
	case TokenLocationHeader:
		return "Header"
	case TokenLocationCookie:
		return "Cookie"
	case TokenLocationQueryString:
		return "QueryString"
	default:
		return "Unknown"
	}
}

func (a *App) CreateSession(session *model.Session) (*model.Session, *model.AppError) {
	session.Token = ""

	if result := <-a.SessionProvider().Save(session); result.Err != nil {
		return nil, result.Err
	} else {
		session := result.Data.(*model.Session)

		a.AddSessionToCache(session)

		return session, nil
	}
}

func (a *App) GetSession(token string) (*model.Session, *model.AppError) {
	var session *model.Session
	if ts, ok := a.sessionCache.Get(token); ok {
		session = ts.(*model.Session)
	}

	if session == nil {
		if sessionResult := <-a.SessionProvider().Get(token); sessionResult.Err == nil {
			session = sessionResult.Data.(*model.Session)

			if session != nil {
				if session.Token != token {
					return nil, model.NewAppError("GetSession", "api.context.invalid_token.error", map[string]interface{}{"Token": token, "Error": ""}, "", http.StatusUnauthorized)
				}

				if !session.IsExpired() {
					a.AddSessionToCache(session)
				}
			}
		} else if sessionResult.Err.StatusCode == http.StatusInternalServerError {
			return nil, sessionResult.Err
		}
	}

	if session == nil || session.IsExpired() {
		return nil, model.NewAppError("GetSession", "api.context.invalid_token.error", map[string]interface{}{"Token": token}, "", http.StatusUnauthorized)
	}

	if a.Config().LoginSettings.SessionIdleTimeoutInMinutes > 0 {
		timeout := a.Config().LoginSettings.SessionIdleTimeoutInMinutes * 1000 * 60
		if model.GetMillis()-session.LastActivityAt > timeout {
			a.RevokeSessionById(session.Id)
			return nil, model.NewAppError("GetSession", "api.context.invalid_token.error", map[string]interface{}{"Token": token}, "idle timeout", http.StatusUnauthorized)
		}
	}

	return session, nil
}

func (a *App) GetSessions(userId string) ([]*model.Session, *model.AppError) {
	if result := <-a.SessionProvider().GetSessions(userId); result.Err != nil {
		return nil, result.Err
	} else {
		return result.Data.([]*model.Session), nil
	}
}

func (a *App) RevokeAllSessions(userId string) *model.AppError {
	if result := <-a.SessionProvider().GetSessions(userId); result.Err != nil {
		return result.Err
	} else {
		sessions := result.Data.([]*model.Session)

		for _, session := range sessions {
			if result := <-a.SessionProvider().Remove(session.Id); result.Err != nil {
				return result.Err
			}
		}
	}

	a.ClearSessionCacheForUser(userId)

	return nil
}

func (a *App) ClearSessionCacheForUser(userId string) {
	keys := a.sessionCache.Keys()

	for _, key := range keys {
		if ts, ok := a.sessionCache.Get(key); ok {
			session := ts.(*model.Session)
			if session.UserId == userId {
				a.sessionCache.Remove(key)
			}
		}
	}
}

func (a *App) AddSessionToCache(session *model.Session) {
	a.sessionCache.AddWithExpiresInSecs(session.Token, session,
		a.Config().LoginSettings.SessionCacheInMinutes*60)
}

func (a *App) SessionCacheLength() int {
	return a.sessionCache.Len()
}

func (a *App) RevokeSessionsForDeviceId(userId string, deviceId string, currentSessionId string) *model.AppError {
	if result := <-a.SessionProvider().GetSessions(userId); result.Err != nil {
		return result.Err
	} else {
		sessions := result.Data.([]*model.Session)
		for _, session := range sessions {
			if session.DeviceId == deviceId && session.Id != currentSessionId {
				mlog.Debug(fmt.Sprintf("Revoking sessionId=%v for userId=%v re-login with same device Id", session.Id, userId), mlog.String("user_id", userId))
				if err := a.RevokeSession(session); err != nil {
					// Soft error so we still remove the other sessions
					mlog.Error(err.Error())
				}
			}
		}
	}

	return nil
}

func (a *App) GetSessionById(sessionId string) (*model.Session, *model.AppError) {
	if result := <-a.SessionProvider().Get(sessionId); result.Err != nil {
		result.Err.StatusCode = http.StatusBadRequest
		return nil, result.Err
	} else {
		return result.Data.(*model.Session), nil
	}
}

func (a *App) RevokeSessionById(sessionId string) *model.AppError {
	if result := <-a.SessionProvider().Get(sessionId); result.Err != nil {
		result.Err.StatusCode = http.StatusBadRequest
		return result.Err
	} else {
		return a.RevokeSession(result.Data.(*model.Session))
	}
}

func (a *App) RevokeSession(session *model.Session) *model.AppError {
	if result := <-a.SessionProvider().Remove(session.Id); result.Err != nil {
		return result.Err
	}
	a.ClearSessionCacheForUser(session.UserId)
	return nil
}

func (a *App) AttachDeviceId(sessionId string, deviceId string, expiresAt int64) *model.AppError {
	if result := <-a.SessionProvider().UpdateDeviceId(sessionId, deviceId, expiresAt); result.Err != nil {
		return result.Err
	}

	return nil
}

func (a *App) UpdateLastActivityAtIfNeeded(session model.Session) {
	now := model.GetMillis()

	if now-session.LastActivityAt < model.SESSION_ACTIVITY_TIMEOUT {
		return
	}

	if result := <-a.SessionProvider().UpdateLastActivityAt(session.Id, now); result.Err != nil {
		mlog.Error(fmt.Sprintf("Failed to update LastActivityAt for user_id=%v and session_id=%v, err=%v", session.UserId, session.Id, result.Err), mlog.String("user_id", session.UserId))
	}

	session.LastActivityAt = now
	a.AddSessionToCache(&session)
}

func ParseAuthTokenFromRequest(r *http.Request) (string, TokenLocation) {
	authHeader := r.Header.Get(utils.HEADER_AUTH)
	if len(authHeader) > 6 && strings.ToUpper(authHeader[0:6]) == utils.HEADER_BEARER {
		// Default session token
		return authHeader[7:], TokenLocationHeader
	} else if len(authHeader) > 5 && strings.ToLower(authHeader[0:5]) == utils.HEADER_TOKEN {
		// OAuth token
		return authHeader[6:], TokenLocationHeader
	}

	// Attempt to parse the token from the cookie
	if cookie, err := r.Cookie(model.SESSION_COOKIE_TOKEN); err == nil {
		return cookie.Value, TokenLocationCookie
	}

	// Attempt to parse token out of the query string
	if token := r.URL.Query().Get("access_token"); token != "" {
		return token, TokenLocationQueryString
	}

	return "", TokenLocationNotFound
}
