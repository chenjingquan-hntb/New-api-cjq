package controller

import (
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

type desktopStringRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

type desktopRefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func DesktopBridge(c *gin.Context) {
	setDesktopNoStore(c)
	if !validDesktopBrowserRequest(c) {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	endpoint, err := service.ValidateDesktopEndpoint(c.Query("endpoint"))
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	redirectTo, err := service.ValidateDesktopRedirect(c.Query("redirect_to"))
	if err != nil || !service.ValidateDesktopCodeChallenge(c.Query("code_challenge_method"), c.Query("code_challenge")) {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	bridgeToken, err := service.CreateDesktopBridgeFlow(endpoint, c.Query("code_challenge"), redirectTo)
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	service.WriteDesktopBridgeCookie(c, bridgeToken)

	if rawRefresh, cookieErr := c.Cookie(service.RefreshCookieName); cookieErr == nil {
		if _, _, validateErr := service.ValidateRefreshLoginSession(rawRefresh); validateErr == nil {
			c.Redirect(http.StatusFound, "/auth/paseo/complete")
			return
		}
	}
	c.Redirect(http.StatusFound, "/sign-in?redirect=%2Fauth%2Fpaseo%2Fcomplete")
}

func DesktopBridgeComplete(c *gin.Context) {
	setDesktopNoStore(c)
	if !validDesktopBrowserRequest(c) {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	bridgeToken, err := c.Cookie(service.DesktopBridgeCookieName)
	if err != nil || strings.TrimSpace(bridgeToken) == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	rawRefresh, err := c.Cookie(service.RefreshCookieName)
	if err != nil {
		c.Redirect(http.StatusFound, "/sign-in?redirect=%2Fauth%2Fpaseo%2Fcomplete")
		return
	}
	identity, _, err := service.ValidateRefreshLoginSession(rawRefresh)
	if err != nil {
		service.ClearDesktopBridgeCookie(c)
		c.Redirect(http.StatusFound, "/sign-in?redirect=%2Fauth%2Fpaseo%2Fcomplete")
		return
	}
	result, err := service.CompleteDesktopBridgeFlow(bridgeToken, identity)
	if err != nil {
		service.ClearDesktopBridgeCookie(c)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	service.ClearDesktopBridgeCookie(c)
	if result.RedirectTo != "" {
		values := url.Values{}
		values.Set("code", result.Code)
		values.Set("endpoint", result.Endpoint)
		c.Redirect(http.StatusFound, result.RedirectTo+"#"+values.Encode())
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("<!doctype html><meta charset=\"utf-8\"><title>Login code</title><p>Copy this one-time code into the desktop app:</p><code>"+html.EscapeString(result.Code)+"</code>"))
}

func DesktopSessionExchange(c *gin.Context) {
	setDesktopNoStore(c)
	var request desktopStringRequest
	if !decodeDesktopStringRequest(c, &request, "code", "code_verifier") {
		writeDesktopError(c, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	session, err := service.ExchangeDesktopCode(request.Code, request.CodeVerifier, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		writeDesktopError(c, http.StatusUnauthorized, service.DesktopLoginInvalidReason, "desktop login code is invalid")
		return
	}
	writeDesktopSuccess(c, session)
}

func DesktopAuthRefresh(c *gin.Context) {
	setDesktopNoStore(c)
	var request desktopRefreshRequest
	if !decodeDesktopStringRequest(c, &request, "refresh_token") {
		writeDesktopError(c, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	bundle, _, err := service.RefreshLoginSession(request.RefreshToken, "", c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		writeDesktopError(c, http.StatusUnauthorized, "AUTH_REFRESH_INVALID", "refresh token is invalid")
		return
	}
	writeDesktopSuccess(c, gin.H{
		"access_token":  bundle.AccessToken,
		"refresh_token": bundle.RefreshToken,
		"expires_in":    int64(service.AccessTokenTTL / time.Second),
	})
}

func DesktopAuthLogout(c *gin.Context) {
	setDesktopNoStore(c)
	var request desktopRefreshRequest
	if !decodeDesktopStringRequest(c, &request, "refresh_token") {
		writeDesktopError(c, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	if _, ok := service.RefreshTokenSID(request.RefreshToken); !ok {
		writeDesktopError(c, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	if err := service.RevokeByRefreshToken(request.RefreshToken, "", "logout"); err != nil {
		writeDesktopError(c, http.StatusInternalServerError, "AUTH_LOGOUT_FAILED", "logout failed")
		return
	}
	writeDesktopSuccess(c, gin.H{})
}

func DesktopAuthMe(c *gin.Context) {
	setDesktopNoStore(c)
	rawToken, ok := dashboardBearer(c.GetHeader("Authorization"))
	if !ok {
		writeDesktopError(c, http.StatusUnauthorized, "AUTH_UNAUTHORIZED", "authorization required")
		return
	}
	identity, err := service.ParseAccessToken(rawToken)
	if err != nil {
		writeDesktopError(c, http.StatusUnauthorized, "AUTH_UNAUTHORIZED", "authorization required")
		return
	}
	if _, _, err := service.ValidateLoginSession(identity); err != nil {
		writeDesktopError(c, http.StatusUnauthorized, "AUTH_UNAUTHORIZED", "authorization required")
		return
	}
	user, err := model.GetSelfUserById(identity.UserID)
	if err != nil || user.Status != common.UserStatusEnabled {
		writeDesktopError(c, http.StatusUnauthorized, "AUTH_UNAUTHORIZED", "authorization required")
		return
	}
	balance := 0.0
	if common.QuotaPerUnit > 0 {
		balance = float64(user.Quota) / common.QuotaPerUnit
	}
	allowedGroups, err := desktopAllowedGroupIDs(user.Group)
	if err != nil {
		writeDesktopError(c, http.StatusServiceUnavailable, "ME_GROUP_IDS_UNAVAILABLE", "group identifiers are unavailable")
		return
	}
	writeDesktopSuccess(c, gin.H{
		"id":             user.Id,
		"email":          user.Email,
		"username":       user.Username,
		"role":           desktopRoleName(user.Role),
		"balance":        balance,
		"status":         desktopStatusName(user.Status),
		"allowed_groups": allowedGroups,
	})
}

func decodeDesktopStringRequest(c *gin.Context, target any, names ...string) bool {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return false
	}
	var fields map[string]json.RawMessage
	if err := common.Unmarshal(body, &fields); err != nil || len(fields) != len(names) {
		return false
	}
	allowed := make(map[string]struct{}, len(names))
	for _, name := range names {
		allowed[name] = struct{}{}
		raw, ok := fields[name]
		if !ok || common.GetJsonType(raw) != "string" {
			return false
		}
	}
	for name := range fields {
		if _, ok := allowed[name]; !ok {
			return false
		}
	}
	if err := common.UnmarshalJsonStr(string(mustMarshalJSON(fields)), target); err != nil {
		return false
	}
	switch request := target.(type) {
	case *desktopStringRequest:
		return strings.TrimSpace(request.Code) != "" && strings.TrimSpace(request.CodeVerifier) != ""
	case *desktopRefreshRequest:
		return strings.TrimSpace(request.RefreshToken) != ""
	default:
		return false
	}
}

func mustMarshalJSON(value any) []byte {
	encoded, err := common.Marshal(value)
	if err != nil {
		return []byte("null")
	}
	return encoded
}

func writeDesktopSuccess(c *gin.Context, data any) {
	writeDesktopJSON(c, http.StatusOK, gin.H{"code": 0, "message": "", "reason": nil, "data": data})
}

func writeDesktopError(c *gin.Context, status int, reason, message string) {
	writeDesktopJSON(c, status, gin.H{"code": 1, "message": message, "reason": reason, "data": gin.H{}})
}

func writeDesktopJSON(c *gin.Context, status int, value any) {
	body, err := common.Marshal(value)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Data(status, "application/json; charset=utf-8", body)
}

func desktopAllowedGroupIDs(userGroup string) ([]int64, error) {
	mapping, err := model.GetDesktopGroupIDs()
	if err != nil {
		return nil, err
	}
	groups := service.GetUserUsableGroups(userGroup)
	ids := make([]int64, 0, len(groups))
	for name := range groups {
		if id, exists := mapping[name]; exists {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids, nil
}
func setDesktopNoStore(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Security-Policy", "default-src 'none'; base-uri 'none'; form-action 'none'")
}

func validDesktopBrowserRequest(c *gin.Context) bool {
	fetchSite := strings.ToLower(strings.TrimSpace(c.GetHeader("Sec-Fetch-Site")))
	if fetchSite != "" && fetchSite != "none" && fetchSite != "same-origin" {
		return false
	}
	expectedScheme := "http"
	if c.Request.TLS != nil || strings.EqualFold(strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")), "https") {
		expectedScheme = "https"
	}
	expectedHost := c.Request.Host
	if forwardedHost := strings.TrimSpace(c.GetHeader("X-Forwarded-Host")); forwardedHost != "" {
		expectedHost = forwardedHost
	}
	for _, header := range []string{"Origin", "Referer"} {
		raw := strings.TrimSpace(c.GetHeader(header))
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != expectedScheme || u.Host != expectedHost {
			return false
		}
	}
	return true
}

func desktopRoleName(role int) string {
	switch role {
	case common.RoleRootUser:
		return "root"
	case common.RoleAdminUser:
		return "admin"
	case common.RoleCommonUser:
		return "user"
	default:
		return "guest"
	}
}

func desktopStatusName(status int) string {
	if status == common.UserStatusEnabled {
		return "active"
	}
	return "disabled"
}
