package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"

	"gorm.io/gorm"
)

const (
	DesktopBridgeCookieName       = "new_api_desktop_bridge"
	DesktopBridgeTTL              = 10 * time.Minute
	DesktopLoginCodeTTL           = 5 * time.Minute
	DesktopLoginInvalidReason     = "DESKTOP_LOGIN_CODE_INVALID"
	DesktopLoginCodeLength        = 32
	DesktopLoginVerifierMinLength = 43
	DesktopLoginVerifierMaxLength = 128
)

type DesktopBridgePayload struct {
	Endpoint      string `json:"endpoint"`
	CodeChallenge string `json:"code_challenge"`
	RedirectTo    string `json:"redirect_to,omitempty"`
}

type DesktopCodePayload struct {
	DesktopBridgePayload
	BrowserIdentity AuthIdentity `json:"browser_identity"`
}

type DesktopBridgeResult struct {
	Code       string
	Endpoint   string
	RedirectTo string
}

type DesktopSession struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	APIKey       string `json:"api_key,omitempty"`
	ClaudeAPIKey string `json:"claude_api_key,omitempty"`
	CodexAPIKey  string `json:"codex_api_key,omitempty"`
}

func NormalizeDesktopCode(raw string) (string, bool) {
	var builder strings.Builder
	for _, r := range strings.TrimSpace(raw) {
		if r == '-' || r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			continue
		}
		if r >= 'a' && r <= 'z' {
			r -= 'a' - 'A'
		}
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return "", false
		}
		builder.WriteRune(r)
	}
	code := builder.String()
	return code, len(code) >= 6 && len(code) <= DesktopLoginCodeLength
}

func ValidateDesktopEndpoint(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("invalid desktop endpoint")
	}
	if (u.Path != "" && u.Path != "/") || (u.RawPath != "" && u.RawPath != "/") {
		return "", errors.New("invalid desktop endpoint path")
	}
	if u.Hostname() == "" || strings.Contains(u.Host, "\\") {
		return "", errors.New("invalid desktop endpoint host")
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid desktop endpoint port")
		}
	}
	host := strings.ToLower(u.Hostname())
	if port != "" {
		return u.Scheme + "://" + net.JoinHostPort(host, port), nil
	}
	return u.Scheme + "://" + host, nil
}

func ValidateDesktopRedirect(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/callback" || (u.RawPath != "" && u.RawPath != "/callback") || u.Port() == "" {
		return "", errors.New("invalid desktop redirect")
	}
	port := u.Port()
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("invalid desktop redirect port")
	}
	return "http://127.0.0.1:" + strconv.Itoa(n) + "/callback", nil
}

func ValidateDesktopCodeChallenge(method, challenge string) bool {
	if method != "S256" || len(challenge) != 43 {
		return false
	}
	for _, r := range challenge {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(decoded) == sha256.Size
}

func ValidateDesktopCodeVerifier(verifier string) bool {
	if len(verifier) < DesktopLoginVerifierMinLength || len(verifier) > DesktopLoginVerifierMaxLength {
		return false
	}
	for _, r := range verifier {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && !strings.ContainsRune("-._~", r) {
			return false
		}
	}
	return true
}

func DesktopCodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func CreateDesktopBridgeFlow(endpoint, challenge, redirect string) (string, error) {
	endpoint, err := ValidateDesktopEndpoint(endpoint)
	if err != nil {
		return "", err
	}
	redirect, err = ValidateDesktopRedirect(redirect)
	if err != nil {
		return "", err
	}
	if !ValidateDesktopCodeChallenge("S256", challenge) {
		return "", errors.New("invalid desktop code challenge")
	}
	payload, err := common.Marshal(DesktopBridgePayload{Endpoint: endpoint, CodeChallenge: challenge, RedirectTo: redirect})
	if err != nil {
		return "", err
	}
	token, _, err := model.CreateAuthFlow(model.AuthFlowCreate{
		Purpose:   model.AuthFlowPurposeDesktopBridge,
		Payload:   string(payload),
		ExpiresAt: time.Now().Add(DesktopBridgeTTL),
	})
	return token, err
}

func CompleteDesktopBridgeFlow(bridgeToken string, identity AuthIdentity) (*DesktopBridgeResult, error) {
	if identity.UserID <= 0 || identity.SessionID == "" {
		return nil, ErrLoginSessionInvalid
	}
	var result DesktopBridgeResult
	_, err := model.ConsumeAuthFlowWithAction(bridgeToken, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeDesktopBridge}, func(tx *gorm.DB, flow *model.AuthFlow) error {
		var payload DesktopBridgePayload
		if err := common.UnmarshalJsonStr(flow.Payload, &payload); err != nil {
			return model.ErrAuthFlowInvalid
		}
		if err := model.ValidateAuthSessionWithTx(tx, model.AuthSessionIdentity{UserID: identity.UserID, SessionID: identity.SessionID, UserAuthVersion: identity.UserAuthVersion, SessionVersion: identity.SessionVersion}); err != nil {
			return ErrLoginSessionRevoked
		}
		bytes := make([]byte, DesktopLoginCodeLength)
		if _, err := rand.Read(bytes); err != nil {
			return err
		}
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		var builder strings.Builder
		builder.Grow(DesktopLoginCodeLength)
		for _, b := range bytes {
			builder.WriteByte(alphabet[int(b)%len(alphabet)])
		}
		code := builder.String()
		identityPayload, err := common.Marshal(DesktopCodePayload{DesktopBridgePayload: payload, BrowserIdentity: identity})
		if err != nil {
			return err
		}
		if _, _, err = model.CreateAuthFlowWithTx(tx, model.AuthFlowCreate{
			Purpose:   model.AuthFlowPurposeDesktopCode,
			UserId:    identity.UserID,
			SessionId: identity.SessionID,
			Payload:   string(identityPayload),
			Token:     code,
			ExpiresAt: time.Now().Add(DesktopLoginCodeTTL),
		}); err != nil {
			return err
		}
		result = DesktopBridgeResult{Code: code, Endpoint: payload.Endpoint, RedirectTo: payload.RedirectTo}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func ExchangeDesktopCode(code, verifier, ip, userAgent string) (*DesktopSession, error) {
	code, ok := NormalizeDesktopCode(code)
	if !ok || !ValidateDesktopCodeVerifier(verifier) {
		return nil, errors.New(DesktopLoginInvalidReason)
	}
	flow, err := model.GetAuthFlow(code, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeDesktopCode})
	if err != nil {
		return nil, errors.New(DesktopLoginInvalidReason)
	}
	var payload DesktopCodePayload
	if err := common.UnmarshalJsonStr(flow.Payload, &payload); err != nil || !ValidateDesktopCodeChallenge("S256", payload.CodeChallenge) || payload.BrowserIdentity.UserID != flow.UserId || payload.BrowserIdentity.SessionID != flow.SessionId {
		return nil, errors.New(DesktopLoginInvalidReason)
	}
	if subtle.ConstantTimeCompare([]byte(DesktopCodeChallenge(verifier)), []byte(payload.CodeChallenge)) != 1 {
		return nil, errors.New(DesktopLoginInvalidReason)
	}
	var createdSession *model.UserSession
	var refreshSecret string
	_, err = model.ConsumeAuthFlowWithAction(code, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeDesktopCode, UserId: flow.UserId, SessionId: flow.SessionId}, func(tx *gorm.DB, _ *model.AuthFlow) error {
		if err := model.ValidateAuthSessionWithTx(tx, model.AuthSessionIdentity{UserID: payload.BrowserIdentity.UserID, SessionID: payload.BrowserIdentity.SessionID, UserAuthVersion: payload.BrowserIdentity.UserAuthVersion, SessionVersion: payload.BrowserIdentity.SessionVersion}); err != nil {
			return ErrLoginSessionRevoked
		}
		var err error
		createdSession, refreshSecret, err = createLoginSessionWithTx(tx, flow.UserId, payload.BrowserIdentity.UserAuthVersion, "desktop", ip, userAgent)
		return err
	})
	if err != nil {
		return nil, errors.New(DesktopLoginInvalidReason)
	}
	if err := model.PublishCreatedUserSession(createdSession); err != nil {
		return nil, err
	}
	bundle, err := issueAuthBundle(createdSession, createdSession.SID+"."+refreshSecret, false)
	if err != nil {
		return nil, err
	}
	return &DesktopSession{AccessToken: bundle.AccessToken, RefreshToken: bundle.RefreshToken, ExpiresIn: int64(AccessTokenTTL / time.Second)}, nil
}

func WriteDesktopBridgeCookie(c *gin.Context, token string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: DesktopBridgeCookieName, Value: token, Path: "/", MaxAge: int(DesktopBridgeTTL / time.Second),
		HttpOnly: true, Secure: common.SessionCookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

func ClearDesktopBridgeCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: DesktopBridgeCookieName, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0),
		HttpOnly: true, Secure: common.SessionCookieSecure, SameSite: http.SameSiteLaxMode,
	})
}
