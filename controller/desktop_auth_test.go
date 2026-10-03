package controller

import (
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestValidDesktopBrowserRequestRejectsCrossSiteNavigation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name   string
		modify func(*http.Request)
		want   bool
	}{
		{name: "no browser metadata", want: true},
		{name: "same origin", modify: func(r *http.Request) {
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			r.Header.Set("Origin", "https://gateway.example")
		}, want: true},
		{name: "cross site fetch", modify: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, want: false},
		{name: "foreign origin", modify: func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") }, want: false},
		{name: "foreign referer", modify: func(r *http.Request) { r.Header.Set("Referer", "https://attacker.example/login") }, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://gateway.example/auth/paseo", nil)
			if tc.modify != nil {
				tc.modify(req)
			}
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = req
			assert.Equal(t, tc.want, validDesktopBrowserRequest(c))
		})
	}
}

// The optional DSN is only for isolated, empty regression databases, never a
// production database. The same observable contracts run on all three engines.
func TestDesktopCompatibilityGroupNumberingAndAuth(t *testing.T) {
	engine := os.Getenv("DESKTOP_AUTH_TEST_DATABASE")
	dsn := os.Getenv("DESKTOP_AUTH_TEST_DSN")
	var dialector gorm.Dialector
	switch engine {
	case "", "sqlite":
		dsn = filepath.Join(t.TempDir(), "desktop.db")
		dialector = sqlite.Open(dsn)
	case "mysql":
		require.NotEmpty(t, dsn)
		dialector = mysql.Open(dsn)
	case "postgres":
		require.NotEmpty(t, dsn)
		dialector = postgres.Open(dsn)
	default:
		t.Fatalf("unsupported test database: %s", engine)
	}
	db, err := gorm.Open(dialector, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(8)
	versionQuery := "SELECT VERSION()"
	if engine == "" || engine == "sqlite" {
		versionQuery = "SELECT sqlite_version()"
	}
	var databaseVersion string
	require.NoError(t, sqlDB.QueryRow(versionQuery).Scan(&databaseVersion))
	t.Logf("database=%s version=%s", db.Dialector.Name(), databaseVersion)
	t.Cleanup(func() { _ = sqlDB.Close() })
	// Start with the existing native schema, without adding a compatibility
	// table or column; an old installation gets only a private option row.
	require.NoError(t, db.AutoMigrate(&model.Option{}, &model.User{}, &model.UserSession{}, &model.AuthFlow{}))
	var optionCount int64
	require.NoError(t, db.Model(&model.Option{}).Count(&optionCount).Error)
	require.Zero(t, optionCount, "use an empty isolated test database")

	previousDB, previousRedis, previousSecret := model.DB, common.RedisEnabled, common.SessionSecret
	previousDatabaseType := common.MainDatabaseType()
	common.SetMainDatabaseType(common.DatabaseType(db.Dialector.Name()))
	previousRatios := ratio_setting.GroupRatio2JSONString()
	previousUsable := setting.UserUsableGroups2JSONString()
	common.OptionMapRWMutex.Lock()
	previousOptions := common.OptionMap
	common.OptionMap = make(map[string]string)
	common.OptionMapRWMutex.Unlock()
	model.DB, common.RedisEnabled, common.SessionSecret = db, false, "desktop-compatibility-test-secret"
	t.Cleanup(func() {
		model.DB, common.RedisEnabled, common.SessionSecret = previousDB, previousRedis, previousSecret
		common.SetMainDatabaseType(previousDatabaseType)
		_ = ratio_setting.UpdateGroupRatioByJSONString(previousRatios)
		_ = setting.UpdateUserUsableGroupsByJSONString(previousUsable)
		common.OptionMapRWMutex.Lock()
		common.OptionMap = previousOptions
		common.OptionMapRWMutex.Unlock()
	})
	// Preserve a representative pre-compatibility option and an existing user.
	require.NoError(t, db.Create(&model.Option{Key: "SystemName", Value: "preserved-test-name"}).Error)
	require.NoError(t, db.Create(&model.Option{Key: "GroupRatio", Value: `{"default":1}`}).Error)
	require.NoError(t, ratio_setting.UpdateGroupRatioByJSONString(`{"default":1}`))
	require.NoError(t, setting.UpdateUserUsableGroupsByJSONString(`{"default":"Default","vip":"not configured"}`))
	user := &model.User{Username: "desktop-compatibility-user", Password: "unused", Role: common.RoleCommonUser,
		Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, Quota: 1000000}
	require.NoError(t, db.Create(user).Error)
	// Competing first readers must initialize exactly the same persisted order.
	type initialMapping struct {
		ids map[string]int64
		err error
	}
	initial := make(chan initialMapping, 2)
	var initialWait sync.WaitGroup
	for range 2 {
		initialWait.Go(func() {
			ids, err := model.GetDesktopGroupIDs()
			initial <- initialMapping{ids: ids, err: err}
		})
	}
	initialWait.Wait()
	close(initial)
	for result := range initial {
		require.NoError(t, result.err)
		assert.Equal(t, map[string]int64{"default": 1}, result.ids)
	}
	mapping, err := model.GetDesktopGroupIDs()
	require.NoError(t, err)
	ids, err := desktopAllowedGroupIDs("default")
	require.NoError(t, err)
	assert.Equal(t, []int64{1}, ids, "unconfigured vip must not be fabricated")

	// This is the actual browser-session -> code -> exchange -> me -> refresh
	// -> logout controller/service chain, not a success-envelope fixture.
	browser, err := service.CreateLoginSession(user.Id, "password", "127.0.0.1", "browser")
	require.NoError(t, err)
	identity, err := service.ParseAccessToken(browser.AccessToken)
	require.NoError(t, err)
	verifier := strings.Repeat("k", 64)
	bridge, err := service.CreateDesktopBridgeFlow("https://gateway.example", service.DesktopCodeChallenge(verifier), "")
	require.NoError(t, err)
	result, err := service.CompleteDesktopBridgeFlow(bridge, identity)
	require.NoError(t, err)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/auth/desktop-session/exchange", DesktopSessionExchange)
	router.GET("/api/v1/auth/me", DesktopAuthMe)
	router.POST("/api/v1/auth/refresh", DesktopAuthRefresh)
	router.POST("/api/v1/auth/logout", DesktopAuthLogout)
	unauthorized := httptest.NewRecorder()
	router.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil))
	assert.Equal(t, http.StatusUnauthorized, unauthorized.Code)
	// A wrong verifier must not consume the valid code or create a session.
	wrongBody, err := common.Marshal(map[string]string{"code": result.Code, "code_verifier": strings.Repeat("w", 64)})
	require.NoError(t, err)
	wrong := httptest.NewRecorder()
	router.ServeHTTP(wrong, httptest.NewRequest(http.MethodPost, "/api/v1/auth/desktop-session/exchange", strings.NewReader(string(wrongBody))))
	assert.Equal(t, http.StatusUnauthorized, wrong.Code)
	assert.Contains(t, wrong.Body.String(), service.DesktopLoginInvalidReason)
	var sessionCount int64
	require.NoError(t, db.Model(&model.UserSession{}).Where("user_id = ?", user.Id).Count(&sessionCount).Error)
	assert.EqualValues(t, 1, sessionCount)
	requestBody, err := common.Marshal(map[string]string{"code": result.Code, "code_verifier": verifier})
	require.NoError(t, err)
	exchange := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/desktop-session/exchange", strings.NewReader(string(requestBody)))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(exchange, request)
	require.Equal(t, http.StatusOK, exchange.Code)
	var session struct {
		Code int `json:"code"`
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int64  `json:"expires_in"`
		} `json:"data"`
	}
	require.NoError(t, common.Unmarshal(exchange.Body.Bytes(), &session))
	require.Zero(t, session.Code)
	require.NotEmpty(t, session.Data.AccessToken)
	require.NotEmpty(t, session.Data.RefreshToken)
	require.Positive(t, session.Data.ExpiresIn)
	me := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	request.Header.Set("Authorization", "Bearer "+session.Data.AccessToken)
	router.ServeHTTP(me, request)
	require.Equal(t, http.StatusOK, me.Code)
	var account struct {
		Code int `json:"code"`
		Data struct {
			ID            int     `json:"id"`
			Role          string  `json:"role"`
			Status        string  `json:"status"`
			Balance       float64 `json:"balance"`
			AllowedGroups []int64 `json:"allowed_groups"`
		} `json:"data"`
	}
	require.NoError(t, common.Unmarshal(me.Body.Bytes(), &account))
	assert.Zero(t, account.Code)
	assert.Equal(t, user.Id, account.Data.ID)
	assert.Equal(t, "user", account.Data.Role)
	assert.Equal(t, "active", account.Data.Status)
	assert.Equal(t, float64(user.Quota)/common.QuotaPerUnit, account.Data.Balance)
	assert.Equal(t, []int64{1}, account.Data.AllowedGroups)
	assert.Equal(t, "no-store", me.Header().Get("Cache-Control"))
	oldRefreshToken := session.Data.RefreshToken
	oldAccessToken := session.Data.AccessToken
	refresh := httptest.NewRecorder()
	payload, err := common.Marshal(map[string]string{"refresh_token": oldRefreshToken})
	require.NoError(t, err)
	request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(string(payload)))
	router.ServeHTTP(refresh, request)
	require.Equal(t, http.StatusOK, refresh.Code)
	require.NoError(t, common.Unmarshal(refresh.Body.Bytes(), &session))
	require.Zero(t, session.Code)
	assert.NotEqual(t, oldRefreshToken, session.Data.RefreshToken)
	assert.NotEqual(t, oldAccessToken, session.Data.AccessToken)
	staleRefresh := httptest.NewRecorder()
	router.ServeHTTP(staleRefresh, httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(string(payload))))
	require.Equal(t, http.StatusOK, staleRefresh.Code)
	recovered := session
	require.NoError(t, common.Unmarshal(staleRefresh.Body.Bytes(), &recovered))
	assert.Equal(t, session.Data.RefreshToken, recovered.Data.RefreshToken, "native bounded grace must recover the winner token")
	staleMe := httptest.NewRecorder()
	staleRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	staleRequest.Header.Set("Authorization", "Bearer "+oldAccessToken)
	router.ServeHTTP(staleMe, staleRequest)
	assert.Equal(t, http.StatusOK, staleMe.Code, "refresh preserves native access-token lifetime until revocation")
	payload, err = common.Marshal(map[string]string{"refresh_token": session.Data.RefreshToken})
	require.NoError(t, err)
	for range 2 {
		logout := httptest.NewRecorder()
		request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", strings.NewReader(string(payload)))
		router.ServeHTTP(logout, request)
		require.Equal(t, http.StatusOK, logout.Code)
	}
	me = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	request.Header.Set("Authorization", "Bearer "+session.Data.AccessToken)
	router.ServeHTTP(me, request)
	assert.Equal(t, http.StatusUnauthorized, me.Code)
	refresh = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(string(payload)))
	router.ServeHTTP(refresh, request)
	assert.Equal(t, http.StatusUnauthorized, refresh.Code)
	_, _, err = service.ValidateLoginSession(identity)
	require.NoError(t, err, "desktop logout must not revoke the browser session")

	// Code expiry, concurrency and rollback run on every real dialect, with
	// its actual row-lock branch enabled by the fixture above.
	bridge, err = service.CreateDesktopBridgeFlow("https://gateway.example", service.DesktopCodeChallenge(verifier), "")
	require.NoError(t, err)
	result, err = service.CompleteDesktopBridgeFlow(bridge, identity)
	require.NoError(t, err)
	flow, err := model.GetAuthFlow(result.Code, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeDesktopCode})
	require.NoError(t, err)
	require.NoError(t, db.Model(flow).Update("expires_at", time.Now().Add(-time.Minute)).Error)
	_, err = service.ExchangeDesktopCode(result.Code, verifier, "127.0.0.1", "desktop")
	require.EqualError(t, err, service.DesktopLoginInvalidReason)

	bridge, err = service.CreateDesktopBridgeFlow("https://gateway.example", service.DesktopCodeChallenge(verifier), "")
	require.NoError(t, err)
	result, err = service.CompleteDesktopBridgeFlow(bridge, identity)
	require.NoError(t, err)
	// Failure after claiming the flow must leave the code usable.
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register("desktop-session-failure", func(tx *gorm.DB) {
		if row, ok := tx.Statement.Dest.(*model.UserSession); ok && row.LoginMethod == "desktop" {
			tx.AddError(fmt.Errorf("test session write failed"))
		}
	}))
	_, err = service.ExchangeDesktopCode(result.Code, verifier, "127.0.0.1", "desktop")
	require.EqualError(t, err, service.DesktopLoginInvalidReason)
	require.NoError(t, db.Callback().Create().Remove("desktop-session-failure"))
	_, err = model.GetAuthFlow(result.Code, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeDesktopCode})
	require.NoError(t, err, "session failure must roll back code consumption")
	exchanges := make(chan error, 2)
	winner := make(chan *service.DesktopSession, 1)
	var exchangeWait sync.WaitGroup
	for range 2 {
		exchangeWait.Go(func() {
			issued, err := service.ExchangeDesktopCode(result.Code, verifier, "127.0.0.1", "desktop")
			if err == nil {
				winner <- issued
			}
			exchanges <- err
		})
	}
	exchangeWait.Wait()
	close(exchanges)
	successes := 0
	for exchangeErr := range exchanges {
		if exchangeErr == nil {
			successes++
		} else {
			assert.EqualError(t, exchangeErr, service.DesktopLoginInvalidReason)
		}
	}
	require.Equal(t, 1, successes, "concurrent exchanges must issue exactly one session")
	require.NoError(t, db.Model(&model.UserSession{}).Where("user_id = ?", user.Id).Count(&sessionCount).Error)
	assert.EqualValues(t, 3, sessionCount, "wrong, expired, rolled-back and replayed codes must not issue sessions")

	// Known previous-token reuse beyond the native bounded grace revokes the
	// family, including the winning refresh and access token, without sleeps.
	issued := <-winner
	rotated, _, err := service.RefreshLoginSession(issued.RefreshToken, "", "127.0.0.1", "desktop")
	require.NoError(t, err)
	require.NoError(t, db.Model(&model.UserSession{}).Where("sid = ?", rotated.Session.SID).
		Update("previous_valid_until", time.Now().Unix()-1).Error)
	_, _, err = service.RefreshLoginSession(issued.RefreshToken, "", "127.0.0.1", "desktop")
	require.Error(t, err)
	_, _, err = service.RefreshLoginSession(rotated.RefreshToken, "", "127.0.0.1", "desktop")
	require.Error(t, err)
	issuedIdentity, err := service.ParseAccessToken(rotated.AccessToken)
	require.NoError(t, err)
	_, _, err = service.ValidateLoginSession(issuedIdentity)
	require.Error(t, err)
	_, _, err = service.ValidateLoginSession(identity)
	require.NoError(t, err, "refresh-family reuse must not revoke the browser")

	// New groups append in creation order, not lexicographic order per request.
	changes := []struct {
		value string
		want  map[string]int64
	}{
		{`{"default":1,"z-last":1}`, map[string]int64{"default": 1, "z-last": 2}},
		{`{"a-first":1,"default":1,"z-last":1}`, map[string]int64{"default": 1, "z-last": 2, "a-first": 3}},
		{`{"a-first":1,"default":1}`, map[string]int64{"default": 1, "a-first": 2}},
		{`{"a-first":1,"default":1,"z-last":1}`, map[string]int64{"default": 1, "a-first": 2, "z-last": 3}},
	}
	for _, change := range changes {
		require.NoError(t, model.UpdateOption("GroupRatio", change.value))
		mapping, err = model.GetDesktopGroupIDs()
		require.NoError(t, err)
		assert.Equal(t, change.want, mapping)
	}
	// Both native configuration entry points keep the same compatibility order.
	require.NoError(t, model.UpdateOptionsBulk(map[string]string{
		"group_ratio_setting.group_ratio": `{"default":1,"a-first":1,"z-last":1,"new":1}`,
		"SystemName":                      "preserved-test-name",
	}))
	mapping, err = model.GetDesktopGroupIDs()
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{"default": 1, "a-first": 2, "z-last": 3, "new": 4}, mapping)
	require.NoError(t, setting.UpdateUserUsableGroupsByJSONString(`{"default":"Default","a-first":"Allowed","auto":"Automatic"}`))
	ids, err = desktopAllowedGroupIDs("default")
	require.NoError(t, err)
	assert.Equal(t, []int64{1, 2}, ids, "only permitted real groups have IDs; auto is not a group")

	// Invalid configuration and attempted writes to private state must not
	// change the registry or the native configuration.
	before := maps.Clone(mapping)
	require.Error(t, model.UpdateOption("GroupRatio", "null"))
	require.Error(t, model.UpdateOption("GroupRatio", `{"":1}`))
	require.Error(t, model.UpdateOption("DesktopGroupRegistry", `[]`))
	require.Error(t, model.UpdateOptionsBulk(map[string]string{"DesktopGroupRegistry": `[]`}))
	mapping, err = model.GetDesktopGroupIDs()
	require.NoError(t, err)
	assert.Equal(t, before, mapping)
	// Updates must not mutate the caller's option map when mirroring aliases.
	updates := map[string]string{"GroupRatio": `{"default":1,"a-first":1,"z-last":1,"new":1}`}
	require.NoError(t, model.UpdateOptionsBulk(updates))
	assert.Len(t, updates, 1)
	// Force failure after registry reconciliation and prove transaction rollback.
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register("desktop-option-failure", func(tx *gorm.DB) {
		if option, ok := tx.Statement.Dest.(*model.Option); ok && option.Key == "ForcedFailure" {
			tx.AddError(fmt.Errorf("test option write failed"))
		}
	}))
	err = model.UpdateOptionsBulk(map[string]string{"GroupRatio": `{"default":1}`, "ForcedFailure": "test"})
	require.Error(t, err)
	require.NoError(t, db.Callback().Create().Remove("desktop-option-failure"))
	mapping, err = model.GetDesktopGroupIDs()
	require.NoError(t, err)
	assert.Equal(t, before, mapping)

	// Concurrent writes must publish a complete registry matching the winning
	// native config, not a mix of two writers or duplicate/lost positions.
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, value := range []string{`{"default":1,"left":1}`, `{"default":1,"right":1}`} {
		wait.Go(func() { results <- model.UpdateOption("GroupRatio", value) })
	}
	wait.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	var saved model.Option
	require.NoError(t, db.Where(&model.Option{Key: "GroupRatio"}).First(&saved).Error)
	var namespaced model.Option
	require.NoError(t, db.Where(&model.Option{Key: "group_ratio_setting.group_ratio"}).First(&namespaced).Error)
	assert.Equal(t, saved.Value, namespaced.Value, "aliases must not diverge across restart")
	var groups map[string]float64
	require.NoError(t, common.UnmarshalJsonStr(saved.Value, &groups))
	mapping, err = model.GetDesktopGroupIDs()
	require.NoError(t, err)
	require.Len(t, mapping, len(groups))
	assert.Equal(t, int64(1), mapping["default"])
	for name := range groups {
		assert.Contains(t, mapping, name)
	}

	// Corrupt private state is an explicit failure, never an empty successful
	// account or a guessed mapping. Restore it before checking persistence.
	registry := model.Option{Key: "DesktopGroupRegistry"}
	require.NoError(t, db.Where(&model.Option{Key: registry.Key}).First(&registry).Error)
	require.NoError(t, db.Model(&model.Option{}).Where(&model.Option{Key: registry.Key}).Update("value", `["default","default"]`).Error)
	_, err = model.GetDesktopGroupIDs()
	require.Error(t, err)
	me = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	request.Header.Set("Authorization", "Bearer "+browser.AccessToken)
	router.ServeHTTP(me, request)
	assert.Equal(t, http.StatusServiceUnavailable, me.Code)
	assert.NotContains(t, me.Body.String(), user.Username)
	require.NoError(t, db.Model(&model.Option{}).Where(&model.Option{Key: registry.Key}).Update("value", registry.Value).Error)

	// A new DB connection and repeated native migrations preserve the order,
	// old data and the option primary-key uniqueness guarantee.
	reopened, err := gorm.Open(dialector, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	reopenedSQL, err := reopened.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopenedSQL.Close() })
	model.DB = reopened
	for range 2 {
		require.NoError(t, reopened.AutoMigrate(&model.Option{}, &model.User{}, &model.UserSession{}, &model.AuthFlow{}))
		again, err := model.GetDesktopGroupIDs()
		require.NoError(t, err)
		assert.Equal(t, mapping, again)
	}
	saved = model.Option{}
	require.NoError(t, reopened.Where(&model.Option{Key: "SystemName"}).First(&saved).Error)
	assert.Equal(t, "preserved-test-name", saved.Value)
	var preserved model.User
	require.NoError(t, reopened.First(&preserved, user.Id).Error)
	assert.Equal(t, user.Username, preserved.Username)
	require.Error(t, reopened.Create(&model.Option{Key: "GroupRatio", Value: `{}`}).Error)
}
