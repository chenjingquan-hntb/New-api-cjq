package service

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDesktopPKCEAndInputValidation(t *testing.T) {
	verifier := strings.Repeat("a", 43)
	challenge := DesktopCodeChallenge(verifier)
	require.Len(t, challenge, 43)
	assert.True(t, ValidateDesktopCodeChallenge("S256", challenge))
	assert.False(t, ValidateDesktopCodeChallenge("plain", challenge))
	assert.False(t, ValidateDesktopCodeChallenge("S256", challenge+"a"))
	assert.True(t, ValidateDesktopCodeVerifier(verifier))
	assert.False(t, ValidateDesktopCodeVerifier(strings.Repeat("a", 42)))
	assert.False(t, ValidateDesktopCodeVerifier(strings.Repeat("a", 43)+" "))
}

func TestNormalizeDesktopCode(t *testing.T) {
	code, ok := NormalizeDesktopCode(" abcd-12 ef ")
	require.True(t, ok)
	assert.Equal(t, "ABCD12EF", code)
	_, ok = NormalizeDesktopCode("short")
	assert.False(t, ok)
	_, ok = NormalizeDesktopCode("ABC_123")
	assert.False(t, ok)
}

func TestDesktopEndpointAndRedirectValidation(t *testing.T) {
	endpoint, err := ValidateDesktopEndpoint("HTTPS://Example.COM:443/")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com:443", endpoint)
	_, err = ValidateDesktopEndpoint("https://user:pass@example.com")
	assert.Error(t, err)
	_, err = ValidateDesktopEndpoint("https://example.com/path")
	assert.Error(t, err)

	redirect, err := ValidateDesktopRedirect("http://127.0.0.1:43127/callback")
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:43127/callback", redirect)
	_, err = ValidateDesktopRedirect("http://localhost:43127/callback")
	assert.Error(t, err)
	_, err = ValidateDesktopRedirect("http://127.0.0.1:43127/callback?code=bad")
	assert.Error(t, err)
}

func TestDesktopAuthFlowCreatesIndependentOneTimeSession(t *testing.T) {
	user := setupAuthSessionTestDB(t)
	verifier := strings.Repeat("v", 64)
	challenge := DesktopCodeChallenge(verifier)
	bridgeToken, err := CreateDesktopBridgeFlow("https://example.com", challenge, "http://127.0.0.1:43127/callback")
	require.NoError(t, err)
	browserBundle, err := CreateLoginSession(user.Id, "password", "127.0.0.1", "browser")
	require.NoError(t, err)
	browserIdentity, err := ParseAccessToken(browserBundle.AccessToken)
	require.NoError(t, err)
	result, err := CompleteDesktopBridgeFlow(bridgeToken, browserIdentity)
	require.NoError(t, err)
	require.NotEmpty(t, result.Code)
	desktopSession, err := ExchangeDesktopCode(result.Code, verifier, "127.0.0.1", "desktop")
	require.NoError(t, err)
	require.NotEmpty(t, desktopSession.AccessToken)
	require.NotEmpty(t, desktopSession.RefreshToken)
	assert.Positive(t, desktopSession.ExpiresIn)
	desktopIdentity, err := ParseAccessToken(desktopSession.AccessToken)
	require.NoError(t, err)
	assert.NotEqual(t, browserIdentity.SessionID, desktopIdentity.SessionID)
	_, err = ExchangeDesktopCode(result.Code, verifier, "127.0.0.1", "desktop")
	require.Error(t, err)
	refreshed, _, err := RefreshLoginSession(desktopSession.RefreshToken, "", "127.0.0.1", "desktop")
	require.NoError(t, err)
	require.NotEmpty(t, refreshed.RefreshToken)
	require.NoError(t, RevokeByRefreshToken(refreshed.RefreshToken, "", "logout"))
	_, _, err = RefreshLoginSession(refreshed.RefreshToken, "", "127.0.0.1", "desktop")
	require.Error(t, err)
}

func TestDesktopAuthCodeConcurrentExchangeIsSingleUse(t *testing.T) {
	user := setupAuthSessionTestDB(t)
	verifier := strings.Repeat("c", 64)
	bridgeToken, err := CreateDesktopBridgeFlow("https://example.com", DesktopCodeChallenge(verifier), "")
	require.NoError(t, err)
	browserBundle, err := CreateLoginSession(user.Id, "password", "127.0.0.1", "browser")
	require.NoError(t, err)
	browserIdentity, err := ParseAccessToken(browserBundle.AccessToken)
	require.NoError(t, err)
	result, err := CompleteDesktopBridgeFlow(bridgeToken, browserIdentity)
	require.NoError(t, err)

	results := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for range 2 {
		waitGroup.Go(func() {
			_, exchangeErr := ExchangeDesktopCode(result.Code, verifier, "127.0.0.1", "desktop")
			results <- exchangeErr
		})
	}
	waitGroup.Wait()
	close(results)

	successes := 0
	for exchangeErr := range results {
		if exchangeErr == nil {
			successes++
		}
	}
	assert.Equal(t, 1, successes)
}
