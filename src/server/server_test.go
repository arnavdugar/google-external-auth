package server_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/arnavdugar/google-external-auth/server"

	"github.com/stretchr/testify/assert"
)

type MockClock struct {
	now time.Time
}

func (clock *MockClock) Now() time.Time {
	return clock.now
}

type MockDatabase struct {
	values map[string]error
}

func (db *MockDatabase) Query(context context.Context, email string) error {
	return db.values[email]
}

type MockTransport struct {
	Handler func(request *http.Request) (*http.Response, error)
}

func (transport *MockTransport) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	return transport.Handler(request)
}

func signedAuthToken(t *testing.T, token *server.AuthToken) string {
	serializedToken, err := json.Marshal(token)
	assert.NoError(t, err)
	encodedToken := base64.RawURLEncoding.EncodeToString(serializedToken)
	signedToken, err := server.Sign(server.AuthTokenKind, encodedToken, []byte{})
	assert.NoError(t, err)
	return signedToken
}

func TestRoot(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/", nil)
	request.AddCookie(&http.Cookie{
		Name: "auth_cookie",
		Value: signedAuthToken(t, &server.AuthToken{
			Email:           "user@example.com",
			ExpiryTimestamp: time.Unix(20001, 0).UnixMilli(),
			IssueTimestamp:  time.Unix(19999, 0).UnixMilli(),
		}),
	})

	server := server.Server{
		Clock:        &MockClock{now: time.Unix(20000, 0)},
		CookieName:   "auth_cookie",
		CookieSecret: []byte{},
		Debug:        true,
	}
	server.ServeHTTP(recorder, request)
	response := recorder.Result()
	body, err := io.ReadAll(response.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "", string(body))
}

func TestRootUnauthorized(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/", nil)

	server := server.Server{
		CookieName: "auth_cookie",
	}
	server.ServeHTTP(recorder, request)
	response := recorder.Result()

	assert.Equal(t, response.StatusCode, http.StatusUnauthorized)
}

func TestRootInvalidSignature(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/", nil)
	request.AddCookie(&http.Cookie{
		Name:  "auth_cookie",
		Value: fmt.Sprintf("%043d%s", 0, "invalid-cookie"),
	})

	server := server.Server{
		CookieName:   "auth_cookie",
		CookieSecret: []byte{},
		Debug:        true,
		Domain: &url.URL{
			Scheme: "https",
			Host:   "auth.example.com",
		},
	}
	server.ServeHTTP(recorder, request)
	response := recorder.Result()
	body, err := io.ReadAll(response.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
	assert.Equal(t, "signature failed", string(body))
	assert.Len(t, response.Cookies(), 1)
	authCookie := response.Cookies()[0]
	assert.Equal(t, time.Unix(0, 0).UTC(), authCookie.Expires)
	assert.True(t, authCookie.HttpOnly)
	assert.Equal(t, "auth_cookie", authCookie.Name)
	assert.True(t, authCookie.Secure)
}

func TestRootBadCookieBase64(t *testing.T) {
	recorder := httptest.NewRecorder()
	signedCookie, err := server.Sign(
		server.AuthTokenKind, "invalid-cookie", []byte{})
	assert.NoError(t, err)
	request := httptest.NewRequest("GET", "/", nil)
	request.AddCookie(&http.Cookie{
		Name:  "auth_cookie",
		Value: signedCookie,
	})

	server := server.Server{
		CookieName:   "auth_cookie",
		CookieSecret: []byte{},
		Debug:        true,
		Domain: &url.URL{
			Scheme: "https",
			Host:   "auth.example.com",
		},
	}
	server.ServeHTTP(recorder, request)
	response := recorder.Result()
	body, err := io.ReadAll(response.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
	assert.Equal(t, "illegal base64 data at input byte 12", string(body))
	assert.Len(t, response.Cookies(), 1)
	authCookie := response.Cookies()[0]
	assert.Equal(t, time.Unix(0, 0).UTC(), authCookie.Expires)
	assert.True(t, authCookie.HttpOnly)
	assert.Equal(t, "auth_cookie", authCookie.Name)
	assert.True(t, authCookie.Secure)
}

func TestRootExpiredCookie(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/", nil)
	request.AddCookie(&http.Cookie{
		Name: "auth_cookie",
		Value: signedAuthToken(t, &server.AuthToken{
			Email:           "user@example.com",
			ExpiryTimestamp: time.Unix(20001, 0).UnixMilli(),
			IssueTimestamp:  time.Unix(19999, 0).UnixMilli(),
		}),
	})

	server := server.Server{
		Clock:        &MockClock{now: time.Unix(30000, 0)},
		CookieName:   "auth_cookie",
		CookieSecret: []byte{},
		Debug:        true,
		Domain: &url.URL{
			Scheme: "https",
			Host:   "auth.example.com",
		},
	}
	server.ServeHTTP(recorder, request)
	response := recorder.Result()
	body, err := io.ReadAll(response.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
	assert.Equal(t, "expired token", string(body))
	assert.Len(t, response.Cookies(), 1)
	authCookie := response.Cookies()[0]
	assert.Equal(t, time.Unix(0, 0).UTC(), authCookie.Expires)
	assert.True(t, authCookie.HttpOnly)
	assert.Equal(t, "auth_cookie", authCookie.Name)
	assert.True(t, authCookie.Secure)
}

func TestLogin(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/login", nil)

	authServer := server.Server{
		ClientId:   "client-id",
		CookieName: "auth_cookie",
		Debug:      true,
		Domain: &url.URL{
			Scheme: "https",
			Host:   "auth.example.com",
		},
	}
	authServer.ServeHTTP(recorder, request)
	response := recorder.Result()

	assert.Equal(t, http.StatusFound, response.StatusCode)
	redirectUrl, err := url.Parse(response.Header.Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, "https", redirectUrl.Scheme)
	assert.Equal(t, "accounts.google.com", redirectUrl.Host)
	assert.Equal(t, "/o/oauth2/v2/auth", redirectUrl.Path)
	assert.Equal(t, "client-id", redirectUrl.Query().Get("client_id"))
	assert.Equal(t, "https://auth.example.com/callback",
		redirectUrl.Query().Get("redirect_uri"))
	assert.Equal(t, "code", redirectUrl.Query().Get("response_type"))
	assert.Equal(t, "openid email", redirectUrl.Query().Get("scope"))

	assert.Len(t, response.Cookies(), 1)
	tokenCookie := response.Cookies()[0]
	assert.True(t, tokenCookie.HttpOnly)
	assert.Equal(t, server.OAuthStateCookieName, tokenCookie.Name)
	assert.True(t, tokenCookie.Secure)
	oAuthState, err := server.Verify(
		server.OAuthStateKind, tokenCookie.Value, []byte{})
	assert.NoError(t, err)
	assert.Equal(t, oAuthState, redirectUrl.Query().Get("state"))
}

func TestLoginWithRedirect(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/login?rd=https://example.com/", nil)

	authServer := server.Server{
		ClientId:   "client-id",
		CookieName: "auth_cookie",
		Debug:      true,
		Domain: &url.URL{
			Scheme: "https",
			Host:   "auth.example.com",
		},
	}
	authServer.ServeHTTP(recorder, request)
	response := recorder.Result()

	assert.Len(t, response.Cookies(), 2)
	var redirectCookie *http.Cookie
	for _, cookie := range response.Cookies() {
		if cookie.Name == server.OAuthRedirectCookieName {
			redirectCookie = cookie
			break
		}
	}
	assert.NotNil(t, redirectCookie)
	assert.True(t, redirectCookie.HttpOnly)
	assert.True(t, redirectCookie.Secure)
	redirectUri, err := server.Verify(
		server.OAuthRedirectKind, redirectCookie.Value, []byte{})
	assert.NoError(t, err)
	assert.Equal(t, "https://example.com/", redirectUri)
}

func TestCallback(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		"GET", "/callback?state=oauth-state&code=code", nil)
	signedToken, err := server.Sign(
		server.OAuthStateKind, "oauth-state", []byte{})
	assert.NoError(t, err)
	request.AddCookie(&http.Cookie{
		Name:  server.OAuthStateCookieName,
		Value: signedToken,
	})

	server := server.Server{
		Clock: &MockClock{now: time.Unix(20000, 0)},
		Database: &MockDatabase{
			values: map[string]error{
				"user@example.com": nil,
			},
		},
		Debug: true,
		Domain: &url.URL{
			Scheme: "https",
			Host:   "auth.example.com",
		},
		HttpClient: &http.Client{
			Transport: &MockTransport{
				Handler: func(request *http.Request) (*http.Response, error) {
					assert.Equal(t, "https://www.googleapis.com/oauth2/v4/token",
						request.URL.String())
					assert.Equal(t, "application/x-www-form-urlencoded",
						request.Header.Get("Content-Type"))
					responseBody, err := json.Marshal(server.TokenResponse{
						IdToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjMwMDAwLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJpc3MiOjEwMDAwfQ.sVN9RbyIZpV4THlNYq-1ftgFcw-GGP1cYUwTuSmueYE",
					})
					assert.NoError(t, err)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(responseBody)),
					}, nil
				},
			},
		},
	}
	server.ServeHTTP(recorder, request)
	response := recorder.Result()
	body, err := io.ReadAll(response.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "", string(body))
}

func TestCallbackWithIncorrectOAuthState(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		"GET", "/callback?state=oauth-state&code=code", nil)
	signedToken, err := server.Sign(
		server.OAuthStateKind, "incorrect-oauth-state", []byte{})
	assert.NoError(t, err)
	request.AddCookie(&http.Cookie{
		Name:  server.OAuthStateCookieName,
		Value: signedToken,
	})

	server := server.Server{
		Debug: true,
	}
	server.ServeHTTP(recorder, request)
	response := recorder.Result()
	body, err := io.ReadAll(response.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	assert.Equal(t, "incorrect state", string(body))
}

func TestCallbackWithInvalidOAuthState(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		"GET", "/callback?state=oauth-state&code=code", nil)
	request.AddCookie(&http.Cookie{
		Name:  server.OAuthStateCookieName,
		Value: "invalid-oauth-state",
	})

	server := server.Server{
		CookieName: "auth_cookie",
		Debug:      true,
	}
	server.ServeHTTP(recorder, request)
	response := recorder.Result()
	body, err := io.ReadAll(response.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	assert.Equal(t, "signature failed", string(body))
}

func TestCallbackWithoutOAuthState(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		"GET", "/callback?state=oauth-state&code=code", nil)

	authServer := server.Server{
		CookieName: "auth_cookie",
		Debug:      true,
	}
	authServer.ServeHTTP(recorder, request)
	response := recorder.Result()
	body, err := io.ReadAll(response.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	assert.Equal(
		t, fmt.Sprintf("missing %s", server.OAuthStateCookieName), string(body))
}

func TestLogout(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/logout", nil)
	request.AddCookie(&http.Cookie{
		Name:  "auth_cookie",
		Value: "auth-token",
	})

	server := server.Server{
		CookieName: "auth_cookie",
		Debug:      true,
		Domain: &url.URL{
			Scheme: "https",
			Host:   "auth.example.com",
		},
	}
	server.ServeHTTP(recorder, request)
	response := recorder.Result()

	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Len(t, response.Cookies(), 1)
	authCookie := response.Cookies()[0]
	assert.Equal(t, time.Unix(0, 0).UTC(), authCookie.Expires)
	assert.True(t, authCookie.HttpOnly)
	assert.Equal(t, "auth_cookie", authCookie.Name)
	assert.True(t, authCookie.Secure)
}

func TestLogoutWithoutCookie(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/logout", nil)

	authServer := server.Server{
		CookieName: "auth_cookie",
		Debug:      true,
	}
	authServer.ServeHTTP(recorder, request)
	response := recorder.Result()

	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Len(t, response.Cookies(), 0)
}
