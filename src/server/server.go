package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/go-querystring/query"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	authUrl  string = "https://accounts.google.com/o/oauth2/v2/auth"
	tokenUrl string = "https://www.googleapis.com/oauth2/v4/token"

	OAuthStateCookieName    string = "oauth_token"
	OAuthRedirectCookieName string = "oauth_redirect"
)

type TokenKind string

const (
	AuthTokenKind     TokenKind = "t"
	OAuthStateKind    TokenKind = "s"
	OAuthRedirectKind TokenKind = "r"
)

type Clock interface {
	Now() time.Time
}

type Database interface {
	Query(context.Context, string) error
}

type Server struct {
	AuthHeader     string
	ClientId       string
	ClientSecret   string
	Clock          Clock
	CookieDomain   string
	CookieDuration time.Duration
	CookieName     string
	CookieSecret   []byte
	Database       Database
	Debug          bool
	Domain         *url.URL
	HttpClient     *http.Client
}

type AuthToken struct {
	ExpiryTimestamp int64  `json:"exp"`
	Email           string `json:"email"`
	IssueTimestamp  int64  `json:"iss"`
}

type OAuthParams struct {
	ClientId     string `url:"client_id"`
	RedirectUri  string `url:"redirect_uri"`
	ResponseType string `url:"response_type"`
	Scope        string `url:"scope"`
	State        string `url:"state"`
}

type TokenParams struct {
	Code         string `url:"code"`
	ClientId     string `url:"client_id"`
	ClientSecret string `url:"client_secret"`
	GrantType    string `url:"grant_type"`
	RedirectUri  string `url:"redirect_uri"`
}

type TokenResponse struct {
	Error   string `json:"error"`
	IdToken string `json:"id_token"`
}

type UserToken struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Expiry        int64  `json:"exp"`
	IssuedAt      int64  `json:"iat"`
	Subject       string `json:"sub"`
}

func (server *Server) ServeHTTP(
	writer http.ResponseWriter, request *http.Request,
) {
	defer func() {
		err := recover()
		if err == nil {
			return
		}
		log.Println(err)
		debug.PrintStack()
		writer.WriteHeader(http.StatusInternalServerError)
		if server.Debug {
			fmt.Fprintf(writer, "%+v", err)
		}
	}()

	var err error
	switch request.URL.Path {
	case "/":
		err = server.root(writer, request)
	case "/callback":
		err = server.callback(writer, request)
	case "/login":
		err = server.login(writer, request)
	case "/logout":
		err = server.logout(writer, request)
	case "/status":
		return
	default:
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	if err != nil && server.Debug {
		writer.Write([]byte(err.Error()))
	}
}

func (server *Server) root(
	writer http.ResponseWriter, request *http.Request,
) error {
	authCookie, err := request.Cookie(server.CookieName)
	if err == http.ErrNoCookie {
		writer.WriteHeader(http.StatusUnauthorized)
		return nil
	}
	if err != nil {
		server.clearAuthCookie(writer)
		writer.WriteHeader(http.StatusInternalServerError)
		return err
	}

	authToken, err := Verify(AuthTokenKind, authCookie.Value, server.CookieSecret)
	if err != nil {
		server.clearAuthCookie(writer)
		writer.WriteHeader(http.StatusUnauthorized)
		return err
	}

	decodedAuthToken, err :=
		base64.RawURLEncoding.Strict().DecodeString(authToken)
	if err != nil {
		server.clearAuthCookie(writer)
		writer.WriteHeader(http.StatusUnauthorized)
		return err
	}

	parsedAuthToken := AuthToken{}
	err = json.Unmarshal(decodedAuthToken, &parsedAuthToken)
	if err != nil {
		server.clearAuthCookie(writer)
		writer.WriteHeader(http.StatusUnauthorized)
		return err
	}

	now := server.Clock.Now().UnixMilli()
	if now < parsedAuthToken.IssueTimestamp ||
		parsedAuthToken.ExpiryTimestamp < now {
		server.clearAuthCookie(writer)
		writer.WriteHeader(http.StatusUnauthorized)
		return errors.New("expired token")
	}

	writer.Header().Add(server.AuthHeader, parsedAuthToken.Email)
	return nil
}

func (server *Server) callback(
	writer http.ResponseWriter, request *http.Request,
) error {
	stateCookie, stateCookieErr := request.Cookie(OAuthStateCookieName)
	if stateCookieErr != http.ErrNoCookie {
		http.SetCookie(writer, &http.Cookie{
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
			Name:     OAuthStateCookieName,
			Secure:   true,
		})
	}

	redirectCookie, redirectCookieErr := request.Cookie(OAuthRedirectCookieName)
	if redirectCookieErr != http.ErrNoCookie {
		http.SetCookie(writer, &http.Cookie{
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
			Name:     OAuthRedirectCookieName,
			Secure:   true,
		})
	}

	if stateCookieErr == http.ErrNoCookie {
		writer.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("missing %s", OAuthStateCookieName)
	}
	if stateCookieErr != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return stateCookieErr
	}
	state, err := Verify(
		OAuthStateKind, stateCookie.Value, server.CookieSecret)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return err
	}

	if !request.URL.Query().Has("state") {
		writer.WriteHeader(http.StatusBadRequest)
		return errors.New("missing state")
	}
	if request.URL.Query().Get("state") != state {
		writer.WriteHeader(http.StatusBadRequest)
		return errors.New("incorrect state")
	}
	if !request.URL.Query().Has("code") {
		writer.WriteHeader(http.StatusBadRequest)
		return errors.New("missing code")
	}

	tokenParams, err := query.Values(&TokenParams{
		ClientId:     server.ClientId,
		ClientSecret: server.ClientSecret,
		Code:         request.URL.Query().Get("code"),
		GrantType:    "authorization_code",
		RedirectUri: fmt.Sprintf(
			"%s://%s/callback", server.Domain.Scheme, server.Domain.Host),
	})
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		if server.Debug {
			writer.Write([]byte(err.Error()))
		}
	}
	oAuthRequest, err :=
		http.NewRequest("POST", tokenUrl, strings.NewReader(tokenParams.Encode()))
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return err
	}
	oAuthRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := server.HttpClient.Do(oAuthRequest)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return err
	}
	defer response.Body.Close()

	responseData := TokenResponse{}
	err = json.NewDecoder(response.Body).Decode(&responseData)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return err
	}

	if responseData.Error != "" {
		writer.WriteHeader(http.StatusInternalServerError)
		return errors.New(responseData.Error)
	}

	splitData := strings.SplitN(responseData.IdToken, ".", 3)
	if len(splitData) != 3 {
		writer.WriteHeader(http.StatusInternalServerError)
		return errors.New("invalid token")
	}

	userTokenPayload, err := base64.RawURLEncoding.DecodeString(splitData[1])
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return err
	}

	userToken := UserToken{}
	err = json.Unmarshal(userTokenPayload, &userToken)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return err
	}

	now := server.Clock.Now().UTC().Unix()
	if now < userToken.IssuedAt || userToken.Expiry < now {
		writer.WriteHeader(http.StatusBadRequest)
		return errors.New("token expired")
	}

	err = server.Database.Query(context.Background(), userToken.Email)
	if err == mongo.ErrNoDocuments {
		writer.WriteHeader(http.StatusUnauthorized)
		return nil
	}
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return err
	}

	authToken, err := json.Marshal(&AuthToken{
		ExpiryTimestamp: time.Unix(userToken.IssuedAt, 0).
			Add(server.CookieDuration).UTC().UnixMilli(),
		Email:          userToken.Email,
		IssueTimestamp: time.Unix(userToken.IssuedAt, 0).UTC().UnixMilli(),
	})
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return err
	}

	encodedAuthToken := base64.RawURLEncoding.EncodeToString(authToken)
	authCookie, err := Sign(AuthTokenKind, encodedAuthToken, server.CookieSecret)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return err
	}

	http.SetCookie(writer, &http.Cookie{
		Domain:   server.CookieDomain,
		HttpOnly: true,
		Name:     server.CookieName,
		Secure:   true,
		Value:    authCookie,
		Expires:  time.Unix(userToken.IssuedAt, 0).Add(server.CookieDuration),
	})

	if redirectCookieErr == http.ErrNoCookie {
		return nil
	}
	if redirectCookieErr != nil {
		return err
	}

	redirectUri, err := Verify(
		OAuthRedirectKind, redirectCookie.Value, server.CookieSecret)
	if err != nil {
		return err
	}

	http.Redirect(writer, request, redirectUri, http.StatusFound)
	return nil
}

func (server *Server) login(
	writer http.ResponseWriter, request *http.Request,
) error {
	var token [32]byte
	_, err := rand.Read(token[:])
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return err
	}
	state := base64.RawURLEncoding.EncodeToString(token[:])
	signedState, err := Sign(OAuthStateKind, state, server.CookieSecret)
	if err != nil {
		return err
	}
	http.SetCookie(writer, &http.Cookie{
		HttpOnly: true,
		Name:     "oauth_token",
		Secure:   true,
		Value:    signedState,
	})

	requestQuery := request.URL.Query()
	if requestQuery.Has("rd") {
		redirect := requestQuery.Get("rd")
		signedRedirect, err := Sign("r", redirect, server.CookieSecret)
		if err != nil {
			return err
		}
		http.SetCookie(writer, &http.Cookie{
			HttpOnly: true,
			Name:     OAuthRedirectCookieName,
			Secure:   true,
			Value:    signedRedirect,
		})
	}

	oAuthParams, err := query.Values(OAuthParams{
		ClientId: server.ClientId,
		RedirectUri: fmt.Sprintf(
			"%s://%s/callback", server.Domain.Scheme, server.Domain.Host),
		ResponseType: "code",
		Scope:        "openid email",
		State:        state,
	})
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return err
	}
	url := fmt.Sprintf("%s?%s", authUrl, oAuthParams.Encode())
	http.Redirect(writer, request, url, http.StatusFound)
	return nil
}

func (server *Server) logout(
	writer http.ResponseWriter, request *http.Request,
) error {
	_, err := request.Cookie(server.CookieName)
	switch err {
	case nil:
		server.clearAuthCookie(writer)
	case http.ErrNoCookie:
		// Do nothing.
	default:
		writer.WriteHeader(http.StatusInternalServerError)
		return err
	}
	return nil
}

func (server *Server) clearAuthCookie(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{
		Domain:   server.CookieDomain,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Name:     server.CookieName,
		Secure:   true,
	})
}
