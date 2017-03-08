// Package passhub implements the OAuth2 protocol for authenticating users through passhub.org.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.

package passhub

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"

	"github.com/markbates/goth"
)

const (
	authURL         string = "http://passhub.org/api/v1/oauth/access"
	tokenURL        string = "http://passhub.org/api/v1/oauth/access_token"
	endpointProfile string = "http://passhub.org/api/v1/user/me?fields=email,first_name,last_name,link,about,id,name,picture,location"
)

// New creates a new PassHub provider, and sets up important connection details.
// You should always call `passhub.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "passhub",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Passhub.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client http
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the passhub package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks PassHub for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	var (
		url     = p.config.AuthCodeURL(state)
		session = &Session{AuthURL: url}
	)
	return session, nil
}

// FetchUser will go to Facebook and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	var (
		sess = session.(*Session)
		user = goth.User{
			AccessToken: sess.AccessToken,
			Provider:    p.Name(),
			ExpiresAt:   sess.ExpiresAt,
		}
		response, err = p.Client().Get(endpointProfile + "&access_token=" + url.QueryEscape(sess.AccessToken))
	)

	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	bits, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)
	return user, err
}

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		About     string `json:"about"`
		Name      string `json:"name"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Link      string `json:"link"`
		Picture   struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
		Location struct {
			Name string `json:"name"`
		} `json:"location"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.Name
	user.FirstName = u.FirstName
	user.LastName = u.LastName
	user.NickName = u.Name
	user.Email = u.Email
	user.Description = u.About
	user.AvatarURL = u.Picture.Data.URL
	user.UserID = u.ID
	user.Location = u.Location.Name

	return err
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{
			"email",
		},
	}

	defaultScopes := map[string]struct{}{
		"email": {},
	}

	for _, scope := range scopes {
		if _, exists := defaultScopes[scope]; !exists {
			c.Scopes = append(c.Scopes, scope)
		}
	}

	return c
}

// RefreshToken refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by passhub")
}

// RefreshTokenAvailable refresh token
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
