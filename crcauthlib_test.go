package crcauthlib

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"github.com/redhatinsights/crcauthlib/deps"
	"github.com/stretchr/testify/assert"
)

var testUser = User{
	Username:      "billy",
	Password:      "password",
	ID:            1234,
	Email:         "billy@billy.billy",
	FirstName:     "Billy",
	LastName:      "Bob",
	AccountNumber: "1",
	AddressString: "1",
	IsActive:      true,
	IsOrgAdmin:    true,
	IsInternal:    false,
	Locale:        "GB",
	OrgID:         5432,
	DisplayName:   "Billy Bob",
	Type:          "User",
	Entitlements:  "",
}

type MockHTTPAllErrors struct {
}

func (m *MockHTTPAllErrors) Do(req *http.Request) (*http.Response, error) {
	return nil, errors.New("Sup")
}
func (m *MockHTTPAllErrors) Get(url string) (*http.Response, error) {
	return nil, errors.New("Sup")
}

type MockHTTPBodyIsKey struct {
}

func (m *MockHTTPBodyIsKey) mockResp() *http.Response {
	io, _ := os.Open("test_files/public.pem")
	resp := http.Response{
		Body: io,
	}
	return &resp
}

func (m *MockHTTPBodyIsKey) Do(req *http.Request) (*http.Response, error) {
	return m.mockResp(), nil
}
func (m *MockHTTPBodyIsKey) Get(url string) (*http.Response, error) {
	return m.mockResp(), nil
}

type MockHTTPResponseIsUserJSON struct {
}

func (m *MockHTTPResponseIsUserJSON) mockResp() *http.Response {
	io, _ := os.Open("test_files/test_user.json")
	resp := http.Response{
		Body:       io,
		StatusCode: 200,
	}
	return &resp
}
func (m *MockHTTPResponseIsUserJSON) Do(req *http.Request) (*http.Response, error) {
	return m.mockResp(), nil
}
func (m *MockHTTPResponseIsUserJSON) Get(url string) (*http.Response, error) {
	return m.mockResp(), nil
}

type MockHTTPResponseStatusCode400 struct {
}

func (m *MockHTTPResponseStatusCode400) mockResp() *http.Response {
	io, _ := os.Open("test_files/test_user.json")
	resp := http.Response{
		StatusCode: 400,
		Body:       io,
	}
	return &resp
}
func (m *MockHTTPResponseStatusCode400) Do(req *http.Request) (*http.Response, error) {
	return m.mockResp(), nil
}
func (m *MockHTTPResponseStatusCode400) Get(url string) (*http.Response, error) {
	return m.mockResp(), nil
}

func TestNewCRCAuthValidatorEmptyBopURLInvalidPEM(t *testing.T) {
	conf := ValidatorConfig{
		BOPUrl: "",
	}

	os.Setenv("JWTPEM", "sup")

	_, err := NewCRCAuthValidator(&conf)

	assert.NotNil(t, err)

}

func TestNewCRCAuthValidatorEmptyBopURLValidPEM(t *testing.T) {
	conf := ValidatorConfig{
		BOPUrl: "",
	}

	keyData, _ := ioutil.ReadFile("test_files/public.pem")

	os.Setenv("JWTPEM", string(keyData))

	_, err := NewCRCAuthValidator(&conf)

	assert.Nil(t, err)

}

func TestNewCRCAuthValidatorBopURLCantGetKey(t *testing.T) {
	conf := ValidatorConfig{
		BOPUrl: "jomo",
	}

	deps.HTTP = &MockHTTPAllErrors{}

	_, err := NewCRCAuthValidator(&conf)

	assert.NotNil(t, err)

}

func TestNewCRCAuthValidatorBopURLCanGetKey(t *testing.T) {
	conf := ValidatorConfig{
		BOPUrl: "jomo",
	}

	deps.HTTP = &MockHTTPBodyIsKey{}

	keyData, _ := ioutil.ReadFile("test_files/public.pem")
	key := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", string(keyData))

	validator, err := NewCRCAuthValidator(&conf)

	assert.Nil(t, err)
	assert.Equal(t, key, validator.pem)

}

func TestProcessRequestBasicAuthOK(t *testing.T) {
	deps.HTTP = &MockHTTPResponseIsUserJSON{}

	req, _ := http.NewRequest("GET", "", nil)
	req.SetBasicAuth(testUser.Username, testUser.Password)

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.Nil(t, errTwo)

	assert.Equal(t, "billy", ident.Identity.User.Username)
	assert.Equal(t, "basic-auth", ident.Identity.AuthType)

}

func TestProcessRequestBasicAuthNotOK(t *testing.T) {
	deps.HTTP = &MockHTTPResponseStatusCode400{}

	req, _ := http.NewRequest("GET", "", nil)
	req.SetBasicAuth(testUser.Username, testUser.Password)

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.NotNil(t, errTwo)
	assert.Nil(t, ident)
}

func TestProcessRequestBadAuthType(t *testing.T) {
	deps.HTTP = &MockHTTPResponseStatusCode400{}

	req, _ := http.NewRequest("GET", "", nil)

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.NotNil(t, errTwo)
	assert.Nil(t, ident)
}

func TestProcessRequestBearerAuthJWTInvalid(t *testing.T) {
	deps.HTTP = &MockHTTPResponseStatusCode400{}

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Set("Authorization", "Bearer")

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.NotNil(t, errTwo)
	assert.Nil(t, ident)
}

func TestProcessRequestBearerAuthJWTValid(t *testing.T) {
	deps.HTTP = &MockHTTPResponseStatusCode400{}

	jwtData, _ := ioutil.ReadFile("test_files/jwt.txt")
	jwt := string(jwtData)

	keyData, _ := ioutil.ReadFile("test_files/public.pem")

	os.Setenv("JWTPEM", string(keyData))

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.Nil(t, errTwo)
	assert.NotNil(t, ident)
}

func TestProcessCookieAuthJWTValid(t *testing.T) {
	deps.HTTP = &MockHTTPResponseStatusCode400{}

	jwtData, _ := ioutil.ReadFile("test_files/jwt.txt")
	jwt := string(jwtData)

	keyData, _ := ioutil.ReadFile("test_files/public.pem")

	os.Setenv("JWTPEM", string(keyData))

	oreo := http.Cookie{}
	oreo.Name = "cs_jwt"
	oreo.Value = jwt

	req, _ := http.NewRequest("GET", "", nil)
	req.AddCookie(&oreo)

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.Nil(t, errTwo)
	assert.NotNil(t, ident)
}

/*



func TestProcessRequestJWTAuth(t *testing.T) {
	deps.HTTP = &MockHTTPResponseStatusCode400{}

	req, _ := http.NewRequest("GET", "", nil)

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.NotNil(t, errTwo)
	assert.Nil(t, ident)
}

/*
func TestBasicAuthSuccess(t *testing.T) {
	keyData, _ := ioutil.ReadFile("public.pem")
	//key, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)

	userData, err := json.Marshal(Resp{User: testUser, Mechanism: "Basic"})
	if err != nil {
		t.Error("cannot create user object")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/jwt" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(keyData))
		} else if r.URL.Path == "/v1/auth" {
			user, pass, ok := r.BasicAuth()
			if ok && (user != testUser.Username || pass != testUser.Password) {
				w.WriteHeader(http.StatusForbidden)
			}
			w.WriteHeader(http.StatusOK)
			w.Write(userData)
			w.Header().Set("Content-Type", "application/json")
		} else {
			w.WriteHeader(http.StatusBadRequest)
			t.Errorf("Expected to request '/v1/auth', got: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	validator, err := NewCRCAuthValidator(&ValidatorConfig{
		BOPUrl: server.URL,
	})

	if err != nil {
		t.Errorf("error in request: %s", err)
	}

	xrhid, err := validator.processBasicAuth("billy", "password")
	if err != nil {
		t.Errorf("error in request: %s", err)
	}

	if xrhid.Identity.User.Username != "billy" {
		t.Errorf("error in request: %s", err)
	}

}

func TestJWTSuccess(t *testing.T) {
	keyData, _ := ioutil.ReadFile("public.pem")
	privateKeyData, _ := ioutil.ReadFile("private.pem")
	key, _ := jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/jwt" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(keyData))
		} else {
			w.WriteHeader(http.StatusBadRequest)
			t.Errorf("Expected to request '/v1/auth', got: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	validator, err := NewCRCAuthValidator(&ValidatorConfig{
		BOPUrl: server.URL,
	})

	if err != nil {
		t.Errorf("error in request: %s", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"account_number":     "1234",
		"is_internal":        true,
		"is_active":          true,
		"last_name":          "Bill",
		"preferred_username": "bobby",
		"type":               "User",
		"locale":             "en_US",
		"is_org_admin":       false,
		"account_id":         "5432",
		"user_id":            "5432",
		"org_id":             "7890",
		"first_name":         "Bobby",
		"email":              "bobby@bobby.bobby",
		"username":           "bobby",
		"entitlements":       "{}",
	})

	string, err := token.SignedString(key)
	if err != nil {
		t.Errorf("failed to sign: %s", err)
	}

	xrhid, err := validator.processJWTToken(string)
	if err != nil {
		t.Errorf("error in request: %s", err)
	}

	if xrhid.Identity.User.Username != "bobby" {
		t.Errorf("error in request: %s", err)
	}

}
*/
