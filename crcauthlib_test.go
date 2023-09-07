package crcauthlib

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/redhatinsights/crcauthlib/deps"
	"github.com/stretchr/testify/assert"
)

var testUser = User{
	Username:      "billy",
	Password:      "password",
	ID:            "1234",
	Email:         "billy@billy.billy",
	FirstName:     "Billy",
	LastName:      "Bob",
	AccountNumber: "1",
	AddressString: "1",
	IsActive:      true,
	IsOrgAdmin:    true,
	IsInternal:    false,
	Locale:        "GB",
	OrgID:         "5432",
	DisplayName:   "Billy Bob",
	Type:          "User",
	Entitlements:  "",
}

type MockHTTP struct {
	logic func() (*http.Response, error)
}

func (m *MockHTTP) Do(req *http.Request) (*http.Response, error) {
	if m.logic != nil {
		return m.logic()
	}
	return nil, errors.New("sup")
}

func (m *MockHTTP) Get(url string) (*http.Response, error) {
	if m.logic != nil {
		return m.logic()
	}
	return nil, errors.New("sup")
}

func HTTPBodyIsKey() (*http.Response, error) {
	io, err := os.Open("test_files/public.pem")
	if err != nil {
		return nil, err
	}
	resp := http.Response{
		Body: io,
	}
	return &resp, nil
}

func MockHTTPResponseIsUserJSON() (*http.Response, error) {
	io, _ := os.Open("test_files/test_user.json")
	resp := http.Response{
		Body:       io,
		StatusCode: 200,
	}
	return &resp, nil
}

func MockHTTPResponseIsStatus400() (*http.Response, error) {
	io, _ := os.Open("test_files/test_user.json")
	resp := http.Response{
		StatusCode: 400,
		Body:       io,
	}
	return &resp, nil
}

func MockHTTPResponseCertGood() (*http.Response, error) {
	resp := http.Response{
		StatusCode: http.StatusOK,
	}
	return &resp, nil
}

func MockHTTPResponseCertNotGood() (*http.Response, error) {
	resp := http.Response{
		StatusCode: http.StatusForbidden,
	}
	return &resp, nil
}

func TestNewCRCAuthValidatorEmptyBopURLInvalidPEM(t *testing.T) {
	conf := ValidatorConfig{
		BOPUrl: "",
	}

	os.Setenv("JWTPEM", "sup")

	validator, err := NewCRCAuthValidator(&conf)
	assert.Nil(t, err)

	err = validator.grabVerify()
	assert.NotNil(t, err)
}

func TestNewCRCAuthValidatorEmptyBopURLValidPEM(t *testing.T) {
	conf := ValidatorConfig{
		BOPUrl: "",
	}

	keyData, _ := os.ReadFile("test_files/public.pem")

	os.Setenv("JWTPEM", string(keyData))

	_, err := NewCRCAuthValidator(&conf)

	assert.Nil(t, err)

}

func TestNewCRCAuthValidatorBopURLCantGetKey(t *testing.T) {
	conf := ValidatorConfig{
		BOPUrl: "jomo",
	}

	deps.HTTP = &MockHTTP{}

	validator, err := NewCRCAuthValidator(&conf)
	assert.Nil(t, err)

	err = validator.grabVerify()

	assert.NotNil(t, err)

}

func TestNewCRCAuthValidatorBopURLCanGetKey(t *testing.T) {
	conf := ValidatorConfig{
		BOPUrl: "jomo",
	}

	deps.HTTP = &MockHTTP{
		logic: HTTPBodyIsKey,
	}

	keyData, _ := os.ReadFile("test_files/public.pem")
	key := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", string(keyData))

	validator, err := NewCRCAuthValidator(&conf)
	validator.grabVerify()

	assert.Nil(t, err)
	assert.Equal(t, key, validator.pem)

}

func TestProcessRequestBasicAuthOK(t *testing.T) {
	deps.HTTP = &MockHTTP{
		logic: MockHTTPResponseIsUserJSON,
	}

	req, _ := http.NewRequest("GET", "", nil)
	req.SetBasicAuth(testUser.Username, testUser.Password)

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.Nil(t, errTwo)

	assert.Equal(t, "billy", ident.Identity.User.Username)
	assert.Equal(t, "basic-auth", ident.Identity.AuthType)
	assert.Equal(t, "5432", ident.Identity.OrgID)
}

func TestProcessRequestBasicAuthNotOK(t *testing.T) {
	deps.HTTP = &MockHTTP{
		logic: MockHTTPResponseIsStatus400,
	}

	req, _ := http.NewRequest("GET", "", nil)
	req.SetBasicAuth(testUser.Username, testUser.Password)

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.NotNil(t, errTwo)
	assert.Nil(t, ident)
}

func TestProcessRequestBadAuthType(t *testing.T) {
	deps.HTTP = &MockHTTP{
		logic: MockHTTPResponseIsStatus400,
	}

	req, _ := http.NewRequest("GET", "", nil)

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.NotNil(t, errTwo)
	assert.Nil(t, ident)
}

func TestProcessRequestBearerAuthJWTInvalid(t *testing.T) {
	deps.HTTP = &MockHTTP{
		logic: MockHTTPResponseIsStatus400,
	}

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Set("Authorization", "Bearer")

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.NotNil(t, errTwo)
	assert.Nil(t, ident)
}

func TestProcessRequestBearerAuthJWTValid(t *testing.T) {
	deps.HTTP = &MockHTTP{
		logic: MockHTTPResponseIsStatus400,
	}

	jwtData, _ := os.ReadFile("test_files/jwt.txt")
	jwt := string(jwtData)

	keyData, _ := os.ReadFile("test_files/public.pem")

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
	deps.HTTP = &MockHTTP{
		logic: MockHTTPResponseIsStatus400,
	}

	jwtData, _ := os.ReadFile("test_files/jwt.txt")
	jwt := string(jwtData)

	keyData, _ := os.ReadFile("test_files/public.pem")

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

func TestProcessRequestCertAuthOK(t *testing.T) {
	deps.HTTP = &MockHTTP{
		logic: MockHTTPResponseCertGood,
	}

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Add("x-rh-check-reg", "boop")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			Subject: pkix.Name{
				Organization: []string{"orgBoop"},
				CommonName:   "cnBoop",
			},
		}},
	}

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.Nil(t, errTwo)
	assert.Equal(t, "cnBoop", ident.Identity.System.CommonName)
	assert.Equal(t, "orgBoop", ident.Identity.OrgID)
	assert.Equal(t, "orgBoop", ident.Identity.Internal.OrgID)
}

func TestProcessRequestCertAuthNotOK(t *testing.T) {
	deps.HTTP = &MockHTTP{
		logic: MockHTTPResponseCertNotGood,
	}

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Add("x-rh-check-reg", "boop")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			Subject: pkix.Name{
				Organization: []string{"orgBoop"},
				CommonName:   "cnBoop",
			},
		}},
	}

	c, errOne := NewCRCAuthValidator(&ValidatorConfig{})

	ident, errTwo := c.ProcessRequest(req)

	assert.Nil(t, errOne)
	assert.NotNil(t, errTwo)
	assert.Nil(t, ident)
}
