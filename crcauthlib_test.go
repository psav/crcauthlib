package crcauthlib

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt"
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
