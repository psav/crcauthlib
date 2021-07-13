package crcauthlib

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/golang-jwt/jwt/request"
	"github.com/redhatinsights/platform-go-middlewares/identity"
)

type User struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	ID            int    `json:"id"`
	Email         string `json:"email"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	AccountNumber string `json:"account_number"`
	AddressString string `json:"address_string"`
	IsActive      bool   `json:"is_active"`
	IsOrgAdmin    bool   `json:"is_org_admin"`
	IsInternal    bool   `json:"is_internal"`
	Locale        string `json:"locale"`
	OrgID         int    `json:"org_id"`
	DisplayName   string `json:"display_name"`
	Type          string `json:"type"`
}

type Resp struct {
	User      User   `json:"user"`
	Mechanism string `json:"mechanism"`
}

type Entitlement struct {
	IsTrial   bool `json:"is_trial"`
	IsEnabled bool `json:"is_enabled"`
}

type XRHID struct {
	Identity     identity.Identity      `json:"identity,omitempty"`
	Entitlements map[string]Entitlement `json:"entitlements,omitempty"`
}

type CRCAuthValidator struct {
	config    *ValidatorConfig
	pem       string
	verifyKey *rsa.PublicKey
}

type ValidatorConfig struct {
	BOPUrl string `json:"bopurl,omitempty"`
}

func NewCRCAuthValidator(config *ValidatorConfig) (*CRCAuthValidator, error) {
	validator := &CRCAuthValidator{config: config}
	if config.BOPUrl != "" {
		resp, err := http.Get(fmt.Sprintf("%s/v1/jwt", config.BOPUrl))
		if err != nil {
			return nil, fmt.Errorf("could not obtain key: %s", err.Error())
		}
		key, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("could not read key body: %s", err.Error())
		}
		validator.pem = fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", key)
		fmt.Printf("PEM Read Successfully\n")
	} else {
		validator.pem = os.Getenv("JWTPEM")
	}

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(validator.pem))
	if err != nil {
		fmt.Println("couldn't verify cert" + err.Error())
		return nil, err
	} else {
		validator.verifyKey = verifyKey
		fmt.Printf("PEM Verified Successfully\n")
	}

	return validator, nil
}

func (crc *CRCAuthValidator) ProcessRequest(r *http.Request) (*XRHID, error) {
	if user, pass, ok := r.BasicAuth(); ok {
		fmt.Printf("\n\nCHOSEN BASIC\n\n")
		return crc.processBasicAuth(user, pass)
	} else if strings.Contains(r.Header.Get("Authorization"), "Bearer") {
		fmt.Printf("\n\nCHOSEN Bearer\n\n")
		return crc.processJWTHeaderRequest(r)
	} else if _, err := r.Cookie("cs_jwt"); err == nil {
		fmt.Printf("\n\nCHOSEN Cookie\n\n")
		return crc.processJWTCookieRequest(r)
	} else {
		fmt.Printf("\n\nCHOSEN BAD\n\n")
		return nil, fmt.Errorf("bad auth type")
	}
}

func (crc *CRCAuthValidator) processBasicAuth(user string, password string) (*XRHID, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/auth", crc.config.BOPUrl), nil)
	req.SetBasicAuth(user, password)
	if err != nil {
		return nil, fmt.Errorf("could not create request: %s", err.Error())
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bad request: %s", err.Error())
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("bad request: %s", err.Error())
	}
	respData := &Resp{}
	if resp.StatusCode == 200 {
		err := json.Unmarshal(data, respData)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling json: %s", err.Error())
		}

		OrgId := strconv.Itoa(respData.User.OrgID)

		ident := &XRHID{
			Identity: identity.Identity{
				AccountNumber: respData.User.AccountNumber,
				Internal: identity.Internal{
					OrgID: OrgId,
				},
				User: identity.User{
					Username:  respData.User.Username,
					Email:     respData.User.Email,
					FirstName: respData.User.FirstName,
					LastName:  respData.User.LastName,
					Active:    respData.User.IsActive,
					OrgAdmin:  respData.User.IsOrgAdmin,
					Internal:  respData.User.IsInternal,
					Locale:    respData.User.Locale,
				},
				Type: respData.User.Type,
			},
			Entitlements: map[string]Entitlement{},
		}
		fmt.Printf("%v", *ident)
		return ident, nil
	} else {
		return nil, fmt.Errorf("could not verify credentials")
	}
	return nil, nil
}

func (crc *CRCAuthValidator) ProcessToken(tokenString string) (*XRHID, error) {
	identity, err := crc.processJWTToken(tokenString)

	if err != nil {
		return nil, err
	}
	return identity, nil
}

func (crc *CRCAuthValidator) processJWTCookieRequest(r *http.Request) (*XRHID, error) {
	token, err := crc.ValidateJWTCookieRequest(r)

	if err != nil {
		return nil, err
	}

	return crc.buildIdent(token)
}

func (crc *CRCAuthValidator) processJWTHeaderRequest(r *http.Request) (*XRHID, error) {
	token, err := crc.ValidateJWTHeaderRequest(r)

	if err != nil {
		return nil, err
	}

	return crc.buildIdent(token)
}

func (crc *CRCAuthValidator) processJWTToken(tokenString string) (*XRHID, error) {
	token, err := crc.ValidateJWTToken(tokenString)

	if err != nil {
		return nil, err
	}

	return crc.buildIdent(token)
}

func (crc *CRCAuthValidator) buildIdent(token *jwt.Token) (*XRHID, error) {
	var ident XRHID
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

		username, ok := claims["preferred_username"].(string)
		if !ok {
			return nil, fmt.Errorf("username not good")
		}

		ident = XRHID{
			Identity: identity.Identity{
				AccountNumber: "540155",
				Internal: identity.Internal{
					OrgID: "abcd",
				},
				User: identity.User{
					Username: username,
				},
				Type: "User",
			},
			Entitlements: map[string]Entitlement{
				"insights": {
					IsTrial:   false,
					IsEnabled: true,
				},
			},
		}
	}

	return &ident, nil
}

func (crc *CRCAuthValidator) ValidateJWTToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			fmt.Println("unexpected signing method")
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return crc.verifyKey, nil
	})

	if err != nil {
		fmt.Println("couldn't validate jwt tokenstring", err.Error())
		return nil, err
	}

	return token, nil
}

func (crc *CRCAuthValidator) ValidateJWTCookieRequest(r *http.Request) (*jwt.Token, error) {
	jwtToken, err := r.Cookie("cs_jwt")

	if err != nil {
		return nil, err
	}

	token, err := crc.ValidateJWTToken(jwtToken.Value)

	if err != nil {
		fmt.Println("couldn't validate jwt cookie", err.Error())
		return nil, err
	}

	return token, nil
}

func (crc *CRCAuthValidator) ValidateJWTHeaderRequest(r *http.Request) (*jwt.Token, error) {
	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			fmt.Println("unexpected signing method")
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return crc.verifyKey, nil
	})

	if err != nil {
		fmt.Println("couldn't validate jwt header", err.Error())
		return nil, err
	}

	return token, nil
}