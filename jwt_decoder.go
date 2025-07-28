package oidc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

type JWT struct {
	Header    map[string]interface{} `json:"header"`
	Payload   JWTPayload             `json:"payload"`
	Signature string                 `json:"signature"`
}

type JWTPayload struct {
       Aud                audList                `json:"aud"`
       Sub                string                 `json:"sub"`
       Scope              []string               `json:"scp"`
       ClientID           string                 `json:"client_id"`
       Exp                int64                  `json:"exp"`
       Iat                int64                  `json:"iat"`
       Nbf                int64                  `json:"nbf"`
       Iss                string                 `json:"iss"`
       Jti                string                 `json:"jti"`
       Groups             []string               `json:"groups"`
       Roles              []string               `json:"roles"`
       Email              string                 `json:"email"`
       PreferredUsername  string                 `json:"preferred_username"`
       TenantID           string                 `json:"tenant_id"`
       Ext                map[string]interface{} `json:"ext"`
       TokenType          string                 `json:"token_type"`
       TokenUse           string                 `json:"token_use"`
}

// audList parses both ["aud1","aud2"] and "single-aud" JSON types.
type audList []string

func (a *audList) UnmarshalJSON(data []byte) error {
       var single string
       if err := json.Unmarshal(data, &single); err == nil {
               *a = []string{single}
               return nil
       }
       var list []string
       if err := json.Unmarshal(data, &list); err == nil {
               *a = list
               return nil
       }
       return errors.New("aud claim must be string or array of strings")
}

func DecodeJWT(token string) (*JWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	headerJson, err := decodeSegment(parts[0])
	if err != nil {
		return nil, err
	}

	payloadJson, err := decodeSegment(parts[1])
	if err != nil {
		return nil, err
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJson, &header); err != nil {
		return nil, err
	}

	var payload JWTPayload
	if err := json.Unmarshal(payloadJson, &payload); err != nil {
		return nil, err
	}

	return &JWT{
		Header:    header,
		Payload:   payload,
		Signature: parts[2],
	}, nil
}

func decodeSegment(seg string) ([]byte, error) {
	// Add padding if necessary
	switch len(seg) % 4 {
	case 2:
		seg += "=="
	case 3:
		seg += "="
	}
	return base64.URLEncoding.DecodeString(seg)
}
