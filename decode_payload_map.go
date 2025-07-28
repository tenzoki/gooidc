package oidc

import (
       "encoding/base64"
       "encoding/json"
)

// DecodePayloadToMap decodes the payload part of a JWT (
// base64-encoded JSON) into a map[string]interface{}.
func DecodePayloadToMap(seg string) (map[string]interface{}, error) {
       // Add padding if necessary
       switch len(seg) % 4 {
       case 2:
               seg += "=="
       case 3:
               seg += "="
       }
       raw, err := base64.URLEncoding.DecodeString(seg)
       if err != nil {
               return nil, err
       }
       m := make(map[string]interface{})
       if err := json.Unmarshal(raw, &m); err != nil {
               return nil, err
       }
       return m, nil
}