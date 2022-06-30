package authn

import (
	"encoding/json"
	"os"
)

func ReadAuthnData(configfile string) (map[string]string, error) {
	authn_data := make(map[string]string)
	dat, err := os.ReadFile(configfile)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(dat, &authn_data)
	if err != nil {
		return nil, err
	}
	return authn_data, nil
}
