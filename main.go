package main

import (
	"log"
	"o2buzzle/sqlproxy/authn"
	"o2buzzle/sqlproxy/proxy"
)

func main() {
	authn_data, err := authn.ReadAuthnData("config.json")
	if err != nil {
		log.Fatal(err)
	}
	this_proxy := proxy.NewProxy("127.0.0.1", ":3306", authn_data["proxy_user"], authn_data["proxy_pass"])
	err = this_proxy.Start("3307")
	if err != nil {
		log.Fatal(err)
	}
}
