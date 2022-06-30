package main

import (
	"log"
	"o2buzzle/sqlproxy/proxy"
)

func main() {
	this_proxy := proxy.NewProxy("127.0.0.1", ":3306")
	err := this_proxy.Start("3307")
	if err != nil {
		log.Fatal(err)
	}
}
