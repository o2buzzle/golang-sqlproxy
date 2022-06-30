package authn

import (
	"crypto/sha1"
	"encoding/json"
	"os"
)

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xor: length mismatch")
	}
	c := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		c[i] = a[i] ^ b[i]
	}
	return c
}

//SHA1( password ) XOR SHA1( "20-bytes random data from server" <concat> SHA1( SHA1( password ) ) )
func HashNativePassword(password string, random []byte) []byte {
	hashed_password := sha1.Sum([]byte(password))
	// fmt.Printf("hashed_password: %x\n", hashed_password)
	hashed_hashed_password := sha1.Sum(hashed_password[:])
	// fmt.Printf("hashed_hashed_password: %x\n", hashed_hashed_password)

	concat := string(random[:len(random)-1]) + string(hashed_hashed_password[:])
	// fmt.Printf("concat: %x\n", concat)
	hashed_concat := sha1.Sum([]byte(concat))
	// fmt.Printf("hashed_concat: %x\n", hashed_concat)

	xored := xor(hashed_password[:], hashed_concat[:])

	return xored
}

func ReadProxyPassword(configfile, username string) (string, error) {
	file, err := os.ReadFile(configfile)
	if err != nil {
		return "", err
	}
	buf := map[string]map[string]string{}
	json.Unmarshal(file, &buf)
	return string(buf["accounts"][username]), nil
}
