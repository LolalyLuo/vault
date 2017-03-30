package polyhash

import (
	"fmt"
	"crypto/sha256"
	"crypto/rand"
)

const SHARE_LENGTH = 32
const SALT_LENGTH =16

func check_error(e error){
	if e != nil {
		panic(e)
	}
}

func xorBytes(a, b []byte) []byte {
	n := len(a)
	dst := make([]byte, n)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return dst
}

func StoreShareInformation(passwords []string, shares [][]byte) []string {

	var shareno int
	salt := make([]byte, SALT_LENGTH)
    var polyhashentry string
	var polyhashdb []string
	var err error

    for i := 0; i < len(shares); i++ {
        // Generate a random salt
        _, err = rand.Read(salt)
        check_error(err);

        // Compute the share_xor_hashes
        hash := computeHash(salt, passwords[i])
		share_xor_hash := xorBytes(shares[i][:len(shares[i])-1], hash)

        // FIXME probably concatenating this tring is not the best idea
        polyhashentry = fmt.Sprintf( "%02x,%064x, %032x\n", shareno,
                    share_xor_hash, salt)

        polyhashdb = append(polyhashdb, polyhashentry)
        shareno += 1
    }

	return polyhashdb
}


func RecoverShareFromPolyhash(share_num int, polyhashdb []string, password string)([]byte){

	share_xor_hash := make([]byte, SHARE_LENGTH)
	salt := make([]byte, SALT_LENGTH)
	var number int

	for _, entry := range polyhashdb{
		fmt.Sscanf(entry, "%x,%x,%x", &number, &share_xor_hash, &salt)
		if (number == share_num){
			break
		}
	}

	hash := computeHash(salt, password)
	share := xorBytes(share_xor_hash, hash)

	return share
}

func computeHash (salt []byte, password string) []byte {
	hash_func := sha256.New()
	hash_func.Write(salt)
	hash_func.Write([]byte(password))
	return hash_func.Sum(nil)
}

func Donoshit() error{
	return fmt.Errorf("Polyhashing is not implemented yet!")
}


//func main() {
//	storeShareInformation([]byte ("password"))
//	storeShareInformation([]byte ("mypassword"))
//	storeShareInformation([]byte ("thepassword"))
//
//	fmt.Printf("obtained share is %064x", obtainShare(1, []byte("password")))
//	fmt.Printf("obtained share is %064x", obtainShare(2, []byte("mypassword")))
//	fmt.Printf("obtained share is %064x", obtainShare(3, []byte("thepassword")))
//
//	//fmt.Printf("%s\n",computeHash([]byte("salt"), []byte("password")))
//}
