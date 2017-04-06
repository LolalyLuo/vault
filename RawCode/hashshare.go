package main

import (
	"fmt"
	//"encoding/binary"
	//"crypto/cipher"
	"bufio"
	"crypto/sha256"
	"crypto/rand"
	//"log"
	//"bytes"
	"os"
)

const SHARE_LENGTH = 32
const SALT_LENGTH =16

func check_error(e error){
	if e != nil {
		panic(e)
	}
}
func xorBytes(dst, a, b []byte) int {
	n := len(a)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}
func insert_share_info(password []byte){
	//replace with Vault shares
	share := make([]byte, SHARE_LENGTH)
	_, err := rand.Read(share)
	check_error(err)

	fmt.Printf("original share is %064x", share)
	//replace with Vault shares
	//find the has and share_xor_hash
	share_xor_hash := make([]byte, SHARE_LENGTH)
	salt := make([]byte, SALT_LENGTH)
	_, err = rand.Read(salt)
	check_error(err);
	var retval int
	hash := obtain_hash(salt, password)
	retval = xorBytes(share_xor_hash, share, hash)
	if (retval < 32) {}
	//find the next number of share number
	file, err := os.Open("share_file.txt")
	check_error(err);
	reader := bufio.NewReader(file)
	var last_shareno string
	var share_num uint8 = 0
	for (err == nil){
		last_shareno,err = reader.ReadString(0x2c)
		_, _,err = reader.ReadLine()
		fmt.Println(last_shareno)
		if (err == nil) {
			fmt.Sscanf(last_shareno, "%x", &share_num)
		}
	}
	share_num += 1
	fmt.Println(share_num)
	file.Close()
	//write share number, share xor hash and salt to the file 
	file, err = os.OpenFile("share_file.txt", os.O_APPEND|os.O_WRONLY, 0666)
	check_error(err)
	_, err = file.WriteString(fmt.Sprintf("%02x", share_num))
	_, err = file.WriteString(",")
	_, err = file.WriteString(fmt.Sprintf("%064X", share_xor_hash))
	_, err = file.WriteString(",")
	_, err = file.WriteString(fmt.Sprintf("%032X", salt))
	_, err = file.WriteString("\n")
	check_error(err)
	file.Close()
}
func extract_share_info(share_num uint8)([]byte, []byte){
	share_xor_hash := make([]byte, SHARE_LENGTH)
	salt := make([]byte, SALT_LENGTH)
	file, err := os.Open("share_file.txt")
	check_error(err)
	reader := bufio.NewReader(file)
	err = nil
	var number uint8
	var share_data string
	for (err == nil){
		share_data , err = reader.ReadString('\n')
		fmt.Sscanf(share_data, "%x,%x,%x", &number, &share_xor_hash, &salt)
		if (number == share_num){
			break
		}
	}
	file.Close()
	return share_xor_hash, salt
}
func obtain_hash (salt, password []byte) []byte {
	hash_func := sha256.New()
	hash_func.Write(salt)
	hash_func.Write(password)
	return hash_func.Sum(nil)
}
func obtain_share (share_num uint8, password []byte) []byte {
	share_xor_hash, salt := extract_share_info(share_num)
	hash := obtain_hash(salt, password)
	share := make([]byte, SHARE_LENGTH)
	retval := xorBytes(share, share_xor_hash, hash)
	if (retval < SHARE_LENGTH){} //panic
	return share

}
func main() {
	insert_share_info([]byte ("password"))
	insert_share_info([]byte ("mypassword"))
	insert_share_info([]byte ("thepassword"))

	fmt.Printf("obtained share is %064x", obtain_share(1, []byte("password")))
	fmt.Printf("obtained share is %064x", obtain_share(2, []byte("mypassword")))
	fmt.Printf("obtained share is %064x", obtain_share(3, []byte("thepassword")))


	//fmt.Printf("%s\n",obtain_hash([]byte("salt"), []byte("password")))
}
