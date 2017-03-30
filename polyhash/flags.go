package polyhash

import (
	"errors"
	"fmt"
	"strings"
)

type PolyhashPasswordsFlag []string

func (p *PolyhashPasswordsFlag) String() string {
	return fmt.Sprint(*p)
}

func (p *PolyhashPasswordsFlag) Set(value string) error {
	var share_num int = 1
	if len(*p) > 0 {
		return errors.New("polyhash can only be specified once")
	}

	splitValues := strings.Split(value, ",")
	for _, password := range splitValues {
		share_num_pwd := string(share_num) + ","
		share_num_pwd += password
		*p = append(*p, share_num_pwd)
	}

	return nil
}
