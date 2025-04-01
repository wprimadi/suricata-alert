package permission

import (
	"os/user"
	"strings"
)

func CheckLinuxRootPermission() (bool, error) {
	currentUser, err := user.Current()
	if err != nil {
		return false, err
	}

	if strings.ToLower(currentUser.Username) == "root" {
		return true, nil
	}

	return false, nil
}
