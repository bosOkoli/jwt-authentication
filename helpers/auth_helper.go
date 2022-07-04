package helper

import (
	"errors"

	"github.com/gin-gonic/gin"
)

func MatchUserTypeToUid(c *gin.Context, userId string) (err error) {
	userType := c.GetString("user_type")

	uid := c.GetString("uid")

	err = nil

	if userType != "ADMIN" && uid != userId {
		err = errors.New("unauthorized to access this resource")
		return err
	}
	CheckUserType(c, userType)
	return err
}

func CheckUserType(c *gin.Context, role string) (err error) {
	userType := c.GetString("uid")

	err = nil
	if userType != role {
		err = errors.New("unauthorized to access this resource")
		return err
	}
	return err
}
