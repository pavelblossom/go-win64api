package shared

import (
	"gopkg.in/nullbio/null.v6"
)

type LocalUser struct {
	Username             string    `json:"username"`
	FullName             string    `json:"fullName"`
	IsEnabled            bool      `json:"isEnabled"`
	IsLocked             bool      `json:"isLocked"`
	IsAdmin              bool      `json:"isAdmin"`
	PasswordNeverExpires bool      `json:"passwordNeverExpires"`
	NoChangePassword     bool      `json:"noChangePassword"`
	PasswordAge          null.Time `json:"passwordAge"`
	LastLogon            null.Time `json:"lastLogon"`
	LastLogoff           null.Time `json:"lastLogoff"`
	BadPasswordCount     uint32    `json:"badPasswordCount"`
	NumberOfLogons       uint32    `json:"numberOfLogons"`
	SID                  string    `json:"sid"`
}
