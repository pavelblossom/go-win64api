package shared

import (
	"fmt"
	"time"
)

const (
	SESS_INTERACTIVE_LOGON        = 2
	SESS_REMOTE_INTERACTIVE_LOGON = 10
	SESS_CACHED_INTERACTIVE_LOGON = 11
)

type SessionDetails struct {
	Username       string        `json:"username"`
	Domain         string        `json:"domain"`
	LocalUser      bool          `json:"isLocal"`
	LocalAdmin     bool          `json:"isAdmin"`
	LogonType      uint32        `json:"logonType"`
	LogonTime      time.Time     `json:"logonTime"`
	DnsDomainName  string        `json:"dnsDomainName"`
	Session        uint32        `json:"session"`
	Sid            string        `json:"sid"`
	State          int           `json:"state"`
	Hostcon        string        `json:"hostcon"`
	ActivityId     string        `json:"activityId"`
	ConnectionName string        `json:"connectionName"`
	ClientIPPort   ClientNetData `json:"clientIp"`
}
type ClientNetData struct {
	Ip   string `json:"IP"`
	Port int64  `json:"Port"`
}

func (s *SessionDetails) FullUser() string {
	return fmt.Sprintf("%s\\%s", s.Domain, s.Username)
}

func (s *SessionDetails) GetLogonType() string {
	switch s.LogonType {
	case SESS_INTERACTIVE_LOGON:
		return "INTERACTIVE_LOGON"
	case SESS_REMOTE_INTERACTIVE_LOGON:
		return "REMOTE_INTERACTIVE_LOGON"
	case SESS_CACHED_INTERACTIVE_LOGON:
		return "CACHED_INTERACTIVE_LOGON"
	default:
		return "UNKNOWN"
	}
}
