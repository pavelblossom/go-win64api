// +build windows

package winapi

import (
	"bytes"
	"fmt"
	so "github.com/pavelblossom/go-win64api/shared"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

//начало исправлений для powershell
type powerShell struct {
	powerShell string
}

func newPower() *powerShell {
	ps, _ := exec.LookPath("powershell.exe")                               //так и надо оставить если 64 и 64
	ps = "c:\\windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell.exe" //так если система 64 а клиент 32
	return &powerShell{
		powerShell: ps,
	}
}

func (p *powerShell) Execute(args ...string) (stdOut string, stdErr string, err error) {
	args = append([]string{"-NoProfile", "-NonInteractive"}, args...)
	cmd := exec.Command(p.powerShell, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	stdOut, stdErr = stdout.String(), stderr.String()
	fmt.Println(stdErr)
	return
}

//конец исправлений

var (
	modwtsapi32                   *windows.LazyDLL  = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumerateSessionsW     *windows.LazyProc = modwtsapi32.NewProc("WTSEnumerateSessionsW")
	modSecur32                                      = syscall.NewLazyDLL("secur32.dll")
	sessLsaFreeReturnBuffer                         = modSecur32.NewProc("LsaFreeReturnBuffer")
	sessLsaEnumerateLogonSessions                   = modSecur32.NewProc("LsaEnumerateLogonSessions")
	sessLsaGetLogonSessionData                      = modSecur32.NewProc("LsaGetLogonSessionData")
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type SECURITY_LOGON_SESSION_DATA struct {
	Size                  uint32
	LogonId               LUID
	UserName              LSA_UNICODE_STRING
	LogonDomain           LSA_UNICODE_STRING
	AuthenticationPackage LSA_UNICODE_STRING
	LogonType             uint32
	Session               uint32
	Sid                   uintptr
	LogonTime             uint64
	LogonServer           LSA_UNICODE_STRING
	DnsDomainName         LSA_UNICODE_STRING
	Upn                   LSA_UNICODE_STRING
}

type LSA_UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	buffer        uintptr
}
type WTS_SESSION_INFO struct {
	SessionID      windows.Handle
	WinStationName *uint16
	State          int
}

const (
	WTS_CURRENT_SERVER_HANDLE uintptr = 0
)

func WTSEnumerateSessions() ([]*WTS_SESSION_INFO, error) {
	var (
		sessionInformation windows.Handle      = windows.Handle(0)
		sessionCount       int                 = 0
		sessionList        []*WTS_SESSION_INFO = make([]*WTS_SESSION_INFO, 0)
	)
	if returnCode, _, err := procWTSEnumerateSessionsW.Call(WTS_CURRENT_SERVER_HANDLE, 0, 1, uintptr(unsafe.Pointer(&sessionInformation)), uintptr(unsafe.Pointer(&sessionCount))); returnCode == 0 {
		return nil, fmt.Errorf("call native WTSEnumerateSessionsW: %s", err)
	}
	structSize := unsafe.Sizeof(WTS_SESSION_INFO{})
	current := uintptr(sessionInformation)
	for i := 0; i < sessionCount; i++ {
		sessionList = append(sessionList, (*WTS_SESSION_INFO)(unsafe.Pointer(current)))
		current += structSize
	}

	return sessionList, nil
}

func ListLoggedInUsers() ([]so.SessionDetails, error) {
	var (
		logonSessionCount uint64
		loginSessionList  uintptr
		sizeTest          LUID
		uList             []string            = make([]string, 0)
		uSessList         []so.SessionDetails = make([]so.SessionDetails, 0)
		PidLUIDList       map[uint32]SessionLUID
	)
	PidLUIDList, err := ProcessLUIDList()
	if err != nil {
		return nil, fmt.Errorf("Error getting process list, %s.", err.Error())
	}
	sessionsWTS, err := WTSEnumerateSessions()
	if err != nil {
		return nil, fmt.Errorf("Error getting WTS sessions, %s.", err.Error())
	}
	_, _, _ = sessLsaEnumerateLogonSessions.Call(
		uintptr(unsafe.Pointer(&logonSessionCount)),
		uintptr(unsafe.Pointer(&loginSessionList)),
	)
	defer sessLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(&loginSessionList)))

	var iter uintptr = uintptr(unsafe.Pointer(loginSessionList))
	//получим журнал за месяц
	puhs := newPower()
	cmdpath := "cmd.exe"
	cmd := `Get-WinEvent -ListLog Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | Get-WinEvent | Where { $_.TimeCreated -gt (get-date).AddDays(-30) -and $_.id -eq "21"} | Sort-Object -Property timecreated -Descending| select  timecreated,message | Format-List`
	std, _, _ := puhs.Execute(cmd)
	//получили

	for i := uint64(0); i < logonSessionCount; i++ {
		var sessionData uintptr
		_, _, _ = sessLsaGetLogonSessionData.Call(uintptr(iter), uintptr(unsafe.Pointer(&sessionData)))
		if sessionData != uintptr(0) {
			var data *SECURITY_LOGON_SESSION_DATA = (*SECURITY_LOGON_SESSION_DATA)(unsafe.Pointer(sessionData))
			if data.Sid != uintptr(0) {
				validTypes := []uint32{so.SESS_INTERACTIVE_LOGON, so.SESS_CACHED_INTERACTIVE_LOGON, so.SESS_REMOTE_INTERACTIVE_LOGON}
				if in_array(data.LogonType, validTypes) {
					strLogonDomain := strings.ToUpper(LsatoString(data.LogonDomain))
					if strLogonDomain != "WINDOW MANAGER" && strLogonDomain != "FONT DRIVER HOST" {
						sUser := fmt.Sprintf("%s\\%s", strings.ToUpper(LsatoString(data.LogonDomain)), strings.ToLower(LsatoString(data.UserName)))
						sort.Strings(uList)
						i := sort.Search(len(uList), func(i int) bool { return uList[i] >= sUser })
						if !(i < len(uList) && uList[i] == sUser) {
							if uok, isAdmin := luidinmap(&data.LogonId, &PidLUIDList); uok {
								uList = append(uList, sUser)
								var sessionState int = 10
								for _, wtsSession := range sessionsWTS {
									if uint32(wtsSession.SessionID) == data.Session {
										sessionState = wtsSession.State
									}
								}
								ud := so.SessionDetails{
									Username:      strings.ToLower(LsatoString(data.UserName)),
									Domain:        strLogonDomain,
									LocalAdmin:    isAdmin,
									LogonType:     data.LogonType,
									DnsDomainName: LsatoString(data.DnsDomainName),
									//	Sid:           data.Sid,
									Session:   data.Session,
									LogonTime: uint64TimestampToTime(data.LogonTime),
									State:     sessionState,
								}

								//найдем SID пользователя

								sid, _ := GetRawSidForAccountName(ud.Username)
								sid2, _ := ConvertRawSidToStringSid(sid)
								ud.Sid = sid2
								//fmt.Println(time.Now().Format("2 Jan 2006 15:04:05.000"), "Reestr")
								//проверить в реестре откуда подключился, предварительно считаем, что локально
								ud.Hostcon = "local"

								reestr := fmt.Sprintf(`HKEY_USERS\%+v\Volatile Environment\%+v\`, ud.Sid, ud.Session)
								reg, _ := exec.Command(cmdpath, "/C", "reg", "query", reestr, "/v", "CLIENTNAME").Output()
								ud.Hostcon = "local"
								if len(strings.Split(string(reg), "CLIENTNAME")) == 2 {
									hostname := strings.Trim(strings.Split(string(reg), "CLIENTNAME")[1], " ")
									hostname = strings.ReplaceAll(hostname, "REG_SZ", "")
									hostname = strings.ReplaceAll(hostname, "\n", "")
									hostname = strings.ReplaceAll(hostname, "\r", "")
									hostname = strings.Trim(hostname, " ")

									if len(hostname) > 2 {
										ud.Hostcon = hostname
									}
								}
								reg = nil
								//fmt.Println(time.Now().Format("2 Jan 2006 15:04:05.000"), "Journal")
								//проверим журнал безопасности по логам подключения rdp (Важно: Савлюк цеплялся по ssh видимо с мака, его ip остался неизвестен)
								ud.IPcon = "not find in wni-event logon" //преварительно считаем, что вошли локально
								if ud.Hostcon != "local" {
									stdR := strings.Split(std, "TimeCreated")
									for k := 0; k < len(stdR); k++ {
										chectctd := strings.Split(stdR[k], ":")
										if len(chectctd) == 10 {
											findeduser := strings.Split(chectctd[7], "\n")[0]
											findeduser = strings.ReplaceAll(findeduser, "\n", "")
											findeduser = strings.ReplaceAll(findeduser, "\r", "")
											findeduser = strings.ReplaceAll(findeduser, " ", "")
											findedses := strings.Split(chectctd[8], "\n")[0]
											findedses = strings.ReplaceAll(findedses, "\n", "")
											findedses = strings.ReplaceAll(findedses, "\r", "")
											findedses = strings.ReplaceAll(findedses, " ", "")
											findedip := chectctd[9]
											findedip = strings.ReplaceAll(findedip, "\n", "")
											findedip = strings.ReplaceAll(findedip, "\r", "")
											findedip = strings.ReplaceAll(findedip, " ", "")
											str := fmt.Sprint(ud.Session)
											if (strings.ToLower(findedses) == strings.ToLower(str)) && (strings.Index(strings.ToLower(findeduser), "\\"+strings.ToLower(ud.Username)) > 5) {
												ud.IPcon = findedip
												k = len(stdR)
											}

										}
									}

								} else {
									ud.IPcon = "local"
								}

								hn, _ := os.Hostname()
								if strings.ToUpper(ud.Domain) == strings.ToUpper(hn) {
									ud.LocalUser = true
									if isAdmin, _ := IsLocalUserAdmin(ud.Username); isAdmin {
										ud.LocalAdmin = true
									}
								} else {
									if isAdmin, _ := IsDomainUserAdmin(ud.Username, LsatoString(data.DnsDomainName)); isAdmin {
										ud.LocalAdmin = true
									}
								}
								uSessList = append(uSessList, ud)
							}
						}
					}
				}
			}
		}

		iter = uintptr(unsafe.Pointer(iter + unsafe.Sizeof(sizeTest)))
		_, _, _ = sessLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(sessionData)))
	}

	return uSessList, nil
}

func uint64TimestampToTime(nsec uint64) time.Time {
	// change starting time to the Epoch (00:00:00 UTC, January 1, 1970)
	nsec -= 116444736000000000
	// convert into nanoseconds
	nsec *= 100

	return time.Unix(0, int64(nsec))
}

func sessUserLUIDs() (map[LUID]string, error) {
	var (
		logonSessionCount uint64
		loginSessionList  uintptr
		sizeTest          LUID
		uList             map[LUID]string = make(map[LUID]string)
	)

	_, _, _ = sessLsaEnumerateLogonSessions.Call(
		uintptr(unsafe.Pointer(&logonSessionCount)),
		uintptr(unsafe.Pointer(&loginSessionList)),
	)
	defer sessLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(&loginSessionList)))

	var iter uintptr = uintptr(unsafe.Pointer(loginSessionList))

	for i := uint64(0); i < logonSessionCount; i++ {
		var sessionData uintptr
		_, _, _ = sessLsaGetLogonSessionData.Call(uintptr(iter), uintptr(unsafe.Pointer(&sessionData)))
		if sessionData != uintptr(0) {
			var data *SECURITY_LOGON_SESSION_DATA = (*SECURITY_LOGON_SESSION_DATA)(unsafe.Pointer(sessionData))

			if data.Sid != uintptr(0) {
				uList[data.LogonId] = fmt.Sprintf("%s\\%s", strings.ToUpper(LsatoString(data.LogonDomain)), strings.ToLower(LsatoString(data.UserName)))
			}
		}

		iter = uintptr(unsafe.Pointer(iter + unsafe.Sizeof(sizeTest)))
		_, _, _ = sessLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(sessionData)))
	}

	return uList, nil
}

func luidinmap(needle *LUID, haystack *map[uint32]SessionLUID) (bool, bool) {
	for _, l := range *haystack {
		if reflect.DeepEqual(l.Value, *needle) {
			if l.IsAdmin {
				return true, true
			} else {
				return true, false
			}
		}
	}
	return false, false
}

func LsatoString(p LSA_UNICODE_STRING) string {
	return syscall.UTF16ToString((*[4096]uint16)(unsafe.Pointer(p.buffer))[:p.Length])
}

func in_array(val interface{}, array interface{}) (exists bool) {
	exists = false

	switch reflect.TypeOf(array).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(array)

		for i := 0; i < s.Len(); i++ {
			if reflect.DeepEqual(val, s.Index(i).Interface()) == true {
				exists = true
				return
			}
		}
	}

	return
}
