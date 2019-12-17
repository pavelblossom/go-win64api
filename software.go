// +build windows

package winapi

import (
	"fmt"
	"reflect"
	"time"

	"golang.org/x/sys/windows/registry"

	so "github.com/pavelblossom/go-win64api/shared"
)

func InstalledSoftwareList() ([]so.Software, error) {
	list := make([]so.Software, 0)
	sw64, err := getSoftwareList(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "X32", registry.READ|registry.WOW64_64KEY)
	if err != nil {
		sw64 = make([]so.Software, 0)
	}
	sw32, err := getSoftwareList(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "X32", registry.READ|registry.WOW64_32KEY)
	if err != nil {
		sw32 = make([]so.Software, 0)
	}
	if reflect.DeepEqual(sw64, sw32) {
		list = append(list, sw32...)
		return list, nil
	} else {
		sw64, err := getSoftwareList(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "X64", registry.READ|registry.WOW64_64KEY)
		if err != nil {
			sw64 = make([]so.Software, 0)
		}
		list = append(list, sw32...)
		list = append(list, sw64...)
		return list, nil
	}
}

func getSoftwareList(baseKey string, arch string, param uint32) ([]so.Software, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, baseKey, param)
	if err != nil {
		return nil, fmt.Errorf("Error reading from registry: %s", err.Error())
	}
	defer k.Close()

	swList := make([]so.Software, 0)

	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("Error reading subkey list from registry: %s", err.Error())
	}
	for _, sw := range subkeys {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, baseKey+`\`+sw, param)
		if err != nil {
			return nil, fmt.Errorf("Error reading from registry (subkey %s): %s", sw, err.Error())
		}

		dn, _, err := sk.GetStringValue("DisplayName")
		if err == nil {
			swv := so.Software{DisplayName: dn, Arch: arch}

			dv, _, err := sk.GetStringValue("DisplayVersion")
			if err == nil {
				swv.DisplayVersion = dv
			}

			pub, _, err := sk.GetStringValue("Publisher")
			if err == nil {
				swv.Publisher = pub
			}

			id, _, err := sk.GetStringValue("InstallDate")
			if err == nil {
				swv.InstallDate, _ = time.Parse("20060102", id)
			}

			es, _, err := sk.GetIntegerValue("EstimatedSize")
			if err == nil {
				swv.EstimatedSize = es
			}

			cont, _, err := sk.GetStringValue("Contact")
			if err == nil {
				swv.Contact = cont
			}

			hlp, _, err := sk.GetStringValue("HelpLink")
			if err == nil {
				swv.HelpLink = hlp
			}

			isource, _, err := sk.GetStringValue("InstallSource")
			if err == nil {
				swv.InstallSource = isource
			}

			mver, _, err := sk.GetIntegerValue("VersionMajor")
			if err == nil {
				swv.VersionMajor = mver
			}

			mnver, _, err := sk.GetIntegerValue("VersionMinor")
			if err == nil {
				swv.VersionMinor = mnver
			}

			swList = append(swList, swv)
		}
	}

	return swList, nil
}
