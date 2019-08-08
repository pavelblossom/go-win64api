// +build windows,386

package winapi

import (
	"fmt"
	so "github.com/pavelblossom/go-win64api/shared"
	"golang.org/x/sys/windows/registry"
	"time"
)

func InstalledSoftwareList() ([]so.Software, error) {
	var appSw []so.Software
	sw64, err := getSoftwareList32(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "X64", registry.QUERY_VALUE|registry.WOW64_64KEY|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	appSw = append(appSw, sw64...)
	sw32, err := getSoftwareList(registry.LOCAL_MACHINE, `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "X32", registry.QUERY_VALUE|registry.WOW64_64KEY|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	appSw = append(appSw, sw32...)
	swU, err := getSoftwareList(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall`, "X32", registry.QUERY_VALUE|registry.WOW64_64KEY|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	appSw = append(appSw, swU...)

	return appSw, nil
}

func InstalledSoftwareList32() ([]so.Software, error) {
	sw32, err := getSoftwareList(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "X32", registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	swU, err := getSoftwareList(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall`, "X32", registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	return append(sw32, swU...), nil
}

func getSoftwareList(key registry.Key, baseKey string, arch string, access uint32) ([]so.Software, error) {
	k, err := registry.OpenKey(key, baseKey, access)
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
		sk, err := registry.OpenKey(key, baseKey+`\`+sw, access)
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

func getSoftwareList32(key registry.Key, baseKey string, arch string, access uint32) ([]so.Software, error) {
	fmt.Println(baseKey)
	fmt.Println(key)
	fmt.Println(arch)
	k, err := registry.OpenKey(key, baseKey, access)
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
		sk, err := registry.OpenKey(key, baseKey+`\`+sw, access)
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
