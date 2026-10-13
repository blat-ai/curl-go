package curlgo

import "fmt"

// Profile selects a browser fingerprint provided by curl-impersonate v2.2.3.
// Use a versioned profile for reproducibility; family aliases select the latest
// profile supported by the bundled native library.
type Profile string

const (
	Edge99           Profile = "edge99"
	Edge101          Profile = "edge101"
	Chrome99         Profile = "chrome99"
	Chrome100        Profile = "chrome100"
	Chrome101        Profile = "chrome101"
	Chrome104        Profile = "chrome104"
	Chrome107        Profile = "chrome107"
	Chrome110        Profile = "chrome110"
	Chrome116        Profile = "chrome116"
	Chrome119        Profile = "chrome119"
	Chrome120        Profile = "chrome120"
	Chrome123        Profile = "chrome123"
	Chrome124        Profile = "chrome124"
	Chrome131        Profile = "chrome131"
	Chrome133A       Profile = "chrome133a"
	Chrome136        Profile = "chrome136"
	Chrome142        Profile = "chrome142"
	Chrome145        Profile = "chrome145"
	Chrome146        Profile = "chrome146"
	Chrome150        Profile = "chrome150"
	Chrome99Android  Profile = "chrome99_android"
	Chrome131Android Profile = "chrome131_android"
	Safari153        Profile = "safari153"
	Safari155        Profile = "safari155"
	Safari170        Profile = "safari170"
	Safari172IOS     Profile = "safari172_ios"
	Safari180        Profile = "safari180"
	Safari180IOS     Profile = "safari180_ios"
	Safari184        Profile = "safari184"
	Safari184IOS     Profile = "safari184_ios"
	Safari260        Profile = "safari260"
	Safari2601       Profile = "safari2601"
	Safari260IOS     Profile = "safari260_ios"
	Firefox133       Profile = "firefox133"
	Firefox135       Profile = "firefox135"
	Firefox144       Profile = "firefox144"
	Firefox147       Profile = "firefox147"
	Tor145           Profile = "tor145"

	Chrome        Profile = "chrome"
	Edge          Profile = "edge"
	Safari        Profile = "safari"
	SafariIOS     Profile = "safari_ios"
	SafariBeta    Profile = "safari_beta"
	SafariIOSBeta Profile = "safari_ios_beta"
	ChromeAndroid Profile = "chrome_android"
	Firefox       Profile = "firefox"
	Tor           Profile = "tor"

	// Deprecated Safari spellings remain accepted for compatibility with curl_cffi.
	Safari15_3    Profile = "safari15_3"
	Safari15_5    Profile = "safari15_5"
	Safari17_0    Profile = "safari17_0"
	Safari17_2IOS Profile = "safari17_2_ios"
	Safari18_0    Profile = "safari18_0"
	Safari18_0IOS Profile = "safari18_0_ios"
	Safari18_4    Profile = "safari18_4"
	Safari18_4IOS Profile = "safari18_4_ios"
)

var profiles = []Profile{
	Edge99, Edge101,
	Chrome99, Chrome100, Chrome101, Chrome104, Chrome107, Chrome110,
	Chrome116, Chrome119, Chrome120, Chrome123, Chrome124, Chrome131,
	Chrome133A, Chrome136, Chrome142, Chrome145, Chrome146, Chrome150,
	Chrome99Android, Chrome131Android,
	Safari153, Safari155, Safari170, Safari172IOS, Safari180, Safari180IOS,
	Safari184, Safari184IOS, Safari260, Safari2601, Safari260IOS,
	Firefox133, Firefox135, Firefox144, Firefox147, Tor145,
}

var profileAliases = map[Profile]Profile{
	Chrome: Chrome150, Edge: Edge101, Safari: Safari2601,
	SafariIOS: Safari260IOS, SafariBeta: Safari2601, SafariIOSBeta: Safari260IOS,
	ChromeAndroid: Chrome131Android, Firefox: Firefox147, Tor: Tor145,
	Safari15_3: Safari153, Safari15_5: Safari155, Safari17_0: Safari170,
	Safari17_2IOS: Safari172IOS, Safari18_0: Safari180, Safari18_0IOS: Safari180IOS,
	Safari18_4: Safari184, Safari18_4IOS: Safari184IOS,
}

// Profiles returns all 38 concrete native profiles, in upstream order. The
// returned slice is independent of the package's registry.
func Profiles() []Profile {
	return append([]Profile(nil), profiles...)
}

// ProfileAliases returns a copy of the latest and deprecated profile aliases.
func ProfileAliases() map[Profile]Profile {
	aliases := make(map[Profile]Profile, len(profileAliases))
	for alias, profile := range profileAliases {
		aliases[alias] = profile
	}
	return aliases
}

// NormalizeProfile resolves aliases and rejects unknown profiles. An empty
// profile requests ordinary curl behavior without browser impersonation.
func NormalizeProfile(profile Profile) (Profile, error) {
	if profile == "" {
		return "", nil
	}
	if resolved, ok := profileAliases[profile]; ok {
		return resolved, nil
	}
	for _, candidate := range profiles {
		if profile == candidate {
			return profile, nil
		}
	}
	return "", fmt.Errorf("curlgo: unknown browser profile %q", profile)
}
