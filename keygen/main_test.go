package main

import (
	"testing"
)

func TestGetAcessKey(t *testing.T) {
	cases := []struct {
		Opts     Opts
		AcessKey string
	}{
		{
			Opts{
				Address: "1.2.3.4:443",
				Cipher:  "chacha20-ietf-poly1305",
				Secret:  "qwerty",
			},
			"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpxd2VydHk=@1.2.3.4:443/?outline=1",
		},
		{
			Opts{
				Address: "1.2.3.4:443",
				Cipher:  "chacha20-ietf-poly1305",
				Secret:  "qwerty",
				Prefix:  "HTTP%2F1.1%20",
			},
			"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpxd2VydHk=@1.2.3.4:443/?outline=1&prefix=HTTP%2F1.1%20",
		},
	}

	for _, c := range cases {
		acessKey, err := GetAcessKey(c.Opts)
		if err != nil {
			t.Errorf("GetAcessKey(%#v): %v", c.Opts, err)
			continue
		}
		if acessKey != c.AcessKey {
			t.Errorf("GetAcessKey(%#v) ==\n\"%s\"\n  want\n\"%s\"", c.Opts, acessKey, c.AcessKey)
		}
	}
}
