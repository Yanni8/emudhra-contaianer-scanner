package stores

import "testing"

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		name string
		data string
		want OSInfo
	}{
		{"empty", "", OSInfo{}},
		{"debian", "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\nID=debian\nHOME_URL=\"https://www.debian.org/\"\n",
			OSInfo{ID: "debian", VersionID: "12", PrettyName: "Debian GNU/Linux 12 (bookworm)"}},
		{"debian-sid", "PRETTY_NAME=\"Debian GNU/Linux forky/sid\"\nNAME=\"Debian GNU/Linux\"\nVERSION_CODENAME=forky\nID=debian\n",
			OSInfo{ID: "debian", PrettyName: "Debian GNU/Linux forky/sid"}},
		{"ubuntu", "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION=\"24.04.1 LTS (Noble Numbat)\"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\nUBUNTU_CODENAME=noble\n",
			OSInfo{ID: "ubuntu", IDLike: "debian", VersionID: "24.04", PrettyName: "Ubuntu 24.04.1 LTS"}},
		{"alpine-unquoted", "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\n",
			OSInfo{ID: "alpine", VersionID: "3.20.3", PrettyName: "Alpine Linux v3.20"}},
		{"rhel-ubi", "NAME=\"Red Hat Enterprise Linux\"\nVERSION=\"9.4 (Plow)\"\nID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.4\"\nPRETTY_NAME=\"Red Hat Enterprise Linux 9.4 (Plow)\"\n",
			OSInfo{ID: "rhel", IDLike: "fedora", VersionID: "9.4", PrettyName: "Red Hat Enterprise Linux 9.4 (Plow)"}},
		{"rocky-multi-like", "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.3\"\n",
			OSInfo{ID: "rocky", IDLike: "rhel centos fedora", VersionID: "9.3"}},
		{"arch-no-version", "NAME=\"Arch Linux\"\nPRETTY_NAME=\"Arch Linux\"\nID=arch\nBUILD_ID=rolling\n",
			OSInfo{ID: "arch", PrettyName: "Arch Linux"}},
		{"single-quotes", "ID='fedora'\nVERSION_ID='41'\nPRETTY_NAME='Fedora Linux 41 (Container Image)'\n",
			OSInfo{ID: "fedora", VersionID: "41", PrettyName: "Fedora Linux 41 (Container Image)"}},
		{"escapes", "PRETTY_NAME=\"Foo \\\"Bar\\\" \\$HOME \\\\ \\`x\\`\"\nID=foo\n",
			OSInfo{ID: "foo", PrettyName: "Foo \"Bar\" $HOME \\ `x`"}},
		{"single-quote-no-escapes", "PRETTY_NAME='Foo \\\"Bar'\nID=foo\n", OSInfo{ID: "foo", PrettyName: "Foo \\\"Bar"}},
		{"crlf-and-comments", "# comment\r\nID=debian\r\n\r\n   VERSION_ID = \"13\"  \r\n# ID=ubuntu\r\n", OSInfo{ID: "debian", VersionID: "13"}},
		{"last-wins", "ID=debian\nID=ubuntu\n", OSInfo{ID: "ubuntu"}},
		{"garbage-lines", "not a key value\n=novalue\nID=\nID_LIKE=debian\n", OSInfo{IDLike: "debian"}},
		{"unterminated-quote", "ID=\"debian\nVERSION_ID=12\"\n", OSInfo{ID: "\"debian", VersionID: "12\""}},
		{"leading-bom-free-tabs", "\tID=alpine\n", OSInfo{ID: "alpine"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseOSRelease([]byte(tt.data)); got != tt.want {
				t.Errorf("ParseOSRelease =\n  %+v\nwant\n  %+v", got, tt.want)
			}
		})
	}
}
