package collector

import "testing"

func TestParseOSRelease(t *testing.T) {
	values := parseOSRelease([]byte(`
ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04 LTS"
`))

	if values["ID"] != "ubuntu" {
		t.Fatalf("ID = %q", values["ID"])
	}
	if values["VERSION_ID"] != "22.04" {
		t.Fatalf("VERSION_ID = %q", values["VERSION_ID"])
	}
}

func TestParsePackageRows(t *testing.T) {
	packages := parsePackageRows(
		[]byte("nginx\t1:1.24.0-1ubuntu1\tnginx\tamd64\nopenssl\t3.0.2\topenssl\tamd64\n"),
		"dpkg",
	)

	if len(packages) != 2 {
		t.Fatalf("len(packages) = %d", len(packages))
	}
	if packages[0].Name != "nginx" || packages[0].Version != "1:1.24.0-1ubuntu1" {
		t.Fatalf("unexpected first package: %#v", packages[0])
	}
	if packages[0].SourcePackage != "nginx" || packages[0].Architecture != "amd64" {
		t.Fatalf("missing structured package identity: %#v", packages[0])
	}
	if _, ok := FindPackage(packages, "nginx"); !ok {
		t.Fatal("expected nginx package to be found")
	}
}

func TestPackagesToComponentsCarriesDistroIdentity(t *testing.T) {
	components := packagesToComponents(
		[]PackageInfo{{
			Name:          "linux-image-generic",
			Version:       "5.15.0.119.119",
			Source:        "dpkg",
			SourcePackage: "linux-meta",
			Architecture:  "amd64",
		}},
		PlatformInfo{OSFamily: "ubuntu", OSVersion: "22.04", Architecture: "amd64"},
	)

	if len(components) != 1 {
		t.Fatalf("len(components) = %d", len(components))
	}
	component := components[0]
	if component.Ecosystem != "deb" || component.VersionScheme != "debian" {
		t.Fatalf("unexpected version identity: %#v", component)
	}
	if component.Distro != "ubuntu" || component.DistroRelease != "22.04" {
		t.Fatalf("unexpected distro identity: %#v", component)
	}
}

func TestParseSSListenRows(t *testing.T) {
	rows := []byte(`
LISTEN 0 511 0.0.0.0:80 0.0.0.0:*
LISTEN 0 128 [::]:443 [::]:*
LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*
`)

	exposures := parseSSListenRows(rows)
	if len(exposures) != 3 {
		t.Fatalf("len(exposures) = %d", len(exposures))
	}
	if exposures[0].Port != 53 || exposures[0].Address != "127.0.0.53" {
		t.Fatalf("unexpected first exposure: %#v", exposures[0])
	}
	if exposures[1].Port != 80 || exposures[1].ServiceName != "http" {
		t.Fatalf("unexpected http exposure: %#v", exposures[1])
	}
	if exposures[2].Port != 443 || exposures[2].Address != "::" {
		t.Fatalf("unexpected ipv6 exposure: %#v", exposures[2])
	}
}

func TestParseProcNetTCPRows(t *testing.T) {
	rows := []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0
   2: 0100007F:1770 00000000:0000 01 00000000:00000000 00:00000000 00000000 0 0 0
`)

	exposures := parseProcNetTCPRows(rows, false)
	if len(exposures) != 2 {
		t.Fatalf("len(exposures) = %d", len(exposures))
	}
	if exposures[0].Port != 22 || exposures[0].Address != "0.0.0.0" {
		t.Fatalf("unexpected ssh exposure: %#v", exposures[0])
	}
	if exposures[1].Port != 8080 || exposures[1].Address != "127.0.0.1" {
		t.Fatalf("unexpected local exposure: %#v", exposures[1])
	}
}

func TestParseProcNetTCP6Rows(t *testing.T) {
	rows := []byte(`  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0
`)

	exposures := parseProcNetTCPRows(rows, true)
	if len(exposures) != 1 {
		t.Fatalf("len(exposures) = %d", len(exposures))
	}
	if exposures[0].Port != 443 || exposures[0].Address != "::1" {
		t.Fatalf("unexpected ipv6 exposure: %#v", exposures[0])
	}
}
