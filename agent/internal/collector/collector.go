package collector

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ProfileOptions struct {
	EnvironmentType    string
	ExposureType       string
	BusinessSystem     string
	OwnerTeam          string
	OwnerPerson        string
	Criticality        string
	AllowAutoVerify    bool
	AllowAutoRemediate bool
}

type Snapshot struct {
	AgentID            string      `json:"agent_id"`
	AgentVersion       string      `json:"agent_version,omitempty"`
	Hostname           string      `json:"hostname"`
	PrimaryIP          string      `json:"primary_ip,omitempty"`
	Platform           string      `json:"platform"`
	OSFamily           string      `json:"os_family,omitempty"`
	OSVersion          string      `json:"os_version,omitempty"`
	KernelVersion      string      `json:"kernel_version,omitempty"`
	Architecture       string      `json:"architecture,omitempty"`
	EnvironmentType    string      `json:"environment_type"`
	ExposureType       string      `json:"exposure_type"`
	BusinessSystem     string      `json:"business_system,omitempty"`
	OwnerTeam          string      `json:"owner_team,omitempty"`
	OwnerPerson        string      `json:"owner_person,omitempty"`
	Criticality        string      `json:"criticality"`
	AllowAutoVerify    bool        `json:"allow_auto_verify"`
	AllowAutoRemediate bool        `json:"allow_auto_remediate"`
	CollectedAt        time.Time   `json:"collected_at"`
	Components         []Component `json:"components"`
	Exposures          []Exposure  `json:"exposures"`
	Firewalls          []Firewall  `json:"firewalls"`
}

type Component struct {
	ComponentName string `json:"component_name"`
	ComponentType string `json:"component_type"`
	Version       string `json:"version,omitempty"`
	SourceType    string `json:"source_type,omitempty"`
	Ecosystem     string `json:"ecosystem,omitempty"`
	Distro        string `json:"distro,omitempty"`
	DistroRelease string `json:"distro_release,omitempty"`
	SourcePackage string `json:"source_package,omitempty"`
	BinaryPackage string `json:"binary_package,omitempty"`
	Architecture  string `json:"architecture,omitempty"`
	Flavor        string `json:"flavor,omitempty"`
	VersionScheme string `json:"version_scheme,omitempty"`
	PURL          string `json:"purl,omitempty"`
	CPE           string `json:"cpe,omitempty"`
	InstallPath   string `json:"install_path,omitempty"`
	EvidenceRef   string `json:"evidence_ref,omitempty"`
}

type Exposure struct {
	ExposureKind string `json:"exposure_kind"`
	Address      string `json:"address,omitempty"`
	Port         int    `json:"port,omitempty"`
	Protocol     string `json:"protocol"`
	ServiceName  string `json:"service_name,omitempty"`
	Product      string `json:"product,omitempty"`
	Version      string `json:"version,omitempty"`
	State        string `json:"state"`
	IsPublic     bool   `json:"is_public"`
	Banner       string `json:"banner,omitempty"`
	EvidenceRef  string `json:"evidence_ref,omitempty"`
}

type PlatformInfo struct {
	Platform      string
	OSFamily      string
	OSVersion     string
	KernelVersion string
	Architecture  string
}

type PackageInfo struct {
	Name          string
	Version       string
	Source        string
	SourcePackage string
	Architecture  string
}

func Collect(agentID string, agentVersion string, options ProfileOptions) (Snapshot, error) {
	hostname, _ := os.Hostname()
	platformInfo := CurrentPlatformInfo()
	packages := InstalledPackages()

	snapshot := Snapshot{
		AgentID:            agentID,
		AgentVersion:       agentVersion,
		Hostname:           hostname,
		PrimaryIP:          primaryIP(),
		Platform:           platformInfo.Platform,
		OSFamily:           platformInfo.OSFamily,
		OSVersion:          platformInfo.OSVersion,
		KernelVersion:      platformInfo.KernelVersion,
		Architecture:       platformInfo.Architecture,
		EnvironmentType:    firstNonEmpty(options.EnvironmentType, "production"),
		ExposureType:       firstNonEmpty(options.ExposureType, "internal"),
		BusinessSystem:     options.BusinessSystem,
		OwnerTeam:          options.OwnerTeam,
		OwnerPerson:        options.OwnerPerson,
		Criticality:        firstNonEmpty(options.Criticality, "medium"),
		AllowAutoVerify:    options.AllowAutoVerify,
		AllowAutoRemediate: options.AllowAutoRemediate,
		CollectedAt:        time.Now().UTC(),
		Components:         packagesToComponents(packages, platformInfo),
		Exposures:          ListeningExposures(),
		Firewalls:          []Firewall{},
	}
	if runtime.GOOS == "linux" {
		snapshot.Firewalls = CollectFirewalls()
	}
	return snapshot, nil
}

func CurrentPlatformInfo() PlatformInfo {
	osRelease := parseOSReleaseFile("/etc/os-release")
	return PlatformInfo{
		Platform:      runtime.GOOS,
		OSFamily:      firstNonEmpty(osRelease["ID"], runtime.GOOS),
		OSVersion:     firstNonEmpty(osRelease["VERSION_ID"], osRelease["PRETTY_NAME"]),
		KernelVersion: kernelVersion(),
		Architecture:  runtime.GOARCH,
	}
}

func InstalledPackages() []PackageInfo {
	if path, err := exec.LookPath("dpkg-query"); err == nil {
		out, err := exec.Command(
			path,
			"-W",
			"-f=${Package}\t${Version}\t${source:Package}\t${Architecture}\n",
		).Output()
		if err == nil {
			return parsePackageRows(out, "dpkg")
		}
	}
	if path, err := exec.LookPath("rpm"); err == nil {
		out, err := exec.Command(
			path,
			"-qa",
			"--qf",
			"%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\t%{ARCH}\n",
		).Output()
		if err == nil {
			return parsePackageRows(out, "rpm")
		}
	}
	return []PackageInfo{}
}

func FindPackage(packages []PackageInfo, name string) (PackageInfo, bool) {
	normalizedName := strings.ToLower(strings.TrimSpace(name))
	for _, pkg := range packages {
		if strings.ToLower(pkg.Name) == normalizedName {
			return pkg, true
		}
	}
	return PackageInfo{}, false
}

func ListeningExposures() []Exposure {
	if path, err := exec.LookPath("ss"); err == nil {
		out, err := exec.Command(path, "-lntH").Output()
		if err == nil {
			exposures := parseSSListenRows(out)
			if len(exposures) > 0 {
				return exposures
			}
		}
	}

	exposures := []Exposure{}
	if data, err := os.ReadFile("/proc/net/tcp"); err == nil {
		exposures = append(exposures, parseProcNetTCPRows(data, false)...)
	}
	if data, err := os.ReadFile("/proc/net/tcp6"); err == nil {
		exposures = append(exposures, parseProcNetTCPRows(data, true)...)
	}
	return dedupeAndSortExposures(exposures)
}

func parseSSListenRows(data []byte) []Exposure {
	exposures := []Exposure{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || strings.ToUpper(fields[0]) != "LISTEN" {
			continue
		}
		address, port, ok := splitListenAddress(fields[3])
		if !ok {
			continue
		}
		exposures = append(exposures, newListeningExposure(address, port, "ss -lntH"))
	}
	return dedupeAndSortExposures(exposures)
}

func parseProcNetTCPRows(data []byte, ipv6 bool) []Exposure {
	exposures := []Exposure{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[0] == "sl" || strings.ToUpper(fields[3]) != "0A" {
			continue
		}
		localParts := strings.SplitN(fields[1], ":", 2)
		if len(localParts) != 2 {
			continue
		}
		port64, err := strconv.ParseInt(localParts[1], 16, 32)
		if err != nil || port64 <= 0 || port64 > 65535 {
			continue
		}
		address := parseProcNetAddress(localParts[0], ipv6)
		if address == "" {
			continue
		}
		evidenceRef := "/proc/net/tcp"
		if ipv6 {
			evidenceRef = "/proc/net/tcp6"
		}
		exposures = append(exposures, newListeningExposure(address, int(port64), evidenceRef))
	}
	return dedupeAndSortExposures(exposures)
}

func splitListenAddress(value string) (string, int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, false
	}

	var address string
	var portText string
	if strings.HasPrefix(value, "[") {
		end := strings.LastIndex(value, "]:")
		if end < 0 {
			return "", 0, false
		}
		address = value[1:end]
		portText = value[end+2:]
	} else {
		index := strings.LastIndex(value, ":")
		if index < 0 {
			return "", 0, false
		}
		address = value[:index]
		portText = value[index+1:]
	}

	if zone := strings.LastIndex(address, "%"); zone >= 0 {
		address = address[:zone]
	}
	address = strings.Trim(address, "[]")
	if address == "" || address == "*" {
		address = "0.0.0.0"
	}
	if portText == "" || portText == "*" {
		return "", 0, false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, false
	}
	return address, port, true
}

func parseProcNetAddress(value string, ipv6 bool) string {
	if !ipv6 {
		if len(value) != 8 {
			return ""
		}
		parsed, err := strconv.ParseUint(value, 16, 32)
		if err != nil {
			return ""
		}
		return net.IPv4(byte(parsed), byte(parsed>>8), byte(parsed>>16), byte(parsed>>24)).String()
	}

	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != net.IPv6len {
		return ""
	}
	for offset := 0; offset < len(raw); offset += 4 {
		raw[offset], raw[offset+3] = raw[offset+3], raw[offset]
		raw[offset+1], raw[offset+2] = raw[offset+2], raw[offset+1]
	}
	return net.IP(raw).String()
}

func newListeningExposure(address string, port int, evidenceRef string) Exposure {
	return Exposure{
		ExposureKind: "listening_port",
		Address:      address,
		Port:         port,
		Protocol:     "tcp",
		ServiceName:  commonServiceName(port),
		State:        "open",
		IsPublic:     isPublicListenAddress(address),
		EvidenceRef:  evidenceRef,
	}
}

func dedupeAndSortExposures(exposures []Exposure) []Exposure {
	seen := map[string]Exposure{}
	for _, exposure := range exposures {
		key := strings.Join([]string{
			exposure.Protocol,
			exposure.Address,
			strconv.Itoa(exposure.Port),
		}, "|")
		seen[key] = exposure
	}

	result := make([]Exposure, 0, len(seen))
	for _, exposure := range seen {
		result = append(result, exposure)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Port != result[j].Port {
			return result[i].Port < result[j].Port
		}
		return result[i].Address < result[j].Address
	})
	return result
}

func commonServiceName(port int) string {
	services := map[int]string{
		22:    "ssh",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		465:   "smtps",
		587:   "submission",
		993:   "imaps",
		995:   "pop3s",
		3306:  "mysql",
		5432:  "postgresql",
		6379:  "redis",
		8080:  "http-alt",
		8443:  "https-alt",
		27017: "mongodb",
	}
	return services[port]
}

func isPublicListenAddress(address string) bool {
	ip := net.ParseIP(address)
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return false
	}
	return ip.IsGlobalUnicast()
}

func parseOSReleaseFile(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}
	}
	return parseOSRelease(data)
}

func parseOSRelease(data []byte) map[string]string {
	values := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return values
}

func parsePackageRows(data []byte, source string) []PackageInfo {
	packages := []PackageInfo{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])
		sourcePackage := name
		if len(parts) > 2 && strings.TrimSpace(parts[2]) != "" {
			sourcePackage = strings.TrimSpace(parts[2])
		}
		if source == "rpm" {
			sourcePackage = sourcePackageFromRPM(sourcePackage, name)
		}
		architecture := ""
		if len(parts) > 3 {
			architecture = strings.TrimSpace(parts[3])
		}
		if name == "" {
			continue
		}
		packages = append(packages, PackageInfo{
			Name:          name,
			Version:       version,
			Source:        source,
			SourcePackage: sourcePackage,
			Architecture:  architecture,
		})
	}
	return packages
}

func packagesToComponents(packages []PackageInfo, platform PlatformInfo) []Component {
	components := make([]Component, 0, len(packages))
	for _, pkg := range packages {
		ecosystem := ""
		versionScheme := ""
		if pkg.Source == "dpkg" {
			ecosystem = "deb"
			versionScheme = "debian"
		} else if pkg.Source == "rpm" {
			ecosystem = "rpm"
			versionScheme = "rpm"
		}
		components = append(components, Component{
			ComponentName: pkg.Name,
			ComponentType: "package",
			Version:       pkg.Version,
			SourceType:    pkg.Source,
			Ecosystem:     ecosystem,
			Distro:        platform.OSFamily,
			DistroRelease: platform.OSVersion,
			SourcePackage: pkg.SourcePackage,
			BinaryPackage: pkg.Name,
			Architecture:  firstNonEmpty(pkg.Architecture, platform.Architecture),
			VersionScheme: versionScheme,
		})
	}
	return components
}

func sourcePackageFromRPM(sourceRPM string, fallback string) string {
	cleaned := strings.TrimSuffix(strings.TrimSpace(sourceRPM), ".src.rpm")
	if cleaned == "" || cleaned == "(none)" {
		return fallback
	}
	parts := strings.Split(cleaned, "-")
	for index, part := range parts {
		if index > 0 && len(part) > 0 && part[0] >= '0' && part[0] <= '9' {
			return strings.Join(parts[:index], "-")
		}
	}
	return fallback
}

func primaryIP() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, item := range interfaces {
		if item.Flags&net.FlagUp == 0 || item.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := item.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil || ip == nil || ip.To4() == nil {
				continue
			}
			return ip.String()
		}
	}
	return ""
}

func kernelVersion() string {
	if path, err := exec.LookPath("uname"); err == nil {
		out, err := exec.Command(path, "-r").Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}
