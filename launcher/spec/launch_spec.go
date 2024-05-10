// Package spec contains definition of some basic container launch specs needed to
// launch a container, provided by the operator.
package spec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"cloud.google.com/go/compute/metadata"

	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/launcher/internal/experiments"
	"github.com/google/go-tpm-tools/verifier/util"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const MaxInt64 = int(^uint64(0) >> 1)

// RestartPolicy is the enum for the container restart policy.
type RestartPolicy string

func (p RestartPolicy) isValid() error {
	switch p {
	case Always, OnFailure, Never:
		return nil
	}
	return fmt.Errorf("invalid restart policy: %s", p)
}

// Restart Policy enum values.
const (
	Always    RestartPolicy = "Always"
	OnFailure RestartPolicy = "OnFailure"
	Never     RestartPolicy = "Never"
)

// LogRedirectLocation specifies the workload logging redirect location.
type LogRedirectLocation string

func (l LogRedirectLocation) isValid() error {
	switch l {
	case Everywhere, CloudLogging, Serial, Nowhere:
		return nil
	}
	return fmt.Errorf("invalid logging redirect location %s, expect one of %s", l,
		[]LogRedirectLocation{Everywhere, CloudLogging, Serial, Nowhere})
}

func (l LogRedirectLocation) enabled() bool {
	return l != Nowhere
}

// LogRedirectLocation acceptable values.
const (
	Everywhere   LogRedirectLocation = "true"
	CloudLogging LogRedirectLocation = "cloud_logging"
	Serial       LogRedirectLocation = "serial"
	Nowhere      LogRedirectLocation = "false"
)

// Metadata variable names.
const (
	imageRefKey                = "tee-image-reference"
	signedImageRepos           = "tee-signed-image-repos"
	restartPolicyKey           = "tee-restart-policy"
	cmdKey                     = "tee-cmd"
	envKeyPrefix               = "tee-env-"
	impersonateServiceAccounts = "tee-impersonate-service-accounts"
	attestationServiceAddrKey  = "tee-attestation-service-endpoint"
	logRedirectKey             = "tee-container-log-redirect"
	memoryMonitoringEnable     = "tee-monitoring-memory-enable"
	devShmSizeKey              = "tee-dev-shm-size"
	mountKey                   = "tee-mount"
)

const (
	instanceAttributesQuery = "instance/attributes/?recursive=true"
)

const (
	mountTypeKey        = "type"
	mountSourceKey      = "source"
	mountDestinationKey = "destination"
	mountTypeTmpfs      = "tmpfs"
	mountTypeBind       = "bind"
	mountTypeGCEDisk    = "gcedisk"
)

// https://cloud.google.com/compute/docs/disks/set-persistent-device-name-in-linux-vm
var errImageRefNotSpecified = fmt.Errorf("%s is not specified in the custom metadata", imageRefKey)

// EnvVar represent a single environment variable key/value pair.
type EnvVar struct {
	Name  string
	Value string
}

// LaunchSpec contains specification set by the operator who wants to
// launch a container.
type LaunchSpec struct {
	// MDS-based values.
	ImageRef                   string
	SignedImageRepos           []string
	RestartPolicy              RestartPolicy
	Cmd                        []string
	Envs                       []EnvVar
	AttestationServiceAddr     string
	ImpersonateServiceAccounts []string
	ProjectID                  string
	Region                     string
	Hardened                   bool
	MemoryMonitoringEnabled    bool
	LogRedirect                LogRedirectLocation
	Mounts                     []specs.Mount
	DevShmSize                 int64
	Experiments                experiments.Experiments
}

// UnmarshalJSON unmarshals an instance attributes list in JSON format from the metadata
// server set by an operator to a LaunchSpec.
func (s *LaunchSpec) UnmarshalJSON(b []byte) error {
	var unmarshaledMap map[string]string
	if err := json.Unmarshal(b, &unmarshaledMap); err != nil {
		return err
	}

	s.ImageRef = unmarshaledMap[imageRefKey]
	if s.ImageRef == "" {
		return errImageRefNotSpecified
	}

	s.RestartPolicy = RestartPolicy(unmarshaledMap[restartPolicyKey])
	// Set the default restart policy to "Never" for now.
	if s.RestartPolicy == "" {
		s.RestartPolicy = Never
	}
	if err := s.RestartPolicy.isValid(); err != nil {
		return err
	}

	if val, ok := unmarshaledMap[impersonateServiceAccounts]; ok && val != "" {
		impersonateAccounts := strings.Split(val, ",")
		s.ImpersonateServiceAccounts = append(s.ImpersonateServiceAccounts, impersonateAccounts...)
	}

	if val, ok := unmarshaledMap[signedImageRepos]; ok && val != "" {
		imageRepos := strings.Split(val, ",")
		s.SignedImageRepos = append(s.SignedImageRepos, imageRepos...)
	}

	if val, ok := unmarshaledMap[memoryMonitoringEnable]; ok && val != "" {
		if boolValue, err := strconv.ParseBool(val); err == nil {
			s.MemoryMonitoringEnabled = boolValue
		}
	}

	// Populate cmd override.
	if val, ok := unmarshaledMap[cmdKey]; ok && val != "" {
		if err := json.Unmarshal([]byte(val), &s.Cmd); err != nil {
			return err
		}
	}

	// Populate all env vars.
	for k, v := range unmarshaledMap {
		if strings.HasPrefix(k, envKeyPrefix) {
			s.Envs = append(s.Envs, EnvVar{strings.TrimPrefix(k, envKeyPrefix), v})
		}
	}

	s.LogRedirect = LogRedirectLocation(unmarshaledMap[logRedirectKey])
	// Default log redirect location is Nowhere ("false").
	if s.LogRedirect == "" {
		s.LogRedirect = Nowhere
	}
	if err := s.LogRedirect.isValid(); err != nil {
		return err
	}

	s.AttestationServiceAddr = unmarshaledMap[attestationServiceAddrKey]

	// Populate /dev/shm size override.
	if val, ok := unmarshaledMap[devShmSizeKey]; ok && val != "" {
		size, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to convert %v into uint64, got: %v", devShmSizeKey, val)
		}
		freeMem, err := getLinuxFreeMem()
		if err != nil {
			return err
		}
		if size > freeMem {
			return fmt.Errorf("got a /dev/shm size (%v) larger than free memory (%v)", size, freeMem)
		}
		if size > uint64(MaxInt64) {
			return fmt.Errorf("got a size greater than max int64: %v", val)
		}
		s.DevShmSize = int64(size)
	}

	// Populate mount override.
	// https://cloud.google.com/compute/docs/disks/set-persistent-device-name-in-linux-vm
	// https://cloud.google.com/compute/docs/disks/add-local-ssd
	if val, ok := unmarshaledMap[mountKey]; ok && val != "" {
		mounts := strings.Split(val, ";")
		for _, mount := range mounts {
			specMnt, err := processMount(mount)
			if err != nil {
				return err
			}
			s.Mounts = append(s.Mounts, specMnt)
		}
	}

	return nil
}

// GetLaunchSpec takes in a metadata server client, reads and parse operator's
// input to the GCE instance custom metadata and return a LaunchSpec.
// ImageRef (tee-image-reference) is required, will return an error if
// ImageRef is not presented in the metadata.
func GetLaunchSpec(ctx context.Context, client *metadata.Client) (LaunchSpec, error) {
	data, err := client.GetWithContext(ctx, instanceAttributesQuery)
	if err != nil {
		return LaunchSpec{}, err
	}

	spec := &LaunchSpec{}
	if err := spec.UnmarshalJSON([]byte(data)); err != nil {
		return LaunchSpec{}, err
	}

	spec.ProjectID, err = client.ProjectID()
	if err != nil {
		return LaunchSpec{}, fmt.Errorf("failed to retrieve projectID from MDS: %v", err)
	}

	spec.Region, err = util.GetRegion(client)
	if err != nil {
		return LaunchSpec{}, err
	}

	kernelCmd, err := readCmdline()
	if err != nil {
		return LaunchSpec{}, err
	}
	spec.Hardened = isHardened(kernelCmd)

	return *spec, nil
}

func isHardened(kernelCmd string) bool {
	for _, arg := range strings.Fields(kernelCmd) {
		if arg == "confidential-space.hardened=true" {
			return true
		}
	}
	return false
}

func processMount(singleMount string) (specs.Mount, error) {
	mntConfig := make(map[string]string)
	var mntType string
	mountOpts := strings.Split(singleMount, ",")
	for _, mountOpt := range mountOpts {
		name, val, err := cel.ParseEnvVar(mountOpt)
		if err != nil {
			return specs.Mount{}, fmt.Errorf("failed to parse mount option: %w", err)
		}
		switch name {
		case mountTypeKey:
			mntType = val
		case mountSourceKey:
		case mountDestinationKey:
		default:
			return specs.Mount{}, fmt.Errorf("found unknown mount option: %v, expect keys of [%v, %v, %v]", mountOpt, mountTypeKey, mountSourceKey, mountDestinationKey)
		}
		mntConfig[name] = val
	}

	switch mntType {
	case mountTypeTmpfs:
		mntDst, ok := mntConfig[mountDestinationKey]
		if !ok {
			return specs.Mount{}, fmt.Errorf("found bad tmpfs mount config %v, expect exact keys [%v, %v]", mountOpts, mountTypeKey, mountDestinationKey)
		}
		return specs.Mount{Type: mountTypeTmpfs, Destination: mntDst}, nil
	case mountTypeGCEDisk:
		mntSrc, okSrc := mntConfig[mountSourceKey]
		mntDst, okDst := mntConfig[mountDestinationKey]
		if !(okSrc && okDst) {
			return specs.Mount{}, fmt.Errorf("found bad bind mount config %v, expect exact keys [%v, %v, %v]", mountOpts, mountTypeKey, mountSourceKey, mountDestinationKey)
		}
		// TODO: check valid sources with prefix /dev/disk/by-id/google-*.
		// overwrite the source with integrity fs .sh
		return specs.Mount{Type: mountTypeBind, Source: mntSrc, Destination: mntDst, Options: []string{"rbind", "rw"}}, nil
	default:
		return specs.Mount{}, fmt.Errorf("found unknown or unspecified mount type: %v, expect one of types [%v, %v]", mountOpts, mountTypeTmpfs, mountTypeGCEDisk)
	}
}

func getLinuxFreeMem() (uint64, error) {
	meminfo, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, fmt.Errorf("failed to read /proc/meminfo: %w", err)
	}
	for _, memtype := range strings.Split(string(meminfo), "\n") {
		if !strings.Contains(memtype, "MemFree") {
			continue
		}
		split := strings.Fields(memtype)
		if len(split) != 3 {
			return 0, fmt.Errorf("found invalid MemInfo entry: got: %v, expected format: MemFree:        <amount> kB", memtype)
		}
		freeMem, err := strconv.ParseUint(split[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to convert MemFree to uint64: %v", memtype)
		}
		return freeMem, nil
	}
	return 0, fmt.Errorf("failed to find MemFree in /proc/meminfo: %v", string(meminfo))
}

func readCmdline() (string, error) {
	kernelCmd, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}
	return string(kernelCmd), nil
}
