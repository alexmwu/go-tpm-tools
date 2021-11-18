package server

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/go-attestation/attest"
	pb "github.com/google/go-tpm-tools/proto/attest"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
)

var (
	newGrubKernelCmdlinePrefix = []byte("kernel_cmdline: ")
	oldGrubKernelCmdlinePrefix = []byte("grub_kernel_cmdline ")
	// See https://www.gnu.org/software/grub/manual/grub/grub.html#Measured-Boot.
	validPrefixes = [][]byte{[]byte("grub_cmd: "),
		newGrubKernelCmdlinePrefix,
		[]byte("module_cmdline: "),
		// Older style prefixes:
		// https://src.fedoraproject.org/rpms/grub2/blob/c789522f7cfa19a10cd716a1db24dab5499c6e5c/f/0224-Rework-TPM-measurements.patch
		oldGrubKernelCmdlinePrefix,
		[]byte("grub_cmd ")}
)

// Bootloader refers to the second-stage bootloader that loads and transfers
// execution to the OS kernel.
type Bootloader int

const (
	// UNSUPPORTED refers to a second-stage bootloader that is unused or of an
	// unsupported type.
	UNSUPPORTED Bootloader = iota
	// GRUB (https://www.gnu.org/software/grub/).
	GRUB
)

// ParseOpts configures the behavior of ParseMachineState.
type ParseOpts struct {
	// Which bootloader the instance uses. Pick UNSUPPORTED to skip this
	// parsing or for unsupported bootloaders (e.g., systemd).
	Loader Bootloader
	// Whether to parse out a dm-verity state
	ParseVerity bool
}

// ParseMachineState parses a raw event log and replays the parsed event
// log against the given PCR values. It returns the corresponding MachineState
// containing the events verified by particular PCR indexes/digests. An error is
// returned if the replay for any PCR index does not match the provided value.
//
// It is the caller's responsibility to ensure that the passed PCR values can be
// trusted. Users can establish trust in PCR values by either calling
// client.ReadPCRs() themselves or by verifying the values via a PCR quote.
func ParseMachineState(rawEventLog []byte, pcrs *tpmpb.PCRs, opts ParseOpts) (*pb.MachineState, error) {
	events, err := parseReplayHelper(rawEventLog, pcrs)
	if err != nil {
		return nil, err
	}
	// error is already checked in convertToAttestPcrs
	cryptoHash, _ := tpm2.Algorithm(pcrs.GetHash()).Hash()

	rawEvents := convertToPbEvents(cryptoHash, events)
	platform, err := getPlatformState(cryptoHash, rawEvents)
	if err != nil {
		// Eventually, we want to support a partial failure model.
		// The MachineState can contain empty {Platform,SecureBoot}States when
		// those individually fail parsing. The error will contain suberrors
		// for the fields in MachineState that failed parsing.
		//
		// For now, since the MachineState only comprises PlatformState, we
		// return an empty MachineState with empty platform state and the error.
		return &pb.MachineState{}, err
	}

	var grub *pb.GrubState
	var kernel *pb.LinuxKernelState
	if opts.Loader == GRUB {
		grub, err = getGrubState(cryptoHash, rawEvents)
		if err != nil {
			// TODO(wuale): replace with SecureBoot changes for GroupedError
			return &pb.MachineState{}, err
		}
		kernel, err = getLinuxKernelStateFromGRUB(grub, opts.ParseVerity)
		// TODO(wuale): replace with changes for GroupedError
		if err != nil {
			return &pb.MachineState{}, err
		}
	}

	return &pb.MachineState{
		Platform:    platform,
		RawEvents:   rawEvents,
		Hash:        pcrs.GetHash(),
		Grub:        grub,
		LinuxKernel: kernel,
	}, nil
}

func contains(set [][]byte, value []byte) bool {
	for _, setItem := range set {
		if bytes.Equal(value, setItem) {
			return true
		}
	}
	return false
}

func getPlatformState(hash crypto.Hash, events []*pb.Event) (*pb.PlatformState, error) {
	// We pre-compute the separator event hash, and check if the event type has
	// been modified. We only trust events that come before a valid separator.
	hasher := hash.New()
	// From the PC Client Firmware Profile spec, on the separator event:
	// The event field MUST contain the hex value 00000000h or FFFFFFFFh.
	separatorData := [][]byte{{0, 0, 0, 0}, {0xff, 0xff, 0xff, 0xff}}
	separatorDigests := make([][]byte, 0, len(separatorData))
	for _, value := range separatorData {
		hasher.Write(value)
		separatorDigests = append(separatorDigests, hasher.Sum(nil))
	}

	var versionString []byte
	var nonHostInfo []byte
	for _, event := range events {
		index := event.GetPcrIndex()
		if index != 0 {
			continue
		}
		evtType := event.GetUntrustedType()

		// Make sure we have a valid separator event, we check any event that
		// claims to be a Separator or "looks like" a separator to prevent
		// certain vulnerabilities in event parsing. For more info see:
		// https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md
		if (evtType == Separator) || contains(separatorDigests, event.GetDigest()) {
			if evtType != Separator {
				return nil, fmt.Errorf("PCR%d event contains separator data but non-separator type %d", index, evtType)
			}
			if !event.GetDigestVerified() {
				return nil, fmt.Errorf("unverified separator digest for PCR%d", index)
			}
			if !contains(separatorData, event.GetData()) {
				return nil, fmt.Errorf("invalid separator data for PCR%d", index)
			}
			// Don't trust any PCR0 events after the separator
			break
		}

		if evtType == SCRTMVersion {
			if !event.GetDigestVerified() {
				return nil, fmt.Errorf("invalid SCRTM version event for PCR%d", index)
			}
			versionString = event.GetData()
		}

		if evtType == NonhostInfo {
			if !event.GetDigestVerified() {
				return nil, fmt.Errorf("invalid Non-Host info event for PCR%d", index)
			}
			nonHostInfo = event.GetData()
		}
	}

	state := &pb.PlatformState{}
	if gceVersion, err := ConvertSCRTMVersionToGCEFirmwareVersion(versionString); err == nil {
		state.Firmware = &pb.PlatformState_GceVersion{GceVersion: gceVersion}
	} else {
		state.Firmware = &pb.PlatformState_ScrtmVersionId{ScrtmVersionId: versionString}
	}

	if tech, err := ParseGCENonHostInfo(nonHostInfo); err == nil {
		state.Technology = tech
	}

	return state, nil
}

// Separate helper function so we can use attest.ParseSecurebootState without
// needing to reparse the entire event log.
func parseReplayHelper(rawEventLog []byte, pcrs *tpmpb.PCRs) ([]attest.Event, error) {
	attestPcrs, err := convertToAttestPcrs(pcrs)
	if err != nil {
		return nil, fmt.Errorf("received bad PCR proto: %v", err)
	}
	eventLog, err := attest.ParseEventLog(rawEventLog)
	if err != nil {
		return nil, fmt.Errorf("failed to parse event log: %v", err)
	}
	events, err := eventLog.Verify(attestPcrs)
	if err != nil {
		return nil, fmt.Errorf("failed to replay event log: %v", err)
	}
	return events, nil
}

func convertToAttestPcrs(pcrProto *tpmpb.PCRs) ([]attest.PCR, error) {
	if len(pcrProto.GetPcrs()) == 0 {
		return nil, errors.New("no PCRs to convert")
	}
	hash := tpm2.Algorithm(pcrProto.GetHash())
	cryptoHash, err := hash.Hash()
	if err != nil {
		return nil, err
	}

	attestPcrs := make([]attest.PCR, 0, len(pcrProto.GetPcrs()))
	for index, digest := range pcrProto.GetPcrs() {
		attestPcrs = append(attestPcrs, attest.PCR{
			Index:     int(index),
			Digest:    digest,
			DigestAlg: cryptoHash,
		})
	}
	return attestPcrs, nil
}

func convertToPbEvents(hash crypto.Hash, events []attest.Event) []*pb.Event {
	pbEvents := make([]*pb.Event, len(events))
	for i, event := range events {
		hasher := hash.New()
		hasher.Write(event.Data)
		digest := hasher.Sum(nil)

		pbEvents[i] = &pb.Event{
			PcrIndex:       uint32(event.Index),
			UntrustedType:  uint32(event.Type),
			Data:           event.Data,
			Digest:         event.Digest,
			DigestVerified: bytes.Equal(digest, event.Digest),
		}
	}
	return pbEvents
}

func getGrubState(hash crypto.Hash, events []*pb.Event) (*pb.GrubState, error) {
	var files []*pb.GrubFile
	var commands []string
	for idx, event := range events {
		index := event.GetPcrIndex()
		if index != 8 && index != 9 {
			continue
		}

		if event.GetUntrustedType() != IPL {
			return nil, fmt.Errorf("invalid event type for PCR%d, expected EV_IPL", index)
		}

		if index == 9 {
			files = append(files, &pb.GrubFile{Digest: event.GetDigest(),
				UntrustedFilename: event.GetData()})
		} else if index == 8 {
			hasher := hash.New()
			suffixAt := -1
			rawData := event.GetData()
			for _, prefix := range validPrefixes {
				if bytes.HasPrefix(rawData, prefix) {
					suffixAt = len(prefix)
					break
				}
			}
			if suffixAt == -1 {
				return nil, fmt.Errorf("invalid prefix seen for PCR%d event: %s", index, rawData)
			}
			hasher.Write(rawData[suffixAt : len(rawData)-1])
			if !bytes.Equal(event.Digest, hasher.Sum(nil)) {
				// Older GRUBs measure "grub_cmd " with the null terminator.
				// However, "grub_kernel_cmdline " measurements also ignore the null terminator.
				hasher.Reset()
				hasher.Write(rawData[suffixAt:])
				if !bytes.Equal(event.Digest, hasher.Sum(nil)) {
					return nil, fmt.Errorf("invalid digest seen for GRUB event log in event %d: %s", idx, hex.EncodeToString(event.Digest))
				}
			}
			hasher.Reset()
			commands = append(commands, string(rawData))
		}
	}
	return &pb.GrubState{Files: files, Commands: commands}, nil
}

func getGrubKernelCmdlineSuffix(grubCmd []byte) int {
	for _, prefix := range [][]byte{oldGrubKernelCmdlinePrefix, newGrubKernelCmdlinePrefix} {
		if bytes.HasPrefix(grubCmd, prefix) {
			return len(prefix)
		}
	}
	return -1
}

// getDmVerityStateFromCmdline only supports the non-upstreamed ChromiumOS
// dm-verity style arguments for now.
// For example:
// dm=1 vroot none ro 1,0 4077568 verity payload=<uuid> hashtree=<uuid> hashstart=4077568 alg=sha256 root_hexdigest=<digest> salt=<digest>
// See:
// https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/verity/README.md
func getDmVerityStateFromCmdline(paramToVal map[string]string) (*pb.DmVerityState, error) {
	if dmLine, ok := paramToVal["dm"]; ok {
		dmArgs := parseArgs([]byte(dmLine))

		hashAlg, ok := dmArgs["alg"]
		if !ok {
			return nil, fmt.Errorf("algorithm not specified in dm-verity configuration")
		}
		if hashAlg != "sha256" {
			return nil, fmt.Errorf("invalid hash algorithm \"%v\" specified in dm-verity configuration: only sha256 is supported", hashAlg)
		}

		rootDigestStr, ok := dmArgs["root_hexdigest"]
		if !ok {
			return nil, fmt.Errorf("root digest not specified in dm-verity configuration")
		}
		rootDigestBytes, err := hex.DecodeString(rootDigestStr)
		if err != nil {
			return nil, fmt.Errorf("invalid hex specified for root digest in dm-verity configuration: %v", err)
		}

		saltStr, ok := dmArgs["salt"]
		if !ok {
			return nil, fmt.Errorf("salt not specified in dm-verity configuration")
		}
		saltBytes, err := hex.DecodeString(saltStr)
		if err != nil {
			return nil, fmt.Errorf("invalid hex specified for root digest in dm-verity configuration: %v", err)
		}

		return &pb.DmVerityState{HashAlg: tpmpb.HashAlgo_SHA256, RootDigest: rootDigestBytes, Salt: saltBytes}, nil
	}
	return nil, fmt.Errorf("supported dm-verity arg not found")
}

func getLinuxKernelStateFromGRUB(grub *pb.GrubState, parseVerity bool) (*pb.LinuxKernelState, error) {
	var cmdline string
	var err error
	var verity *pb.DmVerityState
	seen := false

	for _, command := range grub.GetCommands() {
		// GRUB config is always in UTF-8: https://www.gnu.org/software/grub/manual/grub/html_node/Internationalisation.html.
		cmdBytes := []byte(command)
		suffixAt := getGrubKernelCmdlineSuffix(cmdBytes)
		if suffixAt == -1 {
			continue
		}

		if seen {
			return nil, fmt.Errorf("more than one kernel commandline in GRUB commands")
		}
		seen = true
		cmdline = command[suffixAt:]

		if parseVerity {
			verity, err = getDmVerityStateFromCmdline(parseArgs(cmdBytes))
			if err != nil {
				return nil, err
			}
		}
	}

	return &pb.LinuxKernelState{CommandLine: cmdline, Verity: verity}, nil
}
