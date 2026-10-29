package asterisk

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"noc-workbench/internal/collection"
)

// CLI media rows intentionally omit channel/peer/Call-ID text: installed
// Asterisk truncates those identifiers, so no canonical join is justified.
type CLIStats struct {
	Source string `json:"source"`
	Status string `json:"status"`
	Rows   []CLIStatsRow
}
type CLIStatsRow struct {
	ReceivedPackets, ReceiveLost, ReceivePercent string
	SentPackets, TransmitLost, TransmitPercent   string
}

var sipMediaRow = regexp.MustCompile(`^\S+\s+\S+\s+\S+\s+(\d+K?)\s+(\d+K?)\s+\(\s*(\d+(?:\.\d+)?)%\)\s+\S+\s+(\d+K?)\s+(\d+K?)\s+\(\s*(\d+(?:\.\d+)?)%\)\s+\S+$`)
var cliCount = regexp.MustCompile(`^[0-9]{1,10}K?$`)
var cliPercent = regexp.MustCompile(`^[0-9]{1,3}(?:\.[0-9]{1,2})?$`)

// MediaCLI accepts complete bounded fixed command bundles, with independent
// source capability. Jitter/RTT CLI summaries are omitted: RTCP events provide
// the explicit stream/report direction and units required for those fields.
func MediaCLI(b []byte) ([]collection.Observation, []collection.Diagnostic) {
	if len(b) > 65536 {
		return bad("record_limit")
	}
	parts := strings.Split(string(b), "\nNW_MEDIA_")
	if len(parts) != 4 || strings.TrimSpace(parts[3]) != "END" {
		return bad("parse_error")
	}
	if _, code := frame([]byte(parts[0]), false); code != "" {
		return bad(code)
	}
	var obs []collection.Observation
	for i, source := range []string{"sip", "pjsip"} {
		prefix := source + "\n"
		if !strings.HasPrefix(parts[i+1], prefix) {
			return bad("parse_error")
		}
		text := strings.TrimSpace(strings.TrimPrefix(parts[i+1], prefix))
		s := CLIStats{Source: source, Status: "supported"}
		switch {
		case strings.HasPrefix(text, "No such command '"):
			s.Status = "unsupported"
		case source == "pjsip" && text == "No objects found.":
		default:
			lines := strings.Split(text, "\n")
			header := false
			end := false
			endCount := -1
			for _, line := range lines {
				f := strings.Fields(line)
				if len(f) == 0 {
					continue
				}
				if source == "sip" {
					if strings.HasPrefix(strings.TrimSpace(line), "Peer Call ID") || strings.HasPrefix(strings.TrimSpace(line), "Peer             Call ID") {
						header = true
						continue
					}
					if regexp.MustCompile(`^[0-9]+ active SIP channels$`).MatchString(strings.TrimSpace(line)) {
						end = true
						endCount, _ = strconv.Atoi(f[0])
						continue
					}
					m := sipMediaRow.FindStringSubmatch(strings.TrimSpace(line))
					if !header || end || m == nil {
						return bad("parse_error")
					}
					row := CLIStatsRow{ReceivedPackets: m[1], ReceiveLost: m[2], ReceivePercent: m[3], SentPackets: m[4], TransmitLost: m[5], TransmitPercent: m[6]}
					if !validCLIRow(row) {
						return bad("parse_error")
					}
					s.Rows = append(s.Rows, row)
				} else {
					if strings.Contains(line, "...........Receive") || strings.HasPrefix(strings.TrimSpace(line), "BridgeId ChannelId") || strings.HasPrefix(strings.TrimSpace(line), "=================") {
						header = true
						continue
					}
					if !header {
						return bad("parse_error")
					}
					if strings.HasSuffix(line, " direct media") || strings.HasSuffix(line, " no audio streams") || strings.HasSuffix(line, " not valid") {
						s.Status = "partial"
						continue
					}
					// BridgeId is blank when unbridged; parse numerical columns from the right.
					if len(f) < 12 {
						return bad("parse_error")
					}
					n := len(f)
					row := CLIStatsRow{ReceivedPackets: f[n-9], ReceiveLost: f[n-8], ReceivePercent: f[n-7], SentPackets: f[n-5], TransmitLost: f[n-4], TransmitPercent: f[n-3]}
					if !validCLIRow(row) {
						return bad("parse_error")
					}
					s.Rows = append(s.Rows, row)
				}
				if len(s.Rows) > 128 {
					return bad("record_limit")
				}
			}
			if !header || (source == "sip" && (!end || endCount != len(s.Rows))) || (source == "pjsip" && len(s.Rows) == 0 && s.Status != "partial") {
				return bad("parse_error")
			}
		}
		// Separate ordinal rows bound individual values and discard source identifiers.
		rows := s.Rows
		s.Rows = nil
		v, _ := json.Marshal(s)
		obs = append(obs, collection.Observation{Key: "asterisk.media.cli", Resource: source, Unit: "text", Value: collection.Text(string(v))})
		for j, row := range rows {
			v, _ = json.Marshal(row)
			obs = append(obs, collection.Observation{Key: "asterisk.media.cli", Resource: fmt.Sprintf("%s/%03d", source, j), Unit: "text", Value: collection.Text(string(v))})
		}
	}
	return obs, nil
}
func validCLIRow(r CLIStatsRow) bool {
	return cliCount.MatchString(r.ReceivedPackets) && cliCount.MatchString(r.ReceiveLost) && cliCount.MatchString(r.SentPackets) && cliCount.MatchString(r.TransmitLost) && cliPercent.MatchString(r.ReceivePercent) && cliPercent.MatchString(r.TransmitPercent)
}

type CLIStatsView struct {
	At      time.Time
	Outcome string
	Current bool
	Sources []CLIStats
}
