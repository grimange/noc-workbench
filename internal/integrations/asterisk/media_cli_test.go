package asterisk

import (
	"strings"
	"testing"
)

func TestMediaCLIBoundedUncorrelatedPrivacy(t *testing.T) {
	bundle := func(sip, pjsip string) []byte {
		return []byte("Asterisk 18.26.4-vici\nNW_MEDIA_sip\n" + sip + "\nNW_MEDIA_pjsip\n" + pjsip + "\nNW_MEDIA_END\n")
	}
	header := "Peer             Call ID      Duration Recv: Pack  Lost       (     %) Jitter Send: Pack  Lost       (     %) Jitter\n"
	sip := header + "192.0.2.1 secret-id 00:00:05 50 0 ( 0.00%) 0.0000 100K 3 ( 1.50%) 0.0000\n1 active SIP channels"
	pjsip := "...........Receive.........\n BridgeId ChannelId ........ UpTime.. Codec. Count Lost Pct Jitter Count Lost Pct Jitter RTT....\n=================\n abcdef01 secret-truncated 00:00:05 ulaw 50 0 0 0.000 60 1 1 0.000 0.125"
	obs, ds := MediaCLI(bundle(sip, pjsip))
	if len(ds) != 0 || len(obs) != 4 {
		t.Fatal(obs, ds)
	}
	for _, o := range obs {
		if strings.Contains(o.Value.Text, "secret") || strings.Contains(o.Value.Text, "192.0.2.1") {
			t.Fatal("CLI identity retained", o)
		}
	}
	obs, ds = MediaCLI(bundle(header+"0 active SIP channels", "No objects found."))
	if len(ds) != 0 || len(obs) != 2 {
		t.Fatal("empty", ds)
	}
	obs, ds = MediaCLI(bundle("No such command 'sip show channelstats'", "No objects found."))
	if len(ds) != 0 || !strings.Contains(obs[0].Value.Text, "unsupported") {
		t.Fatal("unsupported", ds)
	}
	for _, b := range [][]byte{bundle("permission denied", "No objects found."), bundle(header+"bad", "No objects found."), bundle(header+"0 active SIP channels", "BridgeId ChannelId"), bundle(header+"1 active SIP channels", "No objects found."), bundle(header+"0 active SIP channels", "bad"), bundle(header+"0 active SIP channels", strings.Repeat("x", 65536))} {
		if _, ds := MediaCLI(b); len(ds) == 0 {
			t.Fatal("malformed accepted")
		}
	}
}
