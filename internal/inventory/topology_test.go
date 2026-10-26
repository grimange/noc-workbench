package inventory

import "testing"

func TestEndpointValidation(t *testing.T) {
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "synthetic.example.invalid", "localhost"} {
		if !ValidEndpointHost(host) {
			t.Errorf("valid host %s", host)
		}
	}
	for _, host := range []string{"", "192.0.2.999", "123", "https://example.invalid", "name/path", "host:22", "-bad.invalid", "bad_.invalid", "[2001:db8::1]", "fe80::1%eth0", "a..invalid"} {
		if ValidEndpointHost(host) {
			t.Errorf("invalid host %s", host)
		}
	}
	env := "00000000-0000-4000-8000-000000000001"
	for _, port := range []int{0, -1, 65536} {
		if _, err := ValidateEndpoint(Endpoint{EnvironmentID: env, AssetID: env, Host: "192.0.2.1", Protocol: "ssh", Port: port, Status: "active"}); err == nil {
			t.Error("invalid port")
		}
	}
	if _, err := ValidateAsset(Asset{EnvironmentID: env, Name: "Host", Kind: "service", Lifecycle: "active"}); err == nil {
		t.Error("service collapsed into asset")
	}
	if _, err := ValidateCluster(Cluster{EnvironmentID: env, Name: "\x00", Lifecycle: "active"}); err == nil {
		t.Error("control character")
	}
}
