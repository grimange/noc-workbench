// Package app owns configuration and the application lifecycle.
package app

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Listen         string
	BaseURL        string
	DatabaseURL    string
	PasswordHash   string
	SessionTTL     time.Duration
	StartupTimeout time.Duration
	SecureCookie   bool
}

// Load reads environment configuration without logging values. HTTP listeners and
// database connections stay on loopback; an explicit HTTPS origin may name a proxy.
func Load() (Config, error) {
	c := Config{
		Listen:       value("NOC_LISTEN", "127.0.0.1:8080"),
		BaseURL:      value("NOC_BASE_URL", "http://127.0.0.1:8080"),
		DatabaseURL:  os.Getenv("NOC_DATABASE_URL"),
		PasswordHash: os.Getenv("NOC_PASSWORD_HASH"),
	}
	var err error
	c.SessionTTL, err = time.ParseDuration(value("NOC_SESSION_TTL", "8h"))
	if err != nil || c.SessionTTL < time.Minute || c.SessionTTL > 24*time.Hour {
		return Config{}, errors.New("NOC_SESSION_TTL must be between 1m and 24h")
	}
	c.StartupTimeout, err = time.ParseDuration(value("NOC_STARTUP_TIMEOUT", "10s"))
	if err != nil || c.StartupTimeout < time.Second || c.StartupTimeout > time.Minute {
		return Config{}, errors.New("NOC_STARTUP_TIMEOUT must be between 1s and 60s")
	}
	c.SecureCookie = strings.HasPrefix(c.BaseURL, "https://")
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate also protects callers constructing Config directly.
func (c Config) Validate() error {
	if !loopbackAddress(c.Listen) {
		return errors.New("NOC_LISTEN must be a literal loopback IP and port")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.String() != c.BaseURL || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Path != "" || u.RawPath != "" || !validOrigin(u, c.Listen) {
		return errors.New("NOC_BASE_URL must match the loopback HTTP listener or name a canonical HTTPS proxy origin")
	}
	u, err = url.Parse(c.DatabaseURL)
	if err != nil || u == nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || !loopbackAddress(u.Host) || u.User == nil || u.User.Username() == "" || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || len(u.Path) < 2 || strings.Contains(u.Path[1:], "/") {
		return errors.New("NOC_DATABASE_URL must name a database at a literal loopback IP and port")
	}
	password, ok := u.User.Password()
	if !ok || password == "" {
		return errors.New("NOC_DATABASE_URL requires an explicit database password")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(query) != 1 || len(query["sslmode"]) != 1 {
		return errors.New("NOC_DATABASE_URL requires only an explicit sslmode query parameter")
	}
	switch query.Get("sslmode") {
	case "disable", "require", "verify-full":
	default:
		return errors.New("NOC_DATABASE_URL sslmode must be disable, require or verify-full")
	}
	cost, err := bcrypt.Cost([]byte(c.PasswordHash))
	if err != nil || cost < 10 || cost > 14 {
		return errors.New("NOC_PASSWORD_HASH must be a bcrypt hash with cost 10 through 14")
	}
	// Cost checks only parse the header. Reject malformed hash bodies as well.
	if err := bcrypt.CompareHashAndPassword([]byte(c.PasswordHash), []byte("configuration-validation")); err != nil && !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return errors.New("NOC_PASSWORD_HASH must be a valid bcrypt hash")
	}
	if c.SessionTTL < time.Minute || c.SessionTTL > 24*time.Hour || c.StartupTimeout < time.Second || c.StartupTimeout > time.Minute {
		return errors.New("session or startup duration outside supported bounds")
	}
	if c.SecureCookie != strings.HasPrefix(c.BaseURL, "https://") {
		return errors.New("secure cookie mode must match the configured origin scheme")
	}
	return nil
}

func validOrigin(u *url.URL, listen string) bool {
	if u.Scheme == "http" {
		return u.Host == listen && u.Port() != "80"
	}
	if u.Scheme != "https" || u.Host == listen || u.Host == "" {
		return false
	}
	// Browsers omit the default HTTPS port from Origin. Reject noncanonical
	// spellings rather than accepting a configuration which will reject its users.
	if port := u.Port(); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 || port != strconv.Itoa(p) || p == 443 {
			return false
		}
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		canonical := ip.String()
		if strings.Contains(canonical, ":") {
			canonical = "[" + canonical + "]"
		}
		if u.Port() != "" {
			canonical += ":" + u.Port()
		}
		return u.Host == canonical
	}
	canonical := host
	if u.Port() != "" {
		canonical += ":" + u.Port()
	}
	if u.Host != canonical || strings.Trim(host, "0123456789.") == "" {
		return false
	}
	// Require a fully qualified ASCII DNS name, without trailing dot or user-
	// supplied normalization. Host and Origin checks use this exact authority.
	if len(host) > 253 || !strings.Contains(host, ".") || host != strings.ToLower(host) {
		return false
	}
	labels := strings.Split(host, ".")
	last := labels[len(labels)-1]
	// Browsers interpret numeric final labels as IPv4, including hexadecimal
	// forms, rather than DNS. Require the canonical IP branch above for those.
	if strings.Trim(last, "0123456789") == "" || strings.HasPrefix(last, "0x") && strings.Trim(last[2:], "0123456789abcdef") == "" {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

func value(key, fallback string) string {
	if s := os.Getenv(key); s != "" {
		return s
	}
	return fallback
}

func loopbackAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	p, err := strconv.Atoi(port)
	// Canonical spelling keeps browser Host/Origin serialization predictable.
	return err == nil && p > 0 && p <= 65535 && port == strconv.Itoa(p) && ip != nil && host == ip.String() && ip.IsLoopback()
}
