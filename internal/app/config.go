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

// Load reads environment configuration without logging values. M0 deliberately
// accepts only literal loopback endpoints; remote deployment is a later feature.
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || !loopbackAddress(u.Host) || (u.Scheme == "http" && (u.Host != c.Listen || u.Port() == "80")) || (u.Scheme == "https" && (u.Host == c.Listen || u.Port() == "443")) || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Path != "" || u.RawPath != "" {
		return errors.New("NOC_BASE_URL must match the HTTP listener or name a separate literal loopback HTTPS proxy origin")
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
