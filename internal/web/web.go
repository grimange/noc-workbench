// Package web serves the local operator interface. It never executes remote work.
package web

import (
	"context"
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"noc-workbench/internal/security"
	"noc-workbench/internal/store/postgres"
)

//go:embed templates/*.html static/*
var assets embed.FS
var pages = template.Must(template.ParseFS(assets, "templates/*.html"))

type Store interface {
	Ping(context.Context) error
	CreateSession(context.Context, postgres.Session) error
	Session(context.Context, string) (postgres.Session, error)
	DeleteSession(context.Context, string) error
	GetNote(context.Context) (string, error)
	SetNote(context.Context, string) error
}
type Options struct {
	BaseURL, PasswordHash string
	SessionTTL            time.Duration
	SecureCookie          bool
}
type Server struct {
	store    Store
	options  Options
	host     string
	mu       sync.Mutex
	window   time.Time
	attempts int
	busy     chan struct{}
	now      func() time.Time
}
type pageData struct{ CSRF, Label, Error string }

func New(store Store, options Options) http.Handler {
	u, err := url.Parse(options.BaseURL)
	if err != nil || u.Host == "" {
		panic("invalid web base URL")
	}
	s := &Server{store: store, options: options, host: u.Host, busy: make(chan struct{}, 1), now: time.Now}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("POST /settings", s.settings)
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		if options.SecureCookie {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if r.Host != s.host {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			if r.Header.Get("Origin") != options.BaseURL || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				http.Error(w, "invalid origin", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 8192)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (s *Server) cookie(w http.ResponseWriter, name, value string, expires time.Time) {
	maxAge := int(expires.Sub(s.now()).Seconds())
	if value == "" {
		maxAge = -1
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Expires: expires, MaxAge: maxAge, HttpOnly: true, Secure: s.options.SecureCookie, SameSite: http.SameSiteStrictMode})
}
func (s *Server) render(w http.ResponseWriter, name string, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pages.ExecuteTemplate(w, name, data)
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"unavailable"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	token := security.Token()
	s.cookie(w, "nw_login", token, s.now().Add(10*time.Minute))
	s.render(w, "login.html", pageData{CSRF: token})
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("nw_login")
	if err != nil || !security.Equal(c.Value, r.PostForm.Get("csrf")) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	s.mu.Lock()
	now := s.now()
	if now.Sub(s.window) >= time.Minute {
		s.window = now
		s.attempts = 0
	}
	s.attempts++
	allowed := s.attempts <= 10
	s.mu.Unlock()
	if !allowed {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "try again later", http.StatusTooManyRequests)
		return
	}
	select {
	case s.busy <- struct{}{}:
		defer func() { <-s.busy }()
	default:
		http.Error(w, "try again later", http.StatusTooManyRequests)
		return
	}
	password := r.PostForm.Get("password")
	if len(password) > 72 || bcrypt.CompareHashAndPassword([]byte(s.options.PasswordHash), []byte(password)) != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	// Revoke the previous browser session on reauthentication.
	if old, e := r.Cookie("nw_session"); e == nil {
		if e = s.store.DeleteSession(r.Context(), s.sessionKey(old.Value)); e != nil {
			http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	token := security.Token()
	session := postgres.Session{TokenHash: s.sessionKey(token), CSRFToken: security.Token(), ExpiresAt: now.Add(s.options.SessionTTL)}
	if err := s.store.CreateSession(r.Context(), session); err != nil {
		http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
		return
	}
	s.cookie(w, "nw_session", token, session.ExpiresAt)
	s.cookie(w, "nw_login", "", now.Add(-time.Hour))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (s *Server) session(w http.ResponseWriter, r *http.Request) (postgres.Session, bool) {
	c, err := r.Cookie("nw_session")
	if err != nil {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return postgres.Session{}, false
	}
	session, err := s.store.Session(r.Context(), s.sessionKey(c.Value))
	if err != nil {
		status := http.StatusServiceUnavailable
		if err == postgres.ErrNotFound {
			status = http.StatusUnauthorized
		}
		http.Error(w, http.StatusText(status), status)
		return postgres.Session{}, false
	}
	if !session.ExpiresAt.After(s.now()) {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return postgres.Session{}, false
	}
	return session, true
}
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("nw_session"); err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	session, ok := s.session(w, r)
	if !ok {
		return
	}
	label, err := s.store.GetNote(r.Context())
	if err != nil {
		http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
		return
	}
	s.render(w, "home.html", pageData{CSRF: session.CSRFToken, Label: label})
}
func (s *Server) mutation(w http.ResponseWriter, r *http.Request) (postgres.Session, bool) {
	session, ok := s.session(w, r)
	if !ok {
		return session, false
	}
	token := r.PostForm.Get("csrf")
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	if !security.Equal(session.CSRFToken, token) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return session, false
	}
	return session, true
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	session, ok := s.mutation(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteSession(r.Context(), session.TokenHash); err != nil {
		http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
		return
	}
	s.cookie(w, "nw_session", "", s.now().Add(-time.Hour))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	_, ok := s.mutation(w, r)
	if !ok {
		return
	}
	label := strings.TrimSpace(r.PostForm.Get("label"))
	if len(label) > 120 {
		http.Error(w, "label too long", http.StatusBadRequest)
		return
	}
	if err := s.store.SetNote(r.Context(), label); err != nil {
		http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Binding the lookup digest to the credential hash revokes old sessions on password rotation.
func (s *Server) sessionKey(token string) string {
	return security.Hash(token + s.options.PasswordHash)
}
