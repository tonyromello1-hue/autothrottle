package web

import (
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"rsc.io/qr"

	"github.com/JaiMistry/autothrottle/internal/backup"
	"github.com/JaiMistry/autothrottle/internal/db"
	"github.com/JaiMistry/autothrottle/internal/packitup"
)

// backupPageData is the Backup page: what the setup holds, and either a
// fresh set of codes or a restore's outcome.
type backupPageData struct {
	pageData
	Current  backup.Summary
	HasSetup bool

	// After Pack.
	Codes    []backupCode
	CodeText string // the codes, one per line, for copying or the file
	FileHref template.URL
	FileName string
	Meta     packitup.Meta
	Made     string
	Packed   backup.Summary
	Locked   bool

	// Restore.
	RestoreCodes string // kept across a retry, so a PIN prompt doesn't lose the scan
	NeedPIN      bool
	RestoreError string
	Restored     *backup.Summary
	// NeedCredentialsNote names the connections a restore without
	// secrets switched off.
	NeedCredentialsNote string
	RestoredMeta        packitup.Meta
	Notes               []string
}

func (s *Server) backupData(r *http.Request) (backupPageData, error) {
	data := backupPageData{pageData: s.page(r, "Backup", "backup")}
	setup, err := backup.Collect(s.db, s.encryptionKey, false)
	if err != nil {
		return data, err
	}
	data.Current = setup.Summary()
	data.HasSetup = data.Current.Servers+data.Current.Clients > 0
	return data, nil
}

func (s *Server) backupPage(w http.ResponseWriter, r *http.Request) {
	data, err := s.backupData(r)
	if err != nil {
		slog.Error("reading setup for backup", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, "backup", data)
}

func (s *Server) packBackup(w http.ResponseWriter, r *http.Request) {
	data, err := s.backupData(r)
	if err != nil {
		slog.Error("reading setup for backup", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	pin := strings.TrimSpace(r.FormValue("pin"))
	if pin != strings.TrimSpace(r.FormValue("pin_confirm")) {
		data.Error = "The two PINs don't match. Enter the same PIN twice."
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, "backup", data)
		return
	}
	codes, meta, sum, err := backup.Pack(s.db, s.encryptionKey, pin, time.Now())
	if errors.Is(err, packitup.ErrPINTooShort) {
		data.Error = fmt.Sprintf("Use a PIN of at least %d characters, or leave it empty for a backup without passwords and tokens.", packitup.MinPINLength)
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, "backup", data)
		return
	}
	if err != nil {
		slog.Error("packing backup", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for _, c := range codes {
		svg, err := qrSVG(c)
		if err != nil {
			slog.Error("drawing backup code", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		data.Codes = append(data.Codes, backupCode{SVG: svg, Part: len(data.Codes) + 1})
	}
	data.CodeText = strings.Join(codes, "\n")
	// A data: URL the handler built itself, from codes it just made.
	data.FileHref = template.URL("data:text/plain;charset=utf-8," + url.PathEscape(data.CodeText+"\n")) //nolint:gosec
	data.FileName = fmt.Sprintf("autothrottle-%s-v%d.atpack", strings.ToLower(meta.Workspace), meta.Version)
	data.Meta, data.Packed, data.Locked = meta, sum, pin != ""
	data.Made = meta.Created.In(time.Local).Format("Jan 2, 2006 3:04 PM")
	slog.Info("backup packed", "version", meta.Version, "codes", len(codes), "locked", data.Locked)
	s.render(w, "backup", data)
}

func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request) {
	data, err := s.backupData(r)
	if err != nil {
		slog.Error("reading setup for restore", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data.RestoreCodes = r.FormValue("codes")
	// Every rejection is a 422: the one non-2xx status app.js swaps in.
	fail := func(message string) {
		data.RestoreError = message
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, "backup", data)
	}

	set, err := packitup.Gather(backup.App, strings.Split(data.RestoreCodes, "\n"))
	if err != nil {
		fail(restoreMessage(err))
		return
	}
	data.Notes = set.Notes
	pin := strings.TrimSpace(r.FormValue("pin"))
	if set.Encrypted && pin == "" {
		data.NeedPIN = true
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, "backup", data)
		return
	}
	setup, err := backup.Open(set, pin)
	if err != nil {
		data.NeedPIN = errors.Is(err, packitup.ErrWrongPIN)
		fail(restoreMessage(err))
		return
	}
	if data.HasSetup && r.FormValue("replace") != "on" {
		data.NeedPIN = set.Encrypted
		fail("This AutoThrottle already has connections. Tick “Replace my current setup” to swap them for the backup's.")
		return
	}

	sum, err := backup.Apply(s.db, s.encryptionKey, setup, set.Meta)
	if err != nil {
		slog.Error("restoring backup", "error", err)
		fail("The backup read correctly but couldn't be saved. Nothing was changed.")
		return
	}
	s.applyConfigChange(true)
	msg := fmt.Sprintf("Restored a Pack It Up backup (v%d): %s, %s",
		set.Meta.Version, count(sum.Servers, "media server", "media servers"), count(sum.Clients, "download client", "download clients"))
	if err := s.db.InsertEvent(db.Event{Level: "info", Message: msg}); err != nil {
		slog.Error("logging restore", "error", err)
	}
	slog.Info("backup restored", "version", set.Meta.Version, "servers", sum.Servers, "clients", sum.Clients)

	data, err = s.backupData(r)
	if err != nil {
		slog.Error("reading setup after restore", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data.Restored, data.RestoredMeta, data.Notes = &sum, set.Meta, set.Notes
	if len(sum.NeedCredentials) > 0 {
		data.NeedCredentialsNote = "This backup was made without a PIN, so it carried no secrets. " +
			strings.Join(sum.NeedCredentials, ", ") +
			" came back switched off: open each on the Configuration page, enter its token or password, and switch it on."
	}
	s.render(w, "backup", data)
}

// restoreMessage says what went wrong and what to do about it.
func restoreMessage(err error) string {
	var missing *packitup.MissingPartsError
	var corrupt *packitup.CorruptPartError
	switch {
	case errors.As(err, &missing), errors.As(err, &corrupt):
		return capitalize(err.Error()) + "."
	case errors.Is(err, packitup.ErrNoCodes):
		return "No AutoThrottle backup codes were found. Add a screenshot of the Backup page's codes, or paste them."
	case errors.Is(err, packitup.ErrWrongPIN):
		return "That PIN didn't unlock this backup. Check it and try again."
	case errors.Is(err, packitup.ErrMixedWorkspace):
		return "These codes are from two different setups. Add the screenshots of one backup only."
	case errors.Is(err, packitup.ErrUnreadable):
		return "One code didn't read cleanly. Capture it again, a little larger if you can."
	case errors.Is(err, backup.ErrNewerFormat):
		return "This backup was made by a newer AutoThrottle. Update this one, then restore."
	default:
		return "The backup didn't verify. One code may have misread; capture it again."
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

type backupCode struct {
	SVG  template.HTML
	Part int
}

// qrSVG draws a code with whole modules and a four-module quiet zone, in
// fixed dark on light whatever the theme: an inverted code confuses some
// scanners, and screenshots get recompressed.
func qrSVG(text string) (template.HTML, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	const quiet = 4
	n := code.Size + 2*quiet
	var path strings.Builder
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			if code.Black(x, y) {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	return template.HTML(fmt.Sprintf( //nolint:gosec // built here from module coordinates only
		`<svg class="at-piu-qr" viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" aria-label="Pack It Up code"><rect width="%d" height="%d" fill="#ffffff"/><path fill="#0a0f1a" d="%s"/></svg>`,
		n, n, n, n, path.String())), nil
}
