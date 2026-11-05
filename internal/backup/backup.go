// Package backup turns AutoThrottle's setup (media servers, download
// clients, mappings and the pause switch) into a Pack It Up backup, and
// restores one. It is the only code that knows both what a setup holds
// and how Pack It Up carries it.
//
// The event log, history and live sessions stay out: they rebuild
// themselves. So does the encryption key: tokens and passwords are opened
// with this install's key, carried only under the backup's PIN, and
// sealed again with the restoring install's own key.
package backup

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/JaiMistry/autothrottle/internal/credential"
	"github.com/JaiMistry/autothrottle/internal/crypto"
	"github.com/JaiMistry/autothrottle/internal/db"
	"github.com/JaiMistry/autothrottle/internal/packitup"
)

// App is AutoThrottle's id in every code.
const App = "AUTOTHROTTLE"

const (
	keyWorkspace = "packitup.workspace"
	keyVersion   = "packitup.version"
	formatV1     = 1
)

// The settings a backup carries; anything else in the table is this
// install's own.
var carriedSettings = []string{"throttle.paused", "throttle.paused_since"}

// Setup is the backup's content. Keys are short: every byte is a module
// in a QR code.
type Setup struct {
	V        int               `json:"v"`
	Servers  []Server          `json:"s"`
	Clients  []Client          `json:"c"`
	Mappings []Mapping         `json:"m"`
	Settings map[string]string `json:"o,omitempty"`
}

type Server struct {
	Name      string `json:"n"`
	Type      string `json:"t"`
	URL       string `json:"u"`
	Token     string `json:"k,omitempty"`
	SkipLocal bool   `json:"l,omitempty"`
	Enabled   bool   `json:"e,omitempty"`
	// Withheld marks a token left out of a backup made without a PIN.
	Withheld bool `json:"w,omitempty"`
}

type Client struct {
	Name          string `json:"n"`
	Type          string `json:"t"`
	URL           string `json:"u"`
	Username      string `json:"un,omitempty"`
	Password      string `json:"pw,omitempty"`
	DefaultDown   int64  `json:"dd,omitempty"`
	DefaultUp     int64  `json:"du,omitempty"`
	ThrottledDown int64  `json:"td,omitempty"`
	ThrottledUp   int64  `json:"tu,omitempty"`
	Enabled       bool   `json:"e,omitempty"`
	Withheld      bool   `json:"w,omitempty"`
}

// Mapping pairs Servers[S] with Clients[C].
type Mapping struct {
	S  int  `json:"s"`
	C  int  `json:"c"`
	On bool `json:"on,omitempty"`
}

// Collect reads the setup. Without credentials, tokens and passwords are
// left out and the rows that had one are marked Withheld.
func Collect(d *db.DB, key []byte, withCredentials bool) (Setup, error) {
	setup := Setup{V: formatV1, Settings: map[string]string{}}
	servers, err := d.ListMediaServers()
	if err != nil {
		return Setup{}, err
	}
	serverAt := map[int64]int{}
	for _, ms := range servers {
		s := Server{Name: ms.Name, Type: ms.Type, URL: ms.URL, SkipLocal: ms.SkipLocalPlayback, Enabled: ms.Enabled}
		if ms.CredentialEncrypted != "" {
			if withCredentials {
				if s.Token, err = crypto.Decrypt(key, ms.CredentialEncrypted); err != nil {
					return Setup{}, fmt.Errorf("opening the token for %q: %w", ms.Name, err)
				}
			} else {
				s.Withheld = true
			}
		}
		serverAt[ms.ID] = len(setup.Servers)
		setup.Servers = append(setup.Servers, s)
	}

	downloaders, err := d.ListDownloaders()
	if err != nil {
		return Setup{}, err
	}
	clientAt := map[int64]int{}
	for _, dl := range downloaders {
		c := Client{Name: dl.Name, Type: dl.Type, URL: dl.URL,
			DefaultDown: dl.DefaultDownloadLimit, DefaultUp: dl.DefaultUploadLimit,
			ThrottledDown: dl.BackupDownloadLimit, ThrottledUp: dl.BackupUploadLimit, Enabled: dl.Enabled}
		if dl.CredentialEncrypted.Valid && dl.CredentialEncrypted.String != "" {
			if withCredentials {
				if c.Username, c.Password, err = credential.Decrypt(key, dl.CredentialEncrypted.String); err != nil {
					return Setup{}, fmt.Errorf("opening the login for %q: %w", dl.Name, err)
				}
			} else {
				c.Withheld = true
			}
		}
		clientAt[dl.ID] = len(setup.Clients)
		setup.Clients = append(setup.Clients, c)
	}

	mappings, err := d.ListMappings()
	if err != nil {
		return Setup{}, err
	}
	for _, m := range mappings {
		s, ok1 := serverAt[m.MediaServerID]
		c, ok2 := clientAt[m.DownloaderID]
		if ok1 && ok2 {
			setup.Mappings = append(setup.Mappings, Mapping{S: s, C: c, On: m.Enabled})
		}
	}

	for _, k := range carriedSettings {
		v, ok, err := d.GetSetting(k)
		if err != nil {
			return Setup{}, err
		}
		if ok {
			setup.Settings[k] = v
		}
	}
	return setup, nil
}

// Summary describes a setup, for the page that shows a backup or the
// result of a restore.
type Summary struct {
	Servers, Clients, Mappings int
	// NeedCredentials names the connections restored switched off,
	// because the backup carried no token or password for them.
	NeedCredentials []string
}

func (s Setup) Summary() Summary {
	sum := Summary{Servers: len(s.Servers), Clients: len(s.Clients), Mappings: len(s.Mappings)}
	for _, sv := range s.Servers {
		if sv.Withheld {
			sum.NeedCredentials = append(sum.NeedCredentials, sv.Name)
		}
	}
	for _, c := range s.Clients {
		if c.Withheld {
			sum.NeedCredentials = append(sum.NeedCredentials, c.Name)
		}
	}
	return sum
}

// Pack makes the codes for this install's setup. A PIN carries every
// token and password, encrypted; no PIN leaves them out. Each backup
// takes the next version of this install's workspace.
func Pack(d *db.DB, key []byte, pin string, now time.Time) ([]string, packitup.Meta, Summary, error) {
	if pin != "" && len(pin) < packitup.MinPINLength {
		return nil, packitup.Meta{}, Summary{}, packitup.ErrPINTooShort
	}
	setup, err := Collect(d, key, pin != "")
	if err != nil {
		return nil, packitup.Meta{}, Summary{}, err
	}
	plain, err := json.Marshal(setup)
	if err != nil {
		return nil, packitup.Meta{}, Summary{}, err
	}

	workspace, ok, err := d.GetSetting(keyWorkspace)
	if err != nil {
		return nil, packitup.Meta{}, Summary{}, err
	}
	if !ok || workspace == "" {
		workspace = packitup.NewID(9)
		if err := d.SetSetting(keyWorkspace, workspace); err != nil {
			return nil, packitup.Meta{}, Summary{}, err
		}
	}
	version := 1
	if raw, ok, err := d.GetSetting(keyVersion); err != nil {
		return nil, packitup.Meta{}, Summary{}, err
	} else if ok {
		if n, err := strconv.Atoi(raw); err == nil {
			version = n + 1
		}
	}

	meta := packitup.Meta{App: App, Workspace: workspace, Snapshot: packitup.NewID(6), Version: version, Created: now}
	codes, err := packitup.Pack(meta, plain, pin)
	if err != nil {
		return nil, packitup.Meta{}, Summary{}, err
	}
	if err := d.SetSetting(keyVersion, strconv.Itoa(version)); err != nil {
		return nil, packitup.Meta{}, Summary{}, err
	}
	return codes, meta, setup.Summary(), nil
}

// ErrNewerFormat is a backup made by a later AutoThrottle.
var ErrNewerFormat = errors.New("this backup was made by a newer AutoThrottle; update this one first")

// Open reads a gathered set's setup.
func Open(set *packitup.Set, pin string) (Setup, error) {
	plain, err := set.Open(pin)
	if err != nil {
		return Setup{}, err
	}
	var setup Setup
	if err := json.Unmarshal(plain, &setup); err != nil {
		return Setup{}, packitup.ErrVerify
	}
	if setup.V > formatV1 {
		return Setup{}, ErrNewerFormat
	}
	return setup, nil
}

// Apply replaces this install's setup with the backup's, sealing every
// credential with this install's key. A connection whose credential was
// withheld comes back switched off, so it can't fail every few seconds
// until its token is entered again. The install also takes the backup's
// workspace and version, so its next backup supersedes the restored one.
func Apply(d *db.DB, key []byte, setup Setup, meta packitup.Meta) (Summary, error) {
	servers := make([]db.MediaServer, 0, len(setup.Servers))
	for _, s := range setup.Servers {
		ms := db.MediaServer{Name: s.Name, Type: s.Type, URL: s.URL, SkipLocalPlayback: s.SkipLocal, Enabled: s.Enabled && !s.Withheld}
		if s.Token != "" {
			sealed, err := crypto.Encrypt(key, s.Token)
			if err != nil {
				return Summary{}, err
			}
			ms.CredentialEncrypted = sealed
		}
		servers = append(servers, ms)
	}
	downloaders := make([]db.Downloader, 0, len(setup.Clients))
	for _, c := range setup.Clients {
		dl := db.Downloader{Name: c.Name, Type: c.Type, URL: c.URL,
			DefaultDownloadLimit: c.DefaultDown, DefaultUploadLimit: c.DefaultUp,
			BackupDownloadLimit: c.ThrottledDown, BackupUploadLimit: c.ThrottledUp,
			Enabled: c.Enabled && !c.Withheld}
		if c.Password != "" || c.Username != "" {
			sealed, err := credential.Encrypt(key, c.Username, c.Password)
			if err != nil {
				return Summary{}, err
			}
			dl.CredentialEncrypted = sql.NullString{String: sealed, Valid: true}
		}
		downloaders = append(downloaders, dl)
	}
	mappings := make([]db.RestoredMapping, 0, len(setup.Mappings))
	for _, m := range setup.Mappings {
		mappings = append(mappings, db.RestoredMapping{MediaServer: m.S, Downloader: m.C, Enabled: m.On})
	}

	settings := map[string]string{keyWorkspace: meta.Workspace, keyVersion: strconv.Itoa(meta.Version)}
	for _, k := range carriedSettings {
		if v, ok := setup.Settings[k]; ok {
			settings[k] = v
		}
	}
	if err := d.ReplaceSetup(servers, downloaders, mappings, settings); err != nil {
		return Summary{}, err
	}
	return setup.Summary(), nil
}
