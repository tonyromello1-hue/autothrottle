package web

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/JaiMistry/autothrottle/internal/crypto"
)

var codeText = regexp.MustCompile(`(?s)<textarea id="piu-codetext"[^>]*>(.*?)</textarea>`)

// packed makes a backup on a and returns its code text.
func packed(t *testing.T, a *testApp, pin string) string {
	t.Helper()
	rec := a.post("/backup/pack", url.Values{"pin": {pin}, "pin_confirm": {pin}})
	expectStatus(t, rec, http.StatusOK)
	expectBody(t, rec, `class="at-piu-qr"`)
	m := codeText.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("no code text on the packed page")
	}
	return html.UnescapeString(m[1])
}

func withToken(t *testing.T, a *testApp, id int64, token string) {
	t.Helper()
	ms, err := a.db.GetMediaServer(id)
	if err != nil {
		t.Fatal(err)
	}
	if ms.CredentialEncrypted, err = crypto.Encrypt(a.srv.encryptionKey, token); err != nil {
		t.Fatal(err)
	}
	if err := a.db.UpdateMediaServer(ms); err != nil {
		t.Fatal(err)
	}
}

func TestBackupPageOnAnEmptySetup(t *testing.T) {
	a := newApp(t)
	rec := a.get("/backup")
	expectStatus(t, rec, http.StatusOK)
	expectBody(t, rec, "Nothing to back up yet")
	expectBody(t, rec, `action="/backup/restore"`)
}

func TestPackRefusesBadPINs(t *testing.T) {
	a := newApp(t)
	a.mediaServer("Plex", "plex", "http://plex.invalid:32400")
	rec := a.post("/backup/pack", url.Values{"pin": {"4821"}, "pin_confirm": {"4812"}})
	expectStatus(t, rec, http.StatusUnprocessableEntity)
	expectBody(t, rec, "The two PINs don")
	rec = a.post("/backup/pack", url.Values{"pin": {"12"}, "pin_confirm": {"12"}})
	expectStatus(t, rec, http.StatusUnprocessableEntity)
	expectBody(t, rec, "at least 4 characters")
}

func TestBackupRestoresOnAnotherInstall(t *testing.T) {
	src := newApp(t)
	plex := src.mediaServer("Living Room Plex", "plex", "http://plex.invalid:32400")
	withToken(t, src, plex, "xZ4pQ9vLm2TbR7nWc8Yd")
	src.downloader("qBittorrent")
	codes := packed(t, src, "4821")
	if !strings.HasPrefix(codes, "PIU1*AUTOTHROTTLE*") {
		t.Fatalf("codes %.60q", codes)
	}

	dst := newApp(t)
	rec := dst.post("/backup/restore", url.Values{"codes": {codes}})
	expectStatus(t, rec, http.StatusUnprocessableEntity)
	expectBody(t, rec, "needed")

	rec = dst.post("/backup/restore", url.Values{"codes": {codes}, "pin": {"1111"}})
	expectStatus(t, rec, http.StatusUnprocessableEntity)
	expectBody(t, rec, "That PIN didn")

	rec = dst.post("/backup/restore", url.Values{"codes": {codes}, "pin": {"4821"}})
	expectStatus(t, rec, http.StatusOK)
	expectBody(t, rec, "Setup restored")
	servers, _ := dst.db.ListMediaServers()
	if len(servers) != 1 || !servers[0].Enabled {
		t.Fatalf("servers %+v", servers)
	}
	tok, err := crypto.Decrypt(dst.srv.encryptionKey, servers[0].CredentialEncrypted)
	if err != nil || tok != "xZ4pQ9vLm2TbR7nWc8Yd" {
		t.Fatalf("token %q, %v", tok, err)
	}
	if dst.watchers.reconciles == 0 {
		t.Fatal("the watchers weren't told about the restored servers")
	}
	events, _ := dst.db.ListEvents(10)
	if len(events) == 0 || !strings.Contains(events[0].Message, "Restored a Pack It Up backup") {
		t.Fatalf("events %+v", events)
	}

	// Now that it has a setup, a second restore has to be asked for.
	rec = dst.post("/backup/restore", url.Values{"codes": {codes}, "pin": {"4821"}})
	expectStatus(t, rec, http.StatusUnprocessableEntity)
	expectBody(t, rec, "Replace my current setup")
	rec = dst.post("/backup/restore", url.Values{"codes": {codes}, "pin": {"4821"}, "replace": {"on"}})
	expectStatus(t, rec, http.StatusOK)
}

func TestRestoreSaysWhatIsWrong(t *testing.T) {
	a := newApp(t)
	rec := a.post("/backup/restore", url.Values{"codes": {"WIFI:S:home;;"}})
	expectStatus(t, rec, http.StatusUnprocessableEntity)
	expectBody(t, rec, "No AutoThrottle backup codes were found")
}

func TestBackupWithoutPINRestoresConnectionsSwitchedOff(t *testing.T) {
	src := newApp(t)
	plex := src.mediaServer("Living Room Plex", "plex", "http://plex.invalid:32400")
	withToken(t, src, plex, "secret-token")
	codes := packed(t, src, "")
	if strings.Contains(codes, "secret") {
		t.Fatal("codes should carry no token")
	}

	dst := newApp(t)
	rec := dst.post("/backup/restore", url.Values{"codes": {codes}})
	expectStatus(t, rec, http.StatusOK)
	expectBody(t, rec, "need their token or password again")
	servers, _ := dst.db.ListMediaServers()
	if len(servers) != 1 || servers[0].Enabled {
		t.Fatalf("servers %+v", servers)
	}
}
