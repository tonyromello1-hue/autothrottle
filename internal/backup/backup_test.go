package backup

import (
	"bytes"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/JaiMistry/autothrottle/internal/credential"
	"github.com/JaiMistry/autothrottle/internal/crypto"
	"github.com/JaiMistry/autothrottle/internal/db"
	"github.com/JaiMistry/autothrottle/internal/packitup"
)

func openDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// homeSetup is the two-server, two-client setup the demo uses.
func homeSetup(t *testing.T, d *db.DB, k []byte) {
	t.Helper()
	plexTok, _ := crypto.Encrypt(k, "xZ4pQ9vLm2TbR7nWc8Yd")
	jfTok, _ := crypto.Encrypt(k, "3f9a1c7e5b2d48a6901fe4c7d2b8a5e3")
	plex, err := d.CreateMediaServer(db.MediaServer{Name: "Living Room Plex", Type: "plex", URL: "http://192.168.1.20:32400", CredentialEncrypted: plexTok, SkipLocalPlayback: true, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	jf, _ := d.CreateMediaServer(db.MediaServer{Name: "Jellyfin", Type: "jellyfin", URL: "http://192.168.1.21:8096", CredentialEncrypted: jfTok, Enabled: true})
	qbCred, _ := credential.Encrypt(k, "admin", "correct-horse-42")
	qb, _ := d.CreateDownloader(db.Downloader{Name: "qBittorrent", Type: "qbittorrent", URL: "http://192.168.1.30:8080",
		CredentialEncrypted: sql.NullString{String: qbCred, Valid: true}, BackupDownloadLimit: 2048, BackupUploadLimit: 512, Enabled: true})
	delCred, _ := credential.Encrypt(k, "", "battery-staple-77")
	del, _ := d.CreateDownloader(db.Downloader{Name: "Seedbox Deluge", Type: "deluge", URL: "https://seedbox.example.net:8112",
		CredentialEncrypted: sql.NullString{String: delCred, Valid: true}, BackupDownloadLimit: 4096, BackupUploadLimit: 1024, Enabled: true})
	for _, pair := range [][2]int64{{plex, qb}, {plex, del}, {jf, qb}} {
		if err := d.SetMappingForPair(pair[0], pair[1], true); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.SetMappingForPair(jf, del, false); err != nil {
		t.Fatal(err)
	}
}

func restore(t *testing.T, codes []string, pin string, into *db.DB, k []byte) Summary {
	t.Helper()
	set, err := packitup.Gather(App, codes)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := Open(set, pin)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := Apply(into, k, setup, set.Meta)
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

func TestFullBackupRestoresEverythingUnderANewKey(t *testing.T) {
	src, srcKey := openDB(t), key(1)
	homeSetup(t, src, srcKey)
	if err := src.SetSetting("throttle.paused", "true"); err != nil {
		t.Fatal(err)
	}

	codes, meta, sum, err := Pack(src, srcKey, "4821", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 1 {
		t.Fatalf("a home setup should fit one code, got %d", len(codes))
	}
	if sum.Servers != 2 || sum.Clients != 2 || sum.Mappings != 4 || len(sum.NeedCredentials) != 0 {
		t.Fatalf("summary %+v", sum)
	}

	dst, dstKey := openDB(t), key(2) // a fresh install has its own key
	restore(t, codes, "4821", dst, dstKey)

	servers, _ := dst.ListMediaServers()
	if len(servers) != 2 {
		t.Fatalf("servers %+v", servers)
	}
	for _, ms := range servers {
		tok, err := crypto.Decrypt(dstKey, ms.CredentialEncrypted)
		if err != nil || tok == "" || !ms.Enabled {
			t.Fatalf("%s: token %q, %v, enabled %v", ms.Name, tok, err, ms.Enabled)
		}
		if ms.Name == "Living Room Plex" && (!ms.SkipLocalPlayback || tok != "xZ4pQ9vLm2TbR7nWc8Yd") {
			t.Fatalf("plex came back as %+v / %q", ms, tok)
		}
	}
	dls, _ := dst.ListDownloaders()
	for _, dl := range dls {
		u, p, err := credential.Decrypt(dstKey, dl.CredentialEncrypted.String)
		if err != nil || p == "" {
			t.Fatalf("%s: %q %q %v", dl.Name, u, p, err)
		}
		if dl.Name == "qBittorrent" && (u != "admin" || p != "correct-horse-42" || dl.BackupDownloadLimit != 2048) {
			t.Fatalf("qbittorrent came back as %+v", dl)
		}
	}
	maps, _ := dst.ListMappings()
	on := 0
	for _, m := range maps {
		if m.Enabled {
			on++
		}
	}
	if len(maps) != 4 || on != 3 {
		t.Fatalf("mappings %+v", maps)
	}
	if v, _, _ := dst.GetSetting("throttle.paused"); v != "true" {
		t.Fatalf("pause switch %q", v)
	}

	// The restored install carries on the backup's line: its next backup
	// is the newer one.
	next, nextMeta, _, err := Pack(dst, dstKey, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if nextMeta.Workspace != meta.Workspace || nextMeta.Version != meta.Version+1 {
		t.Fatalf("next backup %+v after %+v", nextMeta, meta)
	}
	set, err := packitup.Gather(App, append(codes, next...))
	if err != nil || set.Meta.Version != nextMeta.Version {
		t.Fatalf("newest should win: %v %+v", err, set)
	}
}

func TestBackupWithoutPINCarriesNoSecrets(t *testing.T) {
	src, srcKey := openDB(t), key(1)
	homeSetup(t, src, srcKey)
	codes, _, sum, err := Pack(src, srcKey, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.NeedCredentials) != 4 {
		t.Fatalf("want all four connections flagged, got %v", sum.NeedCredentials)
	}
	set, _ := packitup.Gather(App, codes)
	plain, _ := set.Open("")
	for _, secret := range []string{"xZ4pQ9vLm2TbR7nWc8Yd", "correct-horse-42", "battery-staple-77", "admin"} {
		if bytes.Contains(plain, []byte(secret)) {
			t.Fatalf("a backup without a PIN carries %q", secret)
		}
	}

	dst := openDB(t)
	restore(t, codes, "", dst, key(2))
	servers, _ := dst.ListMediaServers()
	dls, _ := dst.ListDownloaders()
	for _, ms := range servers {
		if ms.Enabled {
			t.Fatalf("%s came back on with no token", ms.Name)
		}
	}
	for _, dl := range dls {
		if dl.Enabled || dl.BackupDownloadLimit == 0 {
			t.Fatalf("%s came back as %+v", dl.Name, dl)
		}
	}
}

func TestRestoreReplacesTheCurrentSetup(t *testing.T) {
	src, k := openDB(t), key(1)
	homeSetup(t, src, k)
	codes, _, _, _ := Pack(src, k, "4821", time.Now())

	dst := openDB(t)
	if _, err := dst.CreateMediaServer(db.MediaServer{Name: "Old", Type: "emby", URL: "http://old:8096", CredentialEncrypted: "x", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	restore(t, codes, "4821", dst, k)
	servers, _ := dst.ListMediaServers()
	if len(servers) != 2 {
		t.Fatalf("restore should replace, got %d servers", len(servers))
	}
}

func TestWrongPINRestoresNothing(t *testing.T) {
	src, k := openDB(t), key(1)
	homeSetup(t, src, k)
	codes, _, _, _ := Pack(src, k, "4821", time.Now())
	set, _ := packitup.Gather(App, codes)
	if _, err := Open(set, "1111"); !errors.Is(err, packitup.ErrWrongPIN) {
		t.Fatalf("got %v", err)
	}
}
