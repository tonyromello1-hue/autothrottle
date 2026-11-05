package db

import (
	"context"
	"fmt"
)

// RestoredMapping pairs a media server with a download client by their
// positions in the slices handed to ReplaceSetup, since a restored row
// gets a new id.
type RestoredMapping struct {
	MediaServer, Downloader int
	Enabled                 bool
}

// ReplaceSetup swaps every media server, download client and mapping for
// the given ones, and writes the given settings, in one transaction: a
// restore either lands whole or not at all. The event log and history
// stay; their rows lose the ids they pointed at, as on a delete.
func (d *DB) ReplaceSetup(servers []MediaServer, downloaders []Downloader, mappings []RestoredMapping, settings map[string]string) error {
	ctx := context.Background()
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("restoring setup: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range []string{`DELETE FROM mappings`, `DELETE FROM media_servers`, `DELETE FROM downloaders`} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("restoring setup: %w", err)
		}
	}

	serverIDs := make([]int64, len(servers))
	for i, m := range servers {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO media_servers (name, type, url, credential_encrypted, skip_local_playback, enabled)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			m.Name, m.Type, m.URL, m.CredentialEncrypted, m.SkipLocalPlayback, m.Enabled)
		if err != nil {
			return fmt.Errorf("restoring media server %q: %w", m.Name, err)
		}
		if serverIDs[i], err = res.LastInsertId(); err != nil {
			return err
		}
	}
	downloaderIDs := make([]int64, len(downloaders))
	for i, dl := range downloaders {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO downloaders (name, type, url, credential_encrypted,
			 default_download_limit, default_upload_limit, backup_download_limit, backup_upload_limit, enabled)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			dl.Name, dl.Type, dl.URL, dl.CredentialEncrypted,
			dl.DefaultDownloadLimit, dl.DefaultUploadLimit, dl.BackupDownloadLimit, dl.BackupUploadLimit, dl.Enabled)
		if err != nil {
			return fmt.Errorf("restoring download client %q: %w", dl.Name, err)
		}
		if downloaderIDs[i], err = res.LastInsertId(); err != nil {
			return err
		}
	}
	for _, m := range mappings {
		if m.MediaServer < 0 || m.MediaServer >= len(serverIDs) || m.Downloader < 0 || m.Downloader >= len(downloaderIDs) {
			return fmt.Errorf("restoring setup: a mapping points at nothing")
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO mappings (media_server_id, downloader_id, enabled) VALUES (?, ?, ?)
			 ON CONFLICT(media_server_id, downloader_id) DO UPDATE SET enabled = excluded.enabled`,
			serverIDs[m.MediaServer], downloaderIDs[m.Downloader], m.Enabled); err != nil {
			return fmt.Errorf("restoring mapping: %w", err)
		}
	}
	for k, v := range settings {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO settings (key, value) VALUES (?, ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value,
			   updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`, k, v); err != nil {
			return fmt.Errorf("restoring setting %q: %w", k, err)
		}
	}
	return tx.Commit()
}
