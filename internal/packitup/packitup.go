// Package packitup implements Pack It Up, a backup format that turns an
// app's saved state into QR codes a person can screenshot and later hand
// back. It knows nothing about the app: it takes bytes and an app id and
// returns code strings, and the reverse.
//
// Each code is one line of QR alphanumeric text:
//
//	PIU1*APP*W<workspace>*S<snapshot>*V<version>*T<created>*P<i>.<n>*C<crc>*H<digest>*EB45*<payload>
//
// The payload is one Base45 chunk of a blob. The blob carries its own
// header (compression, the optional PIN encryption, a length and a CRC of
// the plaintext), so the chunker never needs to know about encryption.
package packitup

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	magic = "PIU1"
	// ChunkSize is the most blob bytes one code carries: enough for a
	// typical setup in one code, small enough to scan from a screenshot.
	ChunkSize = 1100
	// MinPINLength is the shortest PIN Pack accepts.
	MinPINLength = 4

	headerSize    = 47
	flagDeflate   = 1 << 0
	flagEncrypted = 1 << 1
	algNone       = 0
	algAESGCM     = 1
	kdfNone       = 0
	kdfPBKDF2     = 1
	// pbkdf2Iterations makes each PIN guess cost something. A short PIN
	// is still protection against someone flicking through a photo
	// library, not against a determined attacker holding the image.
	pbkdf2Iterations = 600_000
	// maxPlain bounds what an unpack will inflate, so a crafted code
	// can't make it allocate without limit.
	maxPlain = 4 << 20
)

// Meta is what every code of one backup says about itself.
type Meta struct {
	App       string // e.g. "AUTOTHROTTLE"
	Workspace string // which install the backup came from
	Snapshot  string // which backup
	Version   int    // rises with each backup of one workspace
	Created   time.Time
}

var (
	ErrNoCodes        = errors.New("no Pack It Up codes were found")
	ErrMixedWorkspace = errors.New("these codes are from two different setups")
	ErrPINRequired    = errors.New("this backup is locked with a PIN")
	ErrWrongPIN       = errors.New("that PIN didn't unlock this backup")
	ErrVerify         = errors.New("the backup didn't verify; one code may have misread")
	ErrPINTooShort    = fmt.Errorf("a PIN needs at least %d characters", MinPINLength)
	ErrUnreadable     = errors.New("one code didn't read cleanly; capture it again")
)

// MissingPartsError names the parts a set still needs.
type MissingPartsError struct {
	Missing []int
	Total   int
}

func (e *MissingPartsError) Error() string {
	parts := make([]string, len(e.Missing))
	for i, p := range e.Missing {
		parts[i] = strconv.Itoa(p)
	}
	noun := "Part"
	if len(parts) > 1 {
		noun = "Parts"
	}
	return fmt.Sprintf("%s %s of %d missing; add the other screenshot", noun, strings.Join(parts, ", "), e.Total)
}

// CorruptPartError is a code that read but failed its own checksum.
type CorruptPartError struct{ Part, Total int }

func (e *CorruptPartError) Error() string {
	return fmt.Sprintf("part %d of %d didn't read cleanly; capture it again", e.Part, e.Total)
}

// Pack seals plaintext into code strings. A non-empty pin encrypts it
// with AES-256-GCM under a PBKDF2 key.
func Pack(meta Meta, plaintext []byte, pin string) ([]string, error) {
	if pin != "" && len(pin) < MinPINLength {
		return nil, ErrPINTooShort
	}
	if !alnum(meta.App) || !alnum(meta.Workspace) || !alnum(meta.Snapshot) {
		return nil, errors.New("packitup: ids must be uppercase letters and digits")
	}
	blob, err := seal(plaintext, pin)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(blob)
	digest := strings.ToUpper(hex.EncodeToString(sum[:8]))
	created := strings.ToUpper(strconv.FormatInt(meta.Created.Unix(), 36))

	total := (len(blob) + ChunkSize - 1) / ChunkSize
	codes := make([]string, 0, total)
	for i := range total {
		chunk := blob[i*ChunkSize : min((i+1)*ChunkSize, len(blob))]
		codes = append(codes, fmt.Sprintf("%s*%s*W%s*S%s*V%d*T%s*P%d.%d*C%08X*H%s*EB45*%s",
			magic, meta.App, meta.Workspace, meta.Snapshot, meta.Version, created,
			i+1, total, crc32.ChecksumIEEE(chunk), digest, base45Encode(chunk)))
	}
	return codes, nil
}

func seal(plaintext []byte, pin string) ([]byte, error) {
	var deflated bytes.Buffer
	fw, err := flate.NewWriter(&deflated, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write(plaintext); err != nil {
		return nil, err
	}
	if err := fw.Close(); err != nil {
		return nil, err
	}

	header := make([]byte, headerSize)
	copy(header, magic)
	header[4] = flagDeflate
	binary.BigEndian.PutUint32(header[39:], uint32(len(plaintext)))
	binary.BigEndian.PutUint32(header[43:], crc32.ChecksumIEEE(plaintext))
	if pin == "" {
		return append(header, deflated.Bytes()...), nil
	}

	header[4] |= flagEncrypted
	header[5] = algAESGCM
	header[6] = kdfPBKDF2
	binary.BigEndian.PutUint32(header[7:], pbkdf2Iterations)
	salt, iv := header[11:27], header[27:39]
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	gcm, err := pinCipher(pin, salt, pbkdf2Iterations)
	if err != nil {
		return nil, err
	}
	// The header is authenticated too, so no field of it can be altered.
	return gcm.Seal(header, iv, deflated.Bytes(), header), nil
}

func pinCipher(pin string, salt []byte, iterations int) (cipher.AEAD, error) {
	key, err := pbkdf2.Key(sha256.New, pin, salt, iterations, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Set is one backup gathered from a pile of scanned codes.
type Set struct {
	Meta      Meta
	Parts     int
	Encrypted bool
	// Notes are things the restore quietly worked around, worth showing.
	Notes []string
	blob  []byte
}

type code struct {
	meta    Meta
	part    int
	total   int
	digest  string
	payload []byte
}

// Gather finds one app's codes among anything scanned (other apps'
// codes, a Wi-Fi code, text that isn't a code), in any order, and
// reassembles the newest complete backup. It does not need the PIN:
// Encrypted says whether Open will.
func Gather(app string, scanned []string) (*Set, error) {
	var codes []code
	var foreign, unreadable int
	for _, raw := range scanned {
		raw = strings.TrimSpace(raw)
		if !strings.HasPrefix(raw, magic+"*") {
			continue
		}
		c, err := parseCode(raw)
		switch {
		case errors.Is(err, errCRC) && c.meta.App == app:
			return nil, &CorruptPartError{Part: c.part, Total: c.total}
		case err != nil && !errors.Is(err, errCRC):
			unreadable++
			continue
		case c.meta.App != app:
			foreign++
			continue
		}
		codes = append(codes, c)
	}
	if len(codes) == 0 {
		if unreadable > 0 {
			return nil, ErrUnreadable
		}
		return nil, ErrNoCodes
	}

	workspace := codes[0].meta.Workspace
	for _, c := range codes {
		if c.meta.Workspace != workspace {
			return nil, ErrMixedWorkspace
		}
	}

	// Two backups of one setup: use the newest, and say so.
	type key struct {
		version          int
		snapshot, digest string
	}
	groups := map[key][]code{}
	for _, c := range codes {
		k := key{c.meta.Version, c.meta.Snapshot, c.digest}
		groups[k] = append(groups[k], c)
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b key) int { return b.version - a.version })
	chosen := groups[keys[0]]

	set := &Set{Meta: chosen[0].meta, Parts: chosen[0].total}
	if foreign > 0 {
		set.Notes = append(set.Notes, fmt.Sprintf("Skipped %d %s from another app.", foreign, plural(foreign, "code", "codes")))
	}
	if len(keys) > 1 {
		versions := make([]string, len(keys))
		ignored := 0
		for i, k := range keys {
			versions[len(keys)-1-i] = "v" + strconv.Itoa(k.version)
			if i > 0 {
				ignored += len(groups[k])
			}
		}
		set.Notes = append(set.Notes, fmt.Sprintf("Found %d backups (%s). Using v%d and ignoring %d older %s.",
			len(keys), strings.Join(versions, ", "), keys[0].version, ignored, plural(ignored, "code", "codes")))
	}

	byPart := make(map[int][]byte, set.Parts)
	for _, c := range chosen {
		if c.total != set.Parts {
			return nil, ErrVerify
		}
		// The same code captured twice is fine; the CRC already vouched
		// for each copy.
		byPart[c.part] = c.payload
	}
	var missing []int
	for p := 1; p <= set.Parts; p++ {
		if _, ok := byPart[p]; !ok {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		if unreadable > 0 {
			return nil, ErrUnreadable
		}
		return nil, &MissingPartsError{Missing: missing, Total: set.Parts}
	}

	var blob []byte
	for p := 1; p <= set.Parts; p++ {
		blob = append(blob, byPart[p]...)
	}
	sum := sha256.Sum256(blob)
	if strings.ToUpper(hex.EncodeToString(sum[:8])) != chosen[0].digest || len(blob) < headerSize || string(blob[:4]) != magic {
		return nil, ErrVerify
	}
	set.blob = blob
	set.Encrypted = blob[4]&flagEncrypted != 0
	return set, nil
}

// Open decrypts (with pin, when the set is Encrypted) and inflates the
// backup, then checks its length and CRC.
func (s *Set) Open(pin string) ([]byte, error) {
	header, body := s.blob[:headerSize], s.blob[headerSize:]
	if header[4]&flagEncrypted != 0 {
		if pin == "" {
			return nil, ErrPINRequired
		}
		if header[5] != algAESGCM || header[6] != kdfPBKDF2 {
			return nil, errors.New("this backup uses encryption this version can't read")
		}
		iterations := int(binary.BigEndian.Uint32(header[7:]))
		if iterations < 1 || iterations > 10_000_000 {
			return nil, ErrVerify
		}
		gcm, err := pinCipher(pin, header[11:27], iterations)
		if err != nil {
			return nil, err
		}
		opened, err := gcm.Open(nil, header[27:39], body, header)
		if err != nil {
			return nil, ErrWrongPIN
		}
		body = opened
	}

	want := binary.BigEndian.Uint32(header[39:])
	if want > maxPlain {
		return nil, ErrVerify
	}
	plain := body
	if header[4]&flagDeflate != 0 {
		var err error
		plain, err = io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(body)), maxPlain+1))
		if err != nil {
			return nil, ErrVerify
		}
	}
	if uint32(len(plain)) != want || crc32.ChecksumIEEE(plain) != binary.BigEndian.Uint32(header[43:]) {
		return nil, ErrVerify
	}
	return plain, nil
}

var errCRC = errors.New("chunk checksum mismatch")

func parseCode(raw string) (code, error) {
	f := strings.SplitN(raw, "*", 11)
	if len(f) != 11 || f[0] != magic {
		return code{}, errors.New("not a code")
	}
	var c code
	c.meta.App = f[1]
	// Each field after the app id opens with its own letter.
	var v [7]string
	for i, prefix := range "WSVTPCH" {
		rest, ok := strings.CutPrefix(f[2+i], string(prefix))
		if !ok {
			return code{}, errors.New("unknown field layout")
		}
		v[i] = rest
	}
	if f[9] != "EB45" {
		return code{}, errors.New("unknown payload encoding")
	}
	ws, snap, ver, created, part, crc, digest := v[0], v[1], v[2], v[3], v[4], v[5], v[6]
	c.meta.Workspace, c.meta.Snapshot, c.digest = ws, snap, digest
	var err error
	if c.meta.Version, err = strconv.Atoi(ver); err != nil {
		return code{}, err
	}
	secs, err := strconv.ParseInt(created, 36, 64)
	if err != nil {
		return code{}, err
	}
	c.meta.Created = time.Unix(secs, 0).UTC()
	i, n, ok := strings.Cut(part, ".")
	if !ok {
		return code{}, errors.New("bad part")
	}
	if c.part, err = strconv.Atoi(i); err != nil {
		return code{}, err
	}
	if c.total, err = strconv.Atoi(n); err != nil {
		return code{}, err
	}
	if c.part < 1 || c.total < 1 || c.part > c.total || c.total > 255 {
		return code{}, errors.New("bad part")
	}
	wantCRC, err := strconv.ParseUint(crc, 16, 32)
	if err != nil {
		return code{}, err
	}
	payload, err := base45Decode(f[10])
	if err != nil || crc32.ChecksumIEEE(payload) != uint32(wantCRC) {
		return c, errCRC
	}
	c.payload = payload
	return c, nil
}

func alnum(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// NewID returns a random id of n uppercase letters and digits, for a
// workspace or a snapshot.
func NewID(n int) string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}
