package packitup

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func testMeta(version int) Meta {
	return Meta{App: "AUTOTHROTTLE", Workspace: "W4KJ9X2QP", Snapshot: NewID(6), Version: version,
		Created: time.Date(2026, 11, 5, 13, 21, 0, 0, time.UTC)}
}

func roundTrip(t *testing.T, plain []byte, pin string) {
	t.Helper()
	codes, err := Pack(testMeta(3), plain, pin)
	if err != nil {
		t.Fatal(err)
	}
	set, err := Gather("AUTOTHROTTLE", codes)
	if err != nil {
		t.Fatal(err)
	}
	if set.Encrypted != (pin != "") {
		t.Fatalf("Encrypted = %v with pin %q", set.Encrypted, pin)
	}
	got, err := set.Open(pin)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip changed the data")
	}
}

func TestBase45(t *testing.T) {
	// RFC 9285's own examples.
	for in, want := range map[string]string{"AB": "BB8", "Hello!!": "%69 VD92EX0", "base-45": "UJCLQE7W581", "ietf!": "QED8WEX0"} {
		if got := base45Encode([]byte(in)); got != want {
			t.Errorf("encode %q = %q, want %q", in, got, want)
		}
		back, err := base45Decode(want)
		if err != nil || string(back) != in {
			t.Errorf("decode %q = %q, %v", want, back, err)
		}
	}
	for _, bad := range []string{"GGW", "A", "a00"} {
		if _, err := base45Decode(bad); err == nil {
			t.Errorf("decode %q: want an error", bad)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	plain := []byte(`{"servers":[{"n":"Living Room Plex","t":"plex","u":"http://192.168.1.20:32400"}]}`)
	roundTrip(t, plain, "")
	roundTrip(t, plain, "4821")
	roundTrip(t, []byte{}, "")
}

func TestCodesAreQRAlphanumeric(t *testing.T) {
	codes, err := Pack(testMeta(1), []byte("anything at all, in any bytes \x00\xff"), "1234")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range codes {
		for _, r := range c {
			if !strings.ContainsRune(base45Alphabet, r) {
				t.Fatalf("code has %q, which QR alphanumeric mode can't carry", r)
			}
		}
	}
}

func TestManyPartsAnyOrder(t *testing.T) {
	plain := make([]byte, 5000) // random, so deflate can't shrink it into one code
	_, _ = rand.Read(plain)
	codes, err := Pack(testMeta(1), plain, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) < 4 {
		t.Fatalf("want several parts, got %d", len(codes))
	}
	shuffled := append([]string{"WIFI:S:home;T:WPA;P:hunter2;;", "not a code"}, codes[2:]...)
	shuffled = append(shuffled, codes[1], codes[0], codes[0]) // a duplicate is fine
	set, err := Gather("AUTOTHROTTLE", shuffled)
	if err != nil {
		t.Fatal(err)
	}
	got, err := set.Open("")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("Open: %v", err)
	}
}

func TestFailures(t *testing.T) {
	plain := make([]byte, 3000)
	_, _ = rand.Read(plain)
	codes, err := Pack(testMeta(2), plain, "4821")
	if err != nil {
		t.Fatal(err)
	}
	total := len(codes)

	t.Run("missing part", func(t *testing.T) {
		_, err := Gather("AUTOTHROTTLE", codes[:total-1])
		var missing *MissingPartsError
		if !errors.As(err, &missing) || len(missing.Missing) != 1 || missing.Missing[0] != total {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("damaged code", func(t *testing.T) {
		damaged := append([]string{}, codes...)
		b := []byte(damaged[0])
		b[len(b)-5] = '0' + (b[len(b)-5]-'0'+1)%10
		if b[len(b)-5] < '0' || b[len(b)-5] > '9' {
			b[len(b)-5] = '7'
		}
		damaged[0] = string(b)
		_, err := Gather("AUTOTHROTTLE", damaged)
		var corrupt *CorruptPartError
		if !errors.As(err, &corrupt) || corrupt.Part != 1 {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("wrong and missing PIN", func(t *testing.T) {
		set, err := Gather("AUTOTHROTTLE", codes)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := set.Open(""); !errors.Is(err, ErrPINRequired) {
			t.Fatalf("no PIN: got %v", err)
		}
		if _, err := set.Open("0000"); !errors.Is(err, ErrWrongPIN) {
			t.Fatalf("wrong PIN: got %v", err)
		}
	})

	t.Run("another app's codes only", func(t *testing.T) {
		other := testMeta(1)
		other.App = "GRIDCOPILOT"
		theirs, _ := Pack(other, []byte("x"), "")
		if _, err := Gather("AUTOTHROTTLE", theirs); !errors.Is(err, ErrNoCodes) {
			t.Fatalf("got %v", err)
		}
		set, err := Gather("AUTOTHROTTLE", append(theirs, codes...))
		if err != nil || len(set.Notes) != 1 || !strings.Contains(set.Notes[0], "another app") {
			t.Fatalf("got %v, notes %v", err, set)
		}
	})

	t.Run("two backups, newest wins", func(t *testing.T) {
		newer, _ := Pack(testMeta(5), []byte("newer"), "")
		set, err := Gather("AUTOTHROTTLE", append(append([]string{}, codes...), newer...))
		if err != nil {
			t.Fatal(err)
		}
		got, err := set.Open("")
		if err != nil || string(got) != "newer" || len(set.Notes) != 1 {
			t.Fatalf("got %q, %v, notes %v", got, err, set.Notes)
		}
	})

	t.Run("two setups", func(t *testing.T) {
		m := testMeta(1)
		m.Workspace = "OTHERSETUP"
		theirs, _ := Pack(m, []byte("x"), "")
		if _, err := Gather("AUTOTHROTTLE", append(theirs, codes...)); !errors.Is(err, ErrMixedWorkspace) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("short PIN refused", func(t *testing.T) {
		if _, err := Pack(testMeta(1), []byte("x"), "12"); !errors.Is(err, ErrPINTooShort) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestHeaderTamperFailsVerify(t *testing.T) {
	codes, _ := Pack(testMeta(1), []byte("hello"), "")
	set, err := Gather("AUTOTHROTTLE", codes)
	if err != nil {
		t.Fatal(err)
	}
	set.blob[40] ^= 0xFF // the plaintext length
	if _, err := set.Open(""); !errors.Is(err, ErrVerify) {
		t.Fatalf("got %v", err)
	}
}
