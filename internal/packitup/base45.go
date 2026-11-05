package packitup

import (
	"errors"
	"strings"
)

// base45Alphabet is RFC 9285's: exactly the characters QR alphanumeric
// mode can carry, so a payload costs 5.5 bits a character, not 8.
const base45Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

var errBase45 = errors.New("not valid Base45")

func base45Encode(b []byte) string {
	var sb strings.Builder
	sb.Grow((len(b)/2)*3 + 2)
	for i := 0; i+1 < len(b); i += 2 {
		n := int(b[i])<<8 | int(b[i+1])
		sb.WriteByte(base45Alphabet[n%45])
		sb.WriteByte(base45Alphabet[(n/45)%45])
		sb.WriteByte(base45Alphabet[n/2025])
	}
	if len(b)%2 == 1 {
		n := int(b[len(b)-1])
		sb.WriteByte(base45Alphabet[n%45])
		sb.WriteByte(base45Alphabet[n/45])
	}
	return sb.String()
}

func base45Decode(s string) ([]byte, error) {
	if len(s)%3 == 1 {
		return nil, errBase45
	}
	out := make([]byte, 0, len(s)/3*2+1)
	digit := func(c byte) (int, error) {
		i := strings.IndexByte(base45Alphabet, c)
		if i < 0 {
			return 0, errBase45
		}
		return i, nil
	}
	for i := 0; i < len(s); i += 3 {
		var d [3]int
		width := min(3, len(s)-i)
		for j := 0; j < width; j++ {
			v, err := digit(s[i+j])
			if err != nil {
				return nil, err
			}
			d[j] = v
		}
		if width == 3 {
			n := d[0] + d[1]*45 + d[2]*2025
			if n > 0xFFFF {
				return nil, errBase45
			}
			out = append(out, byte(n>>8), byte(n))
		} else {
			n := d[0] + d[1]*45
			if n > 0xFF {
				return nil, errBase45
			}
			out = append(out, byte(n))
		}
	}
	return out, nil
}
