package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	// ErrDuplicateKey indicates a JSON object contained duplicate property names.
	ErrDuplicateKey = errors.New("jcs: duplicate JSON object key")
	// ErrInvalidUTF8 indicates input bytes are not valid UTF-8.
	ErrInvalidUTF8 = errors.New("jcs: invalid UTF-8 input")
	// ErrInvalidJSON indicates malformed JSON or trailing tokens.
	ErrInvalidJSON = errors.New("jcs: invalid JSON syntax")
	// ErrInvalidNumber indicates a non-finite or unrepresentable JSON number.
	ErrInvalidNumber = errors.New("jcs: invalid JSON number")
)

type objectEntry struct {
	key   string
	utf16 []uint16
	val   any
}

// ParseStrict parses UTF-8 JSON bytes while rejecting duplicate object keys at
// every nesting level, invalid UTF-8, and trailing non-whitespace data.
func ParseStrict(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, ErrInvalidUTF8
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	val, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: unexpected trailing data", ErrInvalidJSON)
	}
	return val, nil
}

// UnmarshalStrict validates data with ParseStrict (rejecting duplicate keys and
// invalid UTF-8) and then decodes into dst with DisallowUnknownFields enabled.
func UnmarshalStrict(data []byte, dst any) error {
	if _, err := ParseStrict(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: unexpected trailing data", ErrInvalidJSON)
	}
	return nil
}

// Canonicalize parses raw UTF-8 JSON strictly (rejecting duplicate keys) and
// returns its RFC 8785 JSON Canonicalization Scheme (JCS) representation.
func Canonicalize(data []byte) ([]byte, error) {
	val, err := ParseStrict(data)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, val); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MarshalCanonical marshals v to JSON and returns its RFC 8785 canonical bytes.
func MarshalCanonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Canonicalize(raw)
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: unexpected EOF", ErrInvalidJSON)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}

	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			seen := make(map[string]struct{})
			var entries []objectEntry
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
				}
				key, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("%w: object key is not string", ErrInvalidJSON)
				}
				if _, dup := seen[key]; dup {
					return nil, fmt.Errorf("%w: %q", ErrDuplicateKey, key)
				}
				seen[key] = struct{}{}
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				entries = append(entries, objectEntry{
					key:   key,
					utf16: utf16.Encode([]rune(key)),
					val:   val,
				})
			}
			endTok, err := dec.Token()
			if err != nil || endTok != json.Delim('}') {
				return nil, fmt.Errorf("%w: expected closing brace", ErrInvalidJSON)
			}
			return entries, nil

		case '[':
			var items []any
			for dec.More() {
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				items = append(items, val)
			}
			endTok, err := dec.Token()
			if err != nil || endTok != json.Delim(']') {
				return nil, fmt.Errorf("%w: expected closing bracket", ErrInvalidJSON)
			}
			return items, nil

		default:
			return nil, fmt.Errorf("%w: unexpected delimiter %v", ErrInvalidJSON, t)
		}
	case string, bool, nil, json.Number:
		return t, nil
	default:
		return nil, fmt.Errorf("%w: unsupported token %T", ErrInvalidJSON, tok)
	}
}

func writeCanonical(buf *bytes.Buffer, val any) error {
	switch v := val.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeCanonicalString(buf, v)
	case json.Number:
		numStr, err := formatCanonicalNumber(v)
		if err != nil {
			return err
		}
		buf.WriteString(numStr)
	case []any:
		buf.WriteByte('[')
		for i, elem := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []objectEntry:
		sorted := make([]objectEntry, len(v))
		copy(sorted, v)
		sort.Slice(sorted, func(i, j int) bool {
			return compareUTF16(sorted[i].utf16, sorted[j].utf16) < 0
		})
		buf.WriteByte('{')
		for i, entry := range sorted {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, entry.key)
			buf.WriteByte(':')
			if err := writeCanonical(buf, entry.val); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("%w: unsupported value %T", ErrInvalidJSON, val)
	}
	return nil
}

func compareUTF16(a, b []uint16) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for i := 0; i < len(s); {
		b := s[i]
		if b < 0x80 {
			switch b {
			case '"':
				buf.WriteString(`\"`)
			case '\\':
				buf.WriteString(`\\`)
			case '\b':
				buf.WriteString(`\b`)
			case '\t':
				buf.WriteString(`\t`)
			case '\n':
				buf.WriteString(`\n`)
			case '\f':
				buf.WriteString(`\f`)
			case '\r':
				buf.WriteString(`\r`)
			default:
				if b < 0x20 {
					const hex = "0123456789abcdef"
					buf.WriteString(`\u00`)
					buf.WriteByte(hex[b>>4])
					buf.WriteByte(hex[b&0x0f])
				} else {
					buf.WriteByte(b)
				}
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		buf.WriteRune(r)
		i += size
	}
	buf.WriteByte('"')
}

// formatCanonicalNumber implements RFC 8785 Section 3.2.2.3 (ECMAScript
// Number.prototype.toString over IEEE-754 binary64, with exact integer fast-path
// within +/-2^53-1).
func formatCanonicalNumber(n json.Number) (string, error) {
	raw := n.String()
	// Fast path for exact safe integers without exponent or decimal point.
	if i64, err := strconv.ParseInt(raw, 10, 64); err == nil {
		const maxSafeInt = (1 << 53) - 1
		if i64 >= -maxSafeInt && i64 <= maxSafeInt {
			if i64 == 0 {
				return "0", nil
			}
			return strconv.FormatInt(i64, 10), nil
		}
	}

	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("%w: %q", ErrInvalidNumber, raw)
	}
	if f == 0 {
		return "0", nil
	}

	var sign string
	if f < 0 {
		sign = "-"
		f = -f
	}

	// Obtain shortest decimal digits and exponent via strconv ('e' format).
	sci := strconv.FormatFloat(f, 'e', -1, 64)
	eIdx := -1
	for i := 0; i < len(sci); i++ {
		if sci[i] == 'e' {
			eIdx = i
			break
		}
	}
	if eIdx < 0 {
		return "", fmt.Errorf("%w: %q", ErrInvalidNumber, raw)
	}

	mant := sci[:eIdx]
	exp, err := strconv.Atoi(sci[eIdx+1:])
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrInvalidNumber, raw)
	}

	var digits []byte
	for i := 0; i < len(mant); i++ {
		if mant[i] != '.' {
			digits = append(digits, mant[i])
		}
	}
	k := len(digits)
	// Value is 0.<digits> * 10^(exp+1), so nPos = exp + 1 in ES6 spec notation.
	nPos := exp + 1

	var out bytes.Buffer
	out.WriteString(sign)
	switch {
	case k <= nPos && nPos <= 21:
		out.Write(digits)
		for i := 0; i < nPos-k; i++ {
			out.WriteByte('0')
		}
	case 0 < nPos && nPos <= 21:
		out.Write(digits[:nPos])
		out.WriteByte('.')
		out.Write(digits[nPos:])
	case -5 <= nPos && nPos <= 0:
		out.WriteString("0.")
		for i := 0; i < -nPos; i++ {
			out.WriteByte('0')
		}
		out.Write(digits)
	default:
		out.WriteByte(digits[0])
		if k > 1 {
			out.WriteByte('.')
			out.Write(digits[1:])
		}
		out.WriteByte('e')
		if exp >= 0 {
			out.WriteByte('+')
		}
		out.WriteString(strconv.Itoa(exp))
	}
	return out.String(), nil
}
