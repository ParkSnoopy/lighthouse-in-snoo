package jcs_test

import (
	"errors"
	"testing"

	"lighthouse-in-snoo/internal/jcs"
)

func TestCanonicalizeRFC8785(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "sorted keys and whitespace removal",
			input: `{ "z": 1, "a": [ true, false, null ], "m": "ok" }`,
			want:  `{"a":[true,false,null],"m":"ok","z":1}`,
		},
		{
			name:  "utf16 code unit ordering supplementary vs bmp",
			input: "{\"\\ue000\":1,\"\\ud83d\\ude00\":2,\"a\":0}",
			// U+1F600 (0xD83D 0xDE00) sorts BEFORE U+E000 (0xE000) in UTF-16 code unit order!
			want: "{\"a\":0,\"😀\":2,\"\ue000\":1}",
		},
		{
			name:  "control character escaping and unescaped html chars",
			input: `{"s":"\u0000\u0008\u0009\u000a\u000c\u000d\u001f\"\\/<>&"}`,
			want:  `{"s":"\u0000\b\t\n\f\r\u001f\"\\/<>&"}`,
		},
		{
			name:  "number canonicalization",
			input: `{"negzero":-0.0,"int":42,"frac":100.50,"small":0.000001,"tiny":0.0000001}`,
			want:  `{"frac":100.5,"int":42,"negzero":0,"small":0.000001,"tiny":1e-7}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := jcs.Canonicalize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Canonicalize unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("Canonicalize = %q; want %q", string(got), tt.want)
			}
		})
	}
}

func TestRejectDuplicateKeysAndMalformedInput(t *testing.T) {
	t.Parallel()

	badInputs := []struct {
		name string
		raw  string
		err  error
	}{
		{"top-level duplicate key", `{"v":1,"v":2}`, jcs.ErrDuplicateKey},
		{"nested duplicate key", `{"v":1,"body":{"sdp":"a","sdp":"b"}}`, jcs.ErrDuplicateKey},
		{"trailing garbage", `{"v":1} {"v":2}`, jcs.ErrInvalidJSON},
		{"empty input", ``, jcs.ErrInvalidJSON},
		{"invalid utf8", "{\"a\":\"\xff\"}", jcs.ErrInvalidUTF8},
	}

	for _, tc := range badInputs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := jcs.Canonicalize([]byte(tc.raw))
			if !errors.Is(err, tc.err) {
				t.Fatalf("Canonicalize(%s) err = %v; want %v", tc.name, err, tc.err)
			}
		})
	}
}

func TestUnmarshalStrictDisallowsUnknownFields(t *testing.T) {
	t.Parallel()

	type sample struct {
		V    int    `json:"v"`
		Type string `json:"type"`
	}
	var dst sample
	if err := jcs.UnmarshalStrict([]byte(`{"v":1,"type":"heartbeat","extra":true}`), &dst); err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
}
