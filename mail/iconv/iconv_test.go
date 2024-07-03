package iconv

import (
	"strings"
	"testing"

	"github.com/jonkwee/go-guerrilla/mail"
)

// This will use the iconv encoder
func TestIconvMimeHeaderDecode(t *testing.T) {
	str := mail.MimeHeaderDecode("=?ISO-2022-JP?B?GyRCIVo9dztSOWJAOCVBJWMbKEI=?=")
	if i := strings.Index(str, "【女子高生チャ"); i != 0 {
		t.Error("expecting 【女子高生チャ, got:", str)
	}
	str = mail.MimeHeaderDecode("=?ISO-8859-1?Q?Andr=E9?= Pirard <PIRARD@vm1.ulg.ac.be>")
	if strings.Index(str, "André Pirard") != 0 {
		t.Error("expecting André Pirard, got:", str)
	}
}
