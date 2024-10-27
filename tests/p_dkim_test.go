package test

import (
	"os"
	"strings"
	"testing"

	"github.com/phires/go-guerrilla/backends"
	"github.com/phires/go-guerrilla/log"
	"github.com/phires/go-guerrilla/mail"
)

const verifiedMailString = `DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;
      c=simple/simple; q=dns/txt; i=joe@football.example.com;
      h=Received : From : To : Subject : Date : Message-ID;
      bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
      b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB
      4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut
      KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV
      4bmp/YzhwvcubU4=;
Received: from client1.football.example.com  [192.0.2.1]
      by submitserver.example.com with SUBMISSION;
      Fri, 11 Jul 2003 21:01:54 -0700 (PDT)
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>

Hi.

We lost the game. Are you hungry yet?

Joe.
`

// public key for testing dns/txt query method
const dnsPublicKey = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ" +
	"KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt" +
	"IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v" +
	"/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi" +
	"tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB"

func TestDKIM(t *testing.T) {

	e := mail.NewEnvelope("192.0.2.1", 1) //DNS spf ip record
	e.Data.WriteString(verifiedMailString)

	l, _ := log.GetLogger("./test_dkim.log", "debug")
	g, err := backends.New(backends.BackendConfig{
		"save_process":      "HeadersParser|DKIM",
		"primary_mail_host": "example.com",
	}, l)
	if err != nil {
		t.Error(err)
		return
	}
	err = g.Start()
	if err != nil {
		t.Error(err)
		return
	}
	defer func() {
		err := g.Shutdown()
		if err != nil {
			t.Error(err)
		}
	}()
	if gateway, ok := g.(*backends.BackendGateway); ok {
		r := gateway.Process(e)
		if !strings.Contains(r.String(), "250 2.0.0 OK") {
			t.Error("DKIM processor didn't result with expected result, it said", r)
		}
	}
	// check the log
	if _, err := os.Stat("./test_dkim.log"); err != nil {
		t.Error(err)
		return
	}
	if b, err := os.ReadFile("./test_dkim.log"); err != nil {
		t.Error(err)
		return
	} else if !strings.Contains(string(b), "DKIM Valid signature") {
		t.Error("Log did not contain 'DKIM Valid signature', the log was: ", string(b))
		return
	}

	if err := l.Close(); err != nil {
		t.Error(err)
		return
	}

	if err := os.Remove("./test_dkim.log"); err != nil {
		t.Error(err)
		return
	}

}
