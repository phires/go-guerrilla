package backends

import (
	"errors"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/phires/go-guerrilla/mail"
)

const DKIMSignatureHeaderFieldName = "DKIM-Signature"

func init() {
	processors["dkim"] = func() Decorator {
		return DKIM()
	}
}

func DKIM() Decorator {
	return func(p Processor) Processor {
		return ProcessWith(func(e *mail.Envelope, task SelectTask) (Result, error) {

			switch task {
			case TaskSaveMail:
				if dkimSignature := e.Header.Get(DKIMSignatureHeaderFieldName); dkimSignature == "" {
					return NewResult("556 5.7.20 No DKIM signature."), DKIMError
				}
				verifications, err := dkim.Verify(e.NewReader())
				if err != nil {
					Log().Errorf("DKIM error=%s", err)
					return NewResult("556 5.7.20 DKIM verification error."), DKIMError
				}
				for _, v := range verifications {
					if v.Err == nil {
						Log().Infoln("DKIM Valid signature for:", v.Domain)
					} else {
						Log().Infoln("DKIM Invalid signature for:", v.Domain, v.Err)
						return NewResult("556 5.7.0 Unauthorized sender. Email blocked due to policy reasons."), DKIMError
					}
				}
			case TaskTest:
				if dkimSignature := e.Header.Get(DKIMSignatureHeaderFieldName); dkimSignature == "" {
					return NewResult("556 5.7.20 No DKIM signature."), DKIMError
				}
				verifyOptions := dkim.VerifyOptions{
					LookupTXT: func(domain string) ([]string, error) {
						Log().Debugf("DKIM TXT lookup for %s", domain)
						if domain == "grrla._domainkey.example.com" {
							return []string{"v=DKIM1; k=ed25519; p=xSvJUKTEe5zW0XuekE6pkPyd/mhSfpVqSZ2yGtvbt/I="}, nil
						}
						return nil, errors.New("no such domain")
					},
				}
				verifications, err := dkim.VerifyWithOptions(e.NewReader(), &verifyOptions)
				if err != nil {
					Log().Errorf("DKIM error=%s", err)
					return NewResult("556 5.7.20 DKIM verification error."), DKIMError
				}
				for _, v := range verifications {
					if v.Err == nil {
						Log().Infoln("DKIM Valid signature for:", v.Domain)
					} else {
						Log().Infoln("DKIM Invalid signature for:", v.Domain, v.Err)
						return NewResult("556 5.7.0 Unauthorized sender. Email blocked due to policy reasons."), DKIMError
					}
				}
			}
			// next processor
			return p.Process(e, task)
		})
	}
}
