package backends

import (
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
			if task == TaskSaveMail {

				if dkimSignature := e.Header.Get(DKIMSignatureHeaderFieldName); dkimSignature == "" {
					return NewResult("556 5.7.20 No DKIM signature."), DKIMError
				}

				verifications, err := dkim.Verify(&e.Data)
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

				// next processor
				return p.Process(e, task)
			} else {
				// next processor
				return p.Process(e, task)
			}
		})
	}
}
