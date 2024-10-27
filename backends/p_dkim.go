package backends

import (
	"io"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/phires/go-guerrilla/mail"
)

const DKIMSignatureHeaderFieldName = "DKIM-Signature"

func init() {
	processors["dkim"] = func() Decorator {
		return DKIM()
	}
}

type DKIMConfig struct {
	Test bool `json:"dkim_test"`
}

type DKIMProcessor struct {
	config *DKIMConfig
}

func (d DKIMProcessor) verify(r io.Reader) ([]*dkim.Verification, error) {

	if d.config.Test {
		return dkim.VerifyWithOptions(r, &dkim.VerifyOptions{
			LookupTXT: func(domain string) ([]string, error) {
				if domain == "guerrilla.test" {
					return []string{"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4xKeUgQ+Aoz7TLfAfs9+paePb5KIofVthEopwrXFkp8OCeocaTHt9ICjTT2QeJh6cZaDaArfZ+YbG4OD/Slg5f1LzdRuntimeError"}, nil
				}
				return nil, nil
			},
		})
	} else {
		return dkim.Verify(r)
	}

}

func DKIM() Decorator {
	var config *DKIMConfig
	s := &DKIMProcessor{}

	initFunc := InitializeWith(func(backendConfig BackendConfig) error {
		configType := BaseConfig(&DKIMConfig{})
		bcfg, err := Svc.ExtractConfig(backendConfig, configType)
		if err != nil {
			return err
		}
		config = bcfg.(*DKIMConfig)
		s.config = config
		return nil
	})
	Svc.AddInitializer(initFunc)

	return func(p Processor) Processor {
		return ProcessWith(func(e *mail.Envelope, task SelectTask) (Result, error) {
			if task == TaskSaveMail {

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

				// next processor
				return p.Process(e, task)
			} else {
				// next processor
				return p.Process(e, task)
			}
		})
	}
}
