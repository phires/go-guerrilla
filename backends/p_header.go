package backends

import (
	"strings"
	"time"

	"github.com/phires/go-guerrilla/mail"
)

type HeaderConfig struct {
	PrimaryHost string `json:"primary_mail_host"`
}

// ----------------------------------------------------------------------------------
// Processor Name: header
// ----------------------------------------------------------------------------------
// Description   : Adds delivery information headers to e.DeliveryHeader
// ----------------------------------------------------------------------------------
// Config Options: none
// --------------:-------------------------------------------------------------------
// Input         : e.Helo
//
//	: e.RemoteAddress
//	: e.RcptTo
//	: e.Hashes
//
// ----------------------------------------------------------------------------------
// Output        : Sets e.DeliveryHeader with additional delivery info
// ----------------------------------------------------------------------------------
func init() {
	processors["header"] = func() Decorator {
		return Header()
	}
}

// Generate the MTA delivery header
// Sets e.DeliveryHeader part of the envelope with the generated header
func Header() Decorator {

	var config *HeaderConfig

	Svc.AddInitializer(InitializeWith(func(backendConfig BackendConfig) error {
		configType := BaseConfig(&HeaderConfig{})
		bcfg, err := Svc.ExtractConfig(backendConfig, configType)
		if err != nil {
			return err
		}
		config = bcfg.(*HeaderConfig)
		return nil
	}))

	return func(p Processor) Processor {
		return ProcessWith(func(e *mail.Envelope, task SelectTask) (Result, error) {
			switch task {
			case TaskSaveMail, TaskTest:
				to := strings.TrimSpace(e.RcptTo[0].User) + "@" + config.PrimaryHost
				hash := "unknown"
				if len(e.Hashes) > 0 {
					hash = e.Hashes[0]
				}
				protocol := "SMTP"
				if e.ESMTP {
					protocol = "E" + protocol
				}
				if e.TLS {
					protocol = protocol + "S"
				}
				var addHead string
				addHead += "Delivered-To: " + to + "\n"
				addHead += "Received: from " + e.RemoteIP + " ([" + e.RemoteIP + "])\n"
				if len(e.RcptTo) > 0 {
					addHead += "	by " + e.RcptTo[0].Host + " with " + protocol + " id " + hash + "@" + e.RcptTo[0].Host + ";\n"
				}
				addHead += "	" + time.Now().Format(time.RFC1123Z) + "\n"
				// save the result
				e.DeliveryHeader = addHead
			}
			// next processor
			return p.Process(e, task)
		})
	}
}
