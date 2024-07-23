package backends

import (
	"github.com/phires/go-guerrilla/mail"
)

// ----------------------------------------------------------------------------------
// Processor Name: contentparser
// ----------------------------------------------------------------------------------
// Description   : Parses and decodes the content
// ----------------------------------------------------------------------------------
// Config Options: Specify the location path to save the parts of the email
// --------------:-------------------------------------------------------------------
// Input         : envelope
// ----------------------------------------------------------------------------------
// Output        : Content will be populated in e.Content
// ----------------------------------------------------------------------------------
func init() {
	processors["contentparser"] = func() Decorator {
		return ContentParser()
	}
}

type ContentParserProcessorConfig struct {
	LocalStoragePath     string `json:"local_storage_path"`
}

func ContentParser() Decorator {

	var config *ContentParserProcessorConfig

	Svc.AddInitializer(InitializeWith(func(backendConfig BackendConfig) error {
		configType := BaseConfig(&ContentParserProcessorConfig{})
		bcfg, err := Svc.ExtractConfig(backendConfig, configType)
		if err != nil {
			return err
		}
		config = bcfg.(*ContentParserProcessorConfig)
		return nil
	}))


	return func(p Processor) Processor {
		return ProcessWith(func(e *mail.Envelope, task SelectTask) (Result, error) {
			if task == TaskSaveMail {
				if err := e.ParseContent(config.LocalStoragePath); err != nil {
					Log().WithError(err).Error("parse content error")
				} else {
					Log().Info("Parsed Content is: ", e.LocalFileContent)
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

