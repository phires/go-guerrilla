package backends

import (
	"github.com/phires/go-guerrilla/mail"
)

// ----------------------------------------------------------------------------------
// Processor Name: localfiles
// ----------------------------------------------------------------------------------
// Description   : Dump the decoded content to local files
// ----------------------------------------------------------------------------------
// Config Options: Specify the location path to save the parts of the email
// --------------:-------------------------------------------------------------------
// Input         : envelope
// ----------------------------------------------------------------------------------
// Output        : Saved paths will be populated in e.LocalFilesPaths
// ----------------------------------------------------------------------------------
func init() {
	processors["localfiles"] = func() Decorator {
		return LocalFiles()
	}
}

type LocalFilesProcessorConfig struct {
	LocalStoragePath     string `json:"local_storage_path"`
}

func LocalFiles() Decorator {

	var config *LocalFilesProcessorConfig

	Svc.AddInitializer(InitializeWith(func(backendConfig BackendConfig) error {
		configType := BaseConfig(&LocalFilesProcessorConfig{})
		bcfg, err := Svc.ExtractConfig(backendConfig, configType)
		if err != nil {
			return err
		}
		config = bcfg.(*LocalFilesProcessorConfig)
		return nil
	}))


	return func(p Processor) Processor {
		return ProcessWith(func(e *mail.Envelope, task SelectTask) (Result, error) {
			if task == TaskSaveMail {
				if err := e.SaveLocalFiles(config.LocalStoragePath); err != nil {
					Log().WithError(err).Error("save local file error")
				}  else {
					Log().Info("Dumped Content is: ", e.LocalFilesPaths)
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

