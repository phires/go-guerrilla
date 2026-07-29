package backends

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phires/go-guerrilla/log"
	"github.com/phires/go-guerrilla/mail"
)

func TestStates(t *testing.T) {
	gw := BackendGateway{}
	str := gw.State.String()
	if strings.Index(str, "NewState") != 0 {
		t.Error("Backend should begin in NewState")
	}
}

func TestInitialize(t *testing.T) {
	c := BackendConfig{
		"save_process":       "HeadersParser|Debugger",
		"log_received_mails": true,
		"save_workers_size":  "1",
	}

	gateway := &BackendGateway{}
	err := gateway.Initialize(c)
	if err != nil {
		t.Error("Gateway did not init because:", err)
		t.Fail()
	}
	if gateway.processors == nil {
		t.Error("gateway.chains should not be nil")
	} else if len(gateway.processors) != 1 {
		t.Error("len(gateway.chains) should be 1, but got", len(gateway.processors))
	}

	if gateway.conveyor == nil {
		t.Error("gateway.conveyor should not be nil")
	} else if cap(gateway.conveyor) != gateway.workersSize() {
		t.Error("gateway.conveyor channel buffer cap does not match worker size, cap was", cap(gateway.conveyor))
	}

	if gateway.GetState() != BackendStateInitialized {
		t.Error("gateway state is not in initialized state, got ", gateway.GetState())
	}

}

func TestStartProcessStop(t *testing.T) {
	c := BackendConfig{
		"save_process":       "HeadersParser|Debugger",
		"log_received_mails": true,
		"save_workers_size":  2,
	}

	gateway := &BackendGateway{}
	err := gateway.Initialize(c)

	mainlog, _ := log.GetLogger(log.OutputOff.String(), "debug")
	Svc.SetMainlog(mainlog)

	if err != nil {
		t.Error("Gateway did not init because:", err)
		t.Fail()
	}
	err = gateway.Start()
	if err != nil {
		t.Error("Gateway did not start because:", err)
		t.Fail()
	}
	if gateway.GetState() != BackendStateRunning {
		t.Error("gateway state is not in running state, got ", gateway.GetState())
	}
	// can we place an envelope on the conveyor channel?

	e := &mail.Envelope{
		RemoteIP: "127.0.0.1",
		QueuedId: "abc12345",
		Helo:     "helo.example.com",
		MailFrom: mail.Address{User: "test", Host: "example.com"},
		TLS:      true,
	}
	e.PushRcpt(mail.Address{User: "test", Host: "example.com"})
	e.Data.WriteString("Subject:Test\n\nThis is a test.")
	notify := make(chan *notifyMsg)

	gateway.conveyor <- &workerMsg{e, notify, TaskSaveMail}

	// it should not produce any errors
	// headers (subject) should be parsed.

	select {
	case status := <-notify:

		if status.err != nil {
			t.Error("envelope processing failed with:", status.err)
		}
		if e.Header["Subject"][0] != "Test" {
			t.Error("envelope processing did not parse header")
		}

	case <-time.After(time.Second):
		t.Error("gateway did not respond after 1 second")
		t.Fail()
	}

	err = gateway.Shutdown()
	if err != nil {
		t.Error("Gateway did not shutdown")
	}
}

// TestGatewayStateRace covers H1: the gateway's state is written under gw.Mutex
// by Initialize/Start/Shutdown, but Process and ValidateRcpt used to read it
// without holding the lock. Only meaningful when run with -race.
func TestGatewayStateRace(t *testing.T) {
	c := BackendConfig{
		"save_process":       "HeadersParser|Debugger",
		"log_received_mails": true,
		"save_workers_size":  1,
	}
	mainlog, _ := log.GetLogger(log.OutputOff.String(), "info")
	Svc.SetMainlog(mainlog)

	gateway := &BackendGateway{}
	if err := gateway.Initialize(c); err != nil {
		t.Fatal("gateway did not init because:", err)
	}
	if err := gateway.Start(); err != nil {
		t.Fatal("gateway did not start because:", err)
	}

	begin := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := &mail.Envelope{RemoteIP: "127.0.0.1", QueuedId: "abc12345"}
			e.PushRcpt(mail.Address{User: "test", Host: "example.com"})
			<-begin
			for k := 0; k < 100; k++ {
				// reads the state
				_ = gateway.ValidateRcpt(e)
			}
		}()
	}
	close(begin)
	// writes the state
	if err := gateway.Shutdown(); err != nil {
		t.Error("gateway did not shutdown because:", err)
	}
	wg.Wait()

	if gateway.GetState() != BackendStateShuttered {
		t.Error("gateway should be in shuttered state, got", gateway.GetState())
	}
	// the deprecated State field has to stay in sync with the atomic one
	if gateway.State != gateway.GetState() {
		t.Error("the deprecated State field should mirror GetState(), got",
			gateway.State, "want", gateway.GetState())
	}
}
