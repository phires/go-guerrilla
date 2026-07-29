package guerrilla

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/phires/go-guerrilla/log"
	"github.com/phires/go-guerrilla/mail"
)

var (
	ErrPoolShuttingDown = errors.New("server pool: shutting down")
)

// a struct can be pooled if it has the following interface
type Poolable interface {
	// ability to set read/write timeout
	setTimeout(t time.Duration) error
	// set a new connection and client id
	init(c net.Conn, clientID uint64, ep *mail.Pool)
	// get a unique id
	getID() uint64
	kill()
}

// Pool holds Clients.
type Pool struct {
	// clients that are ready to be borrowed
	pool chan Poolable
	// semaphore to control number of maximum borrowed clients
	sem chan bool
	// book-keeping of clients that have been lent
	activeClients     lentClients
	isShuttingDownFlg atomic.Value
	poolGuard         sync.Mutex
	ShutdownChan      chan int
	// shutdownSignal gets closed when a shutdown begins, and replaced by a fresh
	// channel once the pool has drained so that the pool can be reused. Closing a
	// channel broadcasts, which releases *every* Borrow that waits for a free
	// slot - ShutdownChan carries a single value and could only release one.
	// Guarded by poolGuard.
	shutdownSignal chan struct{}
}

type lentClients struct {
	m  map[uint64]Poolable
	mu sync.Mutex // guards access to this struct
	wg sync.WaitGroup
}

// maps the callback on all lentClients
func (c *lentClients) mapAll(callback func(p Poolable)) {
	defer c.mu.Unlock()
	c.mu.Lock()
	for _, item := range c.m {
		callback(item)
	}
}

// operation performs an operation on a Poolable item using the callback
func (c *lentClients) operation(callback func(p Poolable), item Poolable) {
	defer c.mu.Unlock()
	c.mu.Lock()
	callback(item)
}

// NewPool creates a new pool of Clients.
func NewPool(poolSize int) *Pool {
	return &Pool{
		pool:           make(chan Poolable, poolSize),
		sem:            make(chan bool, poolSize),
		activeClients:  lentClients{m: make(map[uint64]Poolable, poolSize)},
		ShutdownChan:   make(chan int, 1),
		shutdownSignal: make(chan struct{}),
	}
}

// shutdownSignalled reports whether a shutdown has already been broadcast.
// The caller must hold poolGuard.
func (p *Pool) shutdownSignalled() bool {
	select {
	case <-p.shutdownSignal:
		return true
	default:
		return false
	}
}
func (p *Pool) Start() {
	p.isShuttingDownFlg.Store(true)
}

// Lock the pool from borrowing then remove all active clients
// each active client's timeout is lowered to 1 sec and notified
// to stop accepting commands
//
// Safe to call more than once: a repeated call only refreshes the timeouts.
func (p *Pool) ShutdownState() {
	const aVeryLowTimeout = 1
	p.poolGuard.Lock() // ensure no other thread is in the borrowing now
	defer p.poolGuard.Unlock()
	p.isShuttingDownFlg.Store(true) // no more borrowing
	if !p.shutdownSignalled() {
		close(p.shutdownSignal) // release every Borrow waiting on p.sem
	}
	// kept for callers that watch the exported channel themselves. The send is
	// non-blocking: the buffer holds a single value and nothing drains it until
	// ShutdownWait runs, so a second ShutdownState must not get stuck here.
	select {
	case p.ShutdownChan <- 1:
	default:
	}

	// set a low timeout (let the clients finish whatever the're doing)
	p.activeClients.mapAll(func(p Poolable) {
		if err := p.setTimeout(time.Duration(int64(aVeryLowTimeout))); err != nil {
			p.kill()
		}
	})

}

func (p *Pool) ShutdownWait() {
	p.poolGuard.Lock() // ensure no other thread is in the borrowing now
	defer p.poolGuard.Unlock()
	p.activeClients.wg.Wait() // wait for clients to finish
	if len(p.ShutdownChan) > 0 {
		// drain
		<-p.ShutdownChan
	}
	p.isShuttingDownFlg.Store(false)
	if p.shutdownSignalled() {
		// hand out a fresh signal, so that the pool can be borrowed from again
		// when the server gets restarted
		p.shutdownSignal = make(chan struct{})
	}
}

// returns true if the pool is shutting down
func (p *Pool) IsShuttingDown() bool {
	if value, ok := p.isShuttingDownFlg.Load().(bool); ok {
		return value
	}
	return false
}

// set a timeout for all lent clients
func (p *Pool) SetTimeout(duration time.Duration) {
	p.activeClients.mapAll(func(p Poolable) {
		if err := p.setTimeout(duration); err != nil {
			p.kill()
		}
	})
}

// Gets the number of active clients that are currently
// out of the pool and busy serving
func (p *Pool) GetActiveClientsCount() int {
	return len(p.sem)
}

// Borrow a Client from the pool. Will block if len(activeClients) > maxClients,
// until a client is returned or the pool starts shutting down.
// Returns a nil Poolable together with ErrPoolShuttingDown when it gives up.
func (p *Pool) Borrow(conn net.Conn, clientID uint64, logger log.Logger, ep *mail.Pool) (Poolable, error) {
	var c Poolable

	p.poolGuard.Lock()
	if p.IsShuttingDown() {
		// pool is shutting down.
		p.poolGuard.Unlock()
		return c, ErrPoolShuttingDown
	}
	shutdown := p.shutdownSignal
	p.poolGuard.Unlock()

	// Wait for a free slot *without* holding poolGuard. ShutdownState needs that
	// same lock to signal the shutdown, and that signal is the only thing that can
	// release us here: holding the lock across this wait wedges every shutdown
	// while the pool is saturated.
	select {
	case p.sem <- true: // block the client from serving until there is room
	case <-shutdown: // unblock p.sem when shutting down
		// pool is shutting down.
		return c, ErrPoolShuttingDown
	}

	p.poolGuard.Lock()
	defer p.poolGuard.Unlock()
	if p.IsShuttingDown() {
		// the pool started shutting down while we were waiting for a slot, hand it
		// back instead of putting another client to work
		<-p.sem
		return c, ErrPoolShuttingDown
	}
	select {
	case c = <-p.pool:
		c.init(conn, clientID, ep)
	default:
		c = NewClient(conn, clientID, logger, ep)
	}
	p.activeClientsAdd(c)
	return c, nil
}

// Return returns a Client back to the pool.
func (p *Pool) Return(c Poolable) {
	p.activeClientsRemove(c)
	select {
	case p.pool <- c:
	default:
		// hasta la vista, baby...
	}

	<-p.sem // make room for the next serving client
}

func (p *Pool) activeClientsAdd(c Poolable) {
	p.activeClients.operation(func(item Poolable) {
		p.activeClients.wg.Add(1)
		p.activeClients.m[c.getID()] = item
	}, c)
}

func (p *Pool) activeClientsRemove(c Poolable) {
	p.activeClients.operation(func(item Poolable) {
		delete(p.activeClients.m, item.getID())
		p.activeClients.wg.Done()
	}, c)
}
