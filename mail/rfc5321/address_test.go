package rfc5321

import (
	"strings"
	"testing"
	"time"
)

// addressWithDeadline parses input, failing the test if the parser doesn't
// terminate. next() returns 0 at the end of the input, but used to leave s.ch
// pointing at the last byte read. atom() and skipSpace() loop on s.ch, so an
// input ending in an atom or in whitespace made them spin forever, appending
// s.ch to s.accept on every iteration until the process was OOM-killed.
func addressWithDeadline(t *testing.T, s *RFC5322, input string) (AddressList, error) {
	t.Helper()
	type result struct {
		list AddressList
		err  error
	}
	done := make(chan result, 1)
	go func() {
		l, err := s.Address([]byte(input))
		done <- result{list: l, err: err}
	}()
	select {
	case r := <-done:
		return r.list, r.err
	case <-time.After(2 * time.Second):
		t.Fatalf("Address(%q) did not terminate within 2s, the parser is looping", input)
		return AddressList{}, nil
	}
}

// An address that ends on an atom or on whitespace must terminate. These inputs
// are reachable through mail.NewAddress on attacker controlled headers, eg.
// "From: hello".
func TestParseRFC5322TerminatesAtEOF(t *testing.T) {
	inputs := []string{
		"hello",
		"hello world",
		"a ",
		"a\t",
		"hello ",
		"Mike Jones <test@tdomain.com",
		"test@tdomain.com ",
		"A Group:Ed Jones <c@a.test>,joe@where.test",
	}
	for _, input := range inputs {
		var s RFC5322
		list, err := addressWithDeadline(t, &s, input)
		if err == nil && len(list.List) == 0 {
			t.Errorf("Address(%q): expecting either an error or an address, got neither", input)
		}
	}
}

// A mailbox without an "@" is not an address, so it must be reported as an
// error rather than silently yielding a half parsed address.
func TestParseRFC5322BareAtomIsNotAnAddress(t *testing.T) {
	for _, input := range []string{"hello", "hello world", "a "} {
		var s RFC5322
		list, err := addressWithDeadline(t, &s, input)
		if err == nil {
			t.Errorf("Address(%q): expecting an error, got none", input)
		}
		if len(list.List) != 0 {
			t.Errorf("Address(%q): expecting 0 addresses, got %d", input, len(list.List))
		}
	}
}

// next() must clear s.ch once the input is exhausted, otherwise every loop that
// advances with next() but tests s.ch never sees the end of the input.
func TestParserNextClearsChAtEOF(t *testing.T) {
	s := NewParser([]byte("a"))
	if c := s.next(); c != 'a' || s.ch != 'a' {
		t.Fatalf("expecting next() and s.ch to be 'a', got %q / %q", c, s.ch)
	}
	if c := s.next(); c != 0 {
		t.Errorf("expecting next() to return 0 at the end of the input, got %q", c)
	}
	if s.ch != 0 {
		t.Errorf("expecting s.ch to be 0 at the end of the input, got %q", s.ch)
	}
}

// Reset() must clear s.ch too, so that a reused parser doesn't decide based on
// the last byte of the previous input. server.go keeps one parser per client and
// reuses it for every command, and Helo/Ehlo test s.ch right after set()+next(),
// which doesn't read anything for an empty argument.
func TestParserResetClearsCh(t *testing.T) {
	// the mail parameters production runs into the end of the input, which used
	// to leave s.ch on the trailing space
	reused := NewParser(nil)
	if err := reused.MailFrom([]byte("<test@tdomain.com> ")); err == nil {
		t.Fatal("expecting a parse error for the empty mail parameter")
	}
	if reused.ch != 0 {
		t.Fatalf("expecting s.ch to be 0 at the end of the input, got %q", reused.ch)
	}
	// a reused parser must answer exactly like a fresh one
	fresh := NewParser(nil)
	_, freshErr := fresh.Helo(nil)
	_, reusedErr := reused.Helo(nil)
	if freshErr == nil || reusedErr == nil {
		t.Fatal("expecting an error for an empty HELO argument")
	}
	if freshErr.Error() != reusedErr.Error() {
		t.Errorf("a reused parser reported %q, a fresh one reported %q", reusedErr, freshErr)
	}
}

// Bound the work that a single header value can ask for.
func TestParseRFC5322InputLimit(t *testing.T) {
	var s RFC5322
	long := strings.Repeat("a", LimitAddressList-len("@tdomain.com")) + "@tdomain.com"
	if _, err := addressWithDeadline(t, &s, long); err != nil {
		t.Errorf("expecting an input of %d bytes to be accepted, got: %v", len(long), err)
	}
	// valid, but longer than the limit
	tooLong := strings.Repeat("a", LimitAddressList) + "@tdomain.com"
	if list, err := addressWithDeadline(t, &s, tooLong); err == nil {
		t.Error("expecting an error for an over-long input, got none")
	} else if len(list.List) != 0 {
		t.Errorf("expecting 0 addresses for an over-long input, got %d", len(list.List))
	}
}

func TestParseRFC5322(t *testing.T) {
	var s RFC5322
	if _, err := s.Address([]byte("\"Mike Jones\" <test@tdomain.com>")); err != nil {
		t.Error(err)
	}
	// parse a simple address
	if a, err := s.Address([]byte("test@tdomain.com")); err != nil {
		t.Error(err)
	} else {
		if len(a.List) != 1 {
			t.Error("expecting 1 address")
		} else {
			// display name should be empty
		}
	}
}

func TestParseRFC5322Decoder(t *testing.T) {
	var s RFC5322
	if _, err := s.Address([]byte("=?ISO-8859-1?Q?Andr=E9?= =?ISO-8859-1?Q?Andr=E9?= <test@tdomain.com>")); err != nil {
		t.Error(err)
	}
}

func TestParseRFC5322IP(t *testing.T) {
	var s RFC5322
	// this is an incorrect IPv6 address
	if _, err := s.Address([]byte("\"Mike Jones\" <\"testing 123\"@[IPv6:IPv6:2001:db8::1]>")); err == nil {
		t.Error("Expecting error, because Ip address was wrong")
	}
	// this one is correct, with quoted display name and quoted local-part
	if a, err := s.Address([]byte("\"Mike Jones\" <\"testing 123\"@[IPv6:2001:db8::1]>")); err != nil {
		t.Error(err)
	} else {
		if len(a.List) != 1 {
			t.Error("expecting 1 address, but got", len(a.List))
		} else {
			if a.List[0].DisplayNameQuoted == false {
				t.Error(".List[0].DisplayNameQuoted is false, expecting true")
			}
			if a.List[0].LocalPartQuoted == false {
				t.Error(".List[0].LocalPartQuotes is false, expecting true")
			}
			if a.List[0].IP == nil {
				t.Error("a.List[0].IP should not be nil")
			}
			if a.List[0].Domain != "2001:db8::1" {
				t.Error("a.List[0].Domain should be, but got", a.List[0].Domain)
			}
		}
	}
}

func TestParseRFC5322Group(t *testing.T) {
	// A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;
	var s RFC5322
	if a, err := s.Address([]byte("A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test> , \"te \\\" st\"<test@example.com> ;")); err != nil {
		t.Error(err)
	} else {
		if a.Group != "A Group" {
			t.Error("expecting a.Group to be \"A Group\" but got:", a.Group)
		}
		if len(a.List) != 4 {
			t.Error("expecting 4 addresses, but got", len(a.List))
		} else {
			if a.List[0].DisplayName != "Ed Jones" {
				t.Error("expecting a.List[0].DisplayName 'Ed Jones' but got:", a.List[0].DisplayName)
			}
			if a.List[0].LocalPart != "c" {
				t.Error("expecting a.List[0].LocalPart 'c' but got:", a.List[0].LocalPart)
			}
			if a.List[0].Domain != "a.test" {
				t.Error("expecting a.List[0].Domain 'a.test' but got:", a.List[0].Domain)
			}
		}

	}
}
