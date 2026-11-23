package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/bits"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/rivo/tview"
	"golang.org/x/net/ipv4"
)

const defaultResolversURL = "https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt"

// userAgent is a common desktop browser string so the resolver list fetch is not tagged as Go
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"

type Config struct {
	concurrency int
	timeout     time.Duration
	retries     int
	dnsServers  []*resolver
	serverIndex int
	debug       bool
	output      *lineWriter // -o file
	stdout      *lineWriter // -j
	mu          sync.Mutex
	loop        bool
	excludes    []ipRange
	queries     uint64 // queries sent, retries included
	retried     uint64 // queries that were retries
}

type Stats struct {
	processed     uint64
	total         uint64
	lastProcessed uint64
	lastCheckTime time.Time
	startTime     time.Time
	success       uint64
	failed        uint64
	cnameOnly     uint64              // answers that were only a CNAME, no PTR behind it
	viaCNAME      uint64              // PTRs reached through an RFC 2317 CNAME
	outcomes      [numOutcomes]uint64 // final result of each failed lookup, for the stats line
	speedHistory  []float64
	mu            sync.Mutex
	round         uint64 // 0-based, shown as round+1
	next          uint64 // next counter value to dispatch
	track         tracker
}

func (s *Stats) increment() {
	atomic.AddUint64(&s.processed, 1)
}

func (s *Stats) incrementSuccess() {
	atomic.AddUint64(&s.success, 1)
}

func (s *Stats) incrementFailed() {
	atomic.AddUint64(&s.failed, 1)
}

func (s *Stats) countCNAME(recordType string) {
	if recordType == "CNAME" {
		atomic.AddUint64(&s.cnameOnly, 1)
	} else {
		atomic.AddUint64(&s.viaCNAME, 1)
	}
}

const (
	benchAfter = 20               // consecutive failures before a resolver is benched (reverse DNS fails often on good resolvers, 5 benched most of them)
	benchFor   = 10 * time.Minute // how long a benched resolver is skipped
)

// resolver is a DNS server with its health: timeouts, REFUSED, SERVFAIL and the like count as failures
type resolver struct {
	host         string // IP without port, for output
	udp          *net.UDPAddr
	fails        int32
	benchedUntil int64 // unix nanoseconds
}

// newResolvers parses ip:port addresses, skipping anything that is not IPv4 (the query sockets are IPv4)
func newResolvers(addrs []string) ([]*resolver, error) {
	var resolvers []*resolver
	for _, addr := range addrs {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil || !ap.Addr().Is4() {
			fmt.Fprintf(os.Stderr, "Skipping resolver %q: not an IPv4 address\n", addr)
			continue
		}
		resolvers = append(resolvers, &resolver{host: ap.Addr().String(), udp: net.UDPAddrFromAddrPort(ap)})
	}
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("no usable IPv4 resolvers")
	}
	return resolvers, nil
}

func (r *resolver) benched(now int64) bool {
	return atomic.LoadInt64(&r.benchedUntil) > now
}

func (r *resolver) ok() {
	atomic.StoreInt32(&r.fails, 0)
}

func (r *resolver) fail() {
	if atomic.AddInt32(&r.fails, 1) >= benchAfter {
		atomic.StoreInt32(&r.fails, 0)
		atomic.StoreInt64(&r.benchedUntil, time.Now().Add(benchFor).UnixNano())
	}
}

// getNextServer returns the next resolver in rotation that is not benched (or the next one if all are)
func (c *Config) getNextServer() *resolver {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.dnsServers) == 0 {
		return nil
	}

	now := time.Now().UnixNano()
	for range c.dnsServers {
		r := c.dnsServers[c.serverIndex]
		c.serverIndex = (c.serverIndex + 1) % len(c.dnsServers)
		if !r.benched(now) {
			return r
		}
	}
	return c.dnsServers[c.serverIndex]
}

// activeResolvers counts the resolvers that are not benched
func (c *Config) activeResolvers() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now, active := time.Now().UnixNano(), 0
	for _, r := range c.dnsServers {
		if !r.benched(now) {
			active++
		}
	}
	return active, len(c.dnsServers)
}

func fetchDefaultResolvers() ([]string, error) {
	req, err := http.NewRequest("GET", defaultResolversURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch default resolvers: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch default resolvers: %s", resp.Status)
	}

	var resolvers []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		resolver := strings.TrimSpace(scanner.Text())
		if resolver != "" {
			resolvers = append(resolvers, resolver)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading default resolvers: %v", err)
	}

	return resolvers, nil
}

func loadDNSServers(dnsFile string) ([]string, error) {
	if dnsFile == "" {
		resolvers, err := fetchDefaultResolvers()
		if err != nil {
			return nil, err
		}
		if len(resolvers) == 0 {
			return nil, fmt.Errorf("no default resolvers found")
		}
		return addDefaultPort(resolvers), nil
	}

	file, err := os.Open(dnsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open DNS servers file: %v", err)
	}
	defer file.Close()

	var servers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		server := strings.TrimSpace(scanner.Text())
		if server != "" {
			servers = append(servers, server)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading DNS servers file: %v", err)
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf("no DNS servers found in file")
	}

	return addDefaultPort(servers), nil
}

func addDefaultPort(servers []string) []string {
	for i, server := range servers {
		if !strings.Contains(server, ":") {
			servers[i] = server + ":53"
		}
	}
	return servers
}

type DNSResponse struct {
	Names      []string
	RecordType string // "PTR" or "CNAME"
	Target     string // CNAME target, if the answer had one
	TTL        uint32 // Add TTL field
}

func translateRcode(rcode int) string {
	switch rcode {
	case dns.RcodeSuccess:
		return "Success"
	case dns.RcodeFormatError:
		return "Format Error"
	case dns.RcodeServerFailure:
		return "Server Failure"
	case dns.RcodeNameError: // NXDOMAIN
		return "No Such Domain"
	case dns.RcodeNotImplemented:
		return "Not Implemented"
	case dns.RcodeRefused:
		return "Query Refused"
	default:
		return fmt.Sprintf("DNS Error %d", rcode)
	}
}

var errTimeout = errors.New("i/o timeout")

// outcomes of a failed lookup, counted for the stats line
const (
	outNXDomain = iota
	outServFail
	outRefused
	outNoPTR
	outTimeout
	outOther
	numOutcomes
)

var outcomeNames = [numOutcomes]string{"nxdomain", "servfail", "refused", "noptr", "timeout", "other"}

// outcome sorts a lookup's final error into one of the stats line buckets
func outcome(err error) int {
	switch {
	case errors.Is(err, errTimeout):
		return outTimeout
	case err.Error() == translateRcode(dns.RcodeNameError):
		return outNXDomain
	case err.Error() == translateRcode(dns.RcodeServerFailure):
		return outServFail
	case err.Error() == translateRcode(dns.RcodeRefused):
		return outRefused
	case err.Error() == "no PTR records found":
		return outNoPTR
	}
	return outOther
}

// parseAnswer interprets a response; final is false for errors worth retrying on another resolver
func parseAnswer(r *dns.Msg) (resp DNSResponse, err error, final bool) {
	// NXDOMAIN is a final answer, other error codes are retried on the next server
	if r.Rcode == dns.RcodeNameError {
		return DNSResponse{}, fmt.Errorf("%s", translateRcode(r.Rcode)), true
	}
	if r.Rcode != dns.RcodeSuccess {
		return DNSResponse{}, fmt.Errorf("%s", translateRcode(r.Rcode)), false
	}

	var names []string
	var ptrTTL, cnameTTL uint32
	var target string

	for _, ans := range r.Answer {
		switch rr := ans.(type) {
		case *dns.PTR:
			names = append(names, rr.Ptr)
			ptrTTL = rr.Hdr.Ttl
		case *dns.CNAME:
			target = strings.TrimSuffix(rr.Target, ".")
			cnameTTL = rr.Hdr.Ttl
		}
	}

	// RFC 2317: a CNAME followed by the PTR it points to is a PTR answer
	if len(names) > 0 {
		return DNSResponse{Names: names, RecordType: "PTR", Target: target, TTL: ptrTTL}, nil, true
	}
	if target != "" {
		return DNSResponse{RecordType: "CNAME", Target: target, TTL: cnameTTL}, nil, true
	}
	// NOERROR without a PTR or CNAME is a final answer too
	return DNSResponse{}, fmt.Errorf("no PTR records found"), true
}

// buildQuery returns a PTR query for ip (id left as 0) with an EDNS0 OPT record for 1232 byte answers,
// and the length of the question section that answers must echo
func buildQuery(ip uint32) ([]byte, int) {
	q := make([]byte, 12, 64)
	q[2] = 0x01 // RD
	q[5] = 1    // QDCOUNT
	q[11] = 1   // ARCOUNT
	for i := 0; i < 4; i++ {
		octet := strconv.Itoa(int(byte(ip >> (8 * i))))
		q = append(q, byte(len(octet)))
		q = append(q, octet...)
	}
	q = append(q, 7, 'i', 'n', '-', 'a', 'd', 'd', 'r', 4, 'a', 'r', 'p', 'a', 0, 0, 12, 0, 1)
	qlen := len(q) - 12
	q = append(q, 0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0) // OPT: root, type 41, UDP size 1232
	return q, qlen
}

const (
	numSockets = 4                     // long-lived query sockets
	batchSize  = 64                    // packets per sendmmsg/recvmmsg call
	wheelTick  = 50 * time.Millisecond // timeout resolution
)

// job is one IP to look up, with the round it belongs to so progress can be tracked per round
type job struct {
	ip    uint32
	round uint64
}

// lookup is one IP in flight; sock/id locate it in the engine table for the current attempt
type lookup struct {
	job     job
	query   []byte
	qlen    int
	attempt int
	res     *resolver
	sock    int
	id      uint16
}

type timeoutEntry struct {
	l       *lookup
	sock    int
	id      uint16
	attempt int
}

// engine sends queries from a few UDP sockets in batches and matches answers by socket, id, source and question
type engine struct {
	cfg    *Config
	rate   int
	conns  []*net.UDPConn
	pconns []*ipv4.PacketConn
	mu     [numSockets]sync.Mutex
	table  [numSockets][]*lookup // indexed by DNS id
	slots  chan struct{}         // one per lookup in flight, caps -c
	retry  chan *lookup
	wg     sync.WaitGroup
	result func(j job, server string, resp DNSResponse, err error)

	wheelMu  sync.Mutex
	wheel    [][]timeoutEntry
	wheelPos int
}

func newEngine(cfg *Config, rate int, result func(j job, server string, resp DNSResponse, err error)) (*engine, error) {
	e := &engine{
		cfg:    cfg,
		rate:   rate,
		slots:  make(chan struct{}, cfg.concurrency),
		retry:  make(chan *lookup, cfg.concurrency),
		result: result,
		wheel:  make([][]timeoutEntry, int(cfg.timeout/wheelTick)+2),
	}
	for i := 0; i < numSockets; i++ {
		conn, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return nil, err
		}
		conn.SetReadBuffer(16 << 20)
		conn.SetWriteBuffer(16 << 20)
		e.conns = append(e.conns, conn)
		e.pconns = append(e.pconns, ipv4.NewPacketConn(conn))
		e.table[i] = make([]*lookup, 65536)
	}
	return e, nil
}

// run looks up every IP from jobs and returns once all of them have a result
func (e *engine) run(jobs <-chan job) {
	for i := range e.conns {
		go e.receive(i)
	}
	stop := make(chan struct{})
	go e.expire(stop)
	defer func() {
		close(stop)
		for _, conn := range e.conns {
			conn.Close()
		}
	}()

	limit := batchSize
	var interval time.Duration
	var nextSend time.Time
	if e.rate > 0 {
		interval = time.Second / time.Duration(e.rate)
		limit = min(batchSize, max(1, e.rate/100))
	}

	jobsOpen := true
	allDone := make(chan struct{})
	closeJobs := func() {
		jobsOpen = false
		go func() {
			e.wg.Wait()
			close(allDone)
		}()
	}

	for {
		var batch []*lookup

		// block for the first lookup: a retry, or a new IP once a slot is free
		if jobsOpen {
			select {
			case l := <-e.retry:
				batch = append(batch, l)
			case e.slots <- struct{}{}:
				if j, ok := <-jobs; ok {
					batch = append(batch, e.newLookup(j))
				} else {
					<-e.slots
					closeJobs()
					continue
				}
			}
		} else {
			select {
			case l := <-e.retry:
				batch = append(batch, l)
			case <-allDone:
				return
			}
		}

		// fill the rest of the batch without blocking
	fill:
		for len(batch) < limit {
			select {
			case l := <-e.retry:
				batch = append(batch, l)
				continue
			default:
			}
			if !jobsOpen {
				break
			}
			select {
			case e.slots <- struct{}{}:
			default:
				break fill
			}
			select {
			case j, ok := <-jobs:
				if !ok {
					<-e.slots
					closeJobs()
					break fill
				}
				batch = append(batch, e.newLookup(j))
			default:
				<-e.slots
				break fill
			}
		}

		if interval > 0 {
			// advance the schedule rather than restarting it from now, so sleep overshoot does not add up;
			// after an idle stretch of over a second, start the schedule again instead of bursting to catch up
			now := time.Now()
			if now.Sub(nextSend) > time.Second {
				nextSend = now
			}
			if wait := nextSend.Sub(now); wait > 0 {
				time.Sleep(wait)
			}
			nextSend = nextSend.Add(time.Duration(len(batch)) * interval)
		}
		e.send(batch)
	}
}

func (e *engine) newLookup(j job) *lookup {
	e.wg.Add(1)
	query, qlen := buildQuery(j.ip)
	return &lookup{job: j, query: query, qlen: qlen}
}

// send registers each lookup under a free id on a socket and writes them with sendmmsg
func (e *engine) send(batch []*lookup) {
	atomic.AddUint64(&e.cfg.queries, uint64(len(batch)))
	var msgs [numSockets][]ipv4.Message
	for i, l := range batch {
		l.res = e.cfg.getNextServer()
		l.sock = i % numSockets

		e.mu[l.sock].Lock()
		id := uint16(rand.Uint32())
		for e.table[l.sock][id] != nil {
			id = uint16(rand.Uint32())
		}
		l.id = id
		binary.BigEndian.PutUint16(l.query, id)
		e.table[l.sock][id] = l
		e.mu[l.sock].Unlock()

		e.addTimeout(l)
		msgs[l.sock] = append(msgs[l.sock], ipv4.Message{Buffers: [][]byte{l.query}, Addr: l.res.udp})
	}

	for s := range msgs {
		for pending := msgs[s]; len(pending) > 0; {
			n, err := e.pconns[s].WriteBatch(pending, 0)
			if err != nil {
				// the lookups in this batch time out and are retried
				fmt.Fprintf(os.Stderr, "Error sending queries: %v\n", err)
				break
			}
			pending = pending[n:]
		}
	}
}

// receive reads answers with recvmmsg and hands each matched one to handle
func (e *engine) receive(s int) {
	msgs := make([]ipv4.Message, batchSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, 4096)}
	}

	for {
		n, err := e.pconns[s].ReadBatch(msgs, 0)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// a read error that keeps happening would otherwise spin a CPU; the lookups waiting time out and retry
			time.Sleep(10 * time.Millisecond)
			continue
		}

		for i := 0; i < n; i++ {
			buf := msgs[i].Buffers[0][:msgs[i].N]
			from, ok := msgs[i].Addr.(*net.UDPAddr)
			if len(buf) < 12 || !ok {
				continue
			}
			id := binary.BigEndian.Uint16(buf)

			// only accept an answer from the resolver we asked, for the question we asked
			e.mu[s].Lock()
			l := e.table[s][id]
			if l == nil || !l.res.udp.IP.Equal(from.IP) || l.res.udp.Port != from.Port || !bytes.HasPrefix(buf[12:], l.query[12:12+l.qlen]) {
				e.mu[s].Unlock()
				continue
			}
			e.table[s][id] = nil
			e.mu[s].Unlock()

			e.handle(l, buf)
		}
	}
}

func (e *engine) handle(l *lookup, buf []byte) {
	m := new(dns.Msg)
	if err := m.Unpack(buf); err != nil {
		l.res.fail()
		e.retryOrFinish(l, err)
		return
	}

	// a truncated answer is incomplete (and resolvers like Cloudflare send them to busy clients): ask again over TCP
	if m.Truncated {
		go e.tcpLookup(l)
		return
	}

	e.process(l, m)
}

// process finishes a lookup on a final answer, or retries it on the next resolver
func (e *engine) process(l *lookup, m *dns.Msg) {
	resp, err, final := parseAnswer(m)
	if !final {
		l.res.fail()
		e.retryOrFinish(l, err)
		return
	}
	l.res.ok()
	e.finish(l, resp, err)
}

// tcpLookup repeats a truncated lookup over TCP to the same resolver; it keeps its slot while it runs
func (e *engine) tcpLookup(l *lookup) {
	arpa, _ := dns.ReverseAddr(ipToString(l.job.ip))
	m := new(dns.Msg)
	m.SetQuestion(arpa, dns.TypePTR)

	r, _, err := (&dns.Client{Net: "tcp", Timeout: e.cfg.timeout}).Exchange(m, l.res.udp.String())
	if err != nil {
		// no TCP on this resolver does not make its UDP answers bad, so it is not counted against it
		e.retryOrFinish(l, fmt.Errorf("truncated"))
		return
	}
	e.process(l, r)
}

// retryOrFinish queues another attempt on the next resolver, or reports err once -r retries are used up
func (e *engine) retryOrFinish(l *lookup, err error) {
	if l.attempt < e.cfg.retries {
		l.attempt++
		atomic.AddUint64(&e.cfg.retried, 1)
		e.retry <- l
		return
	}
	e.finish(l, DNSResponse{}, err)
}

func (e *engine) finish(l *lookup, resp DNSResponse, err error) {
	e.result(l.job, l.res.host, resp, err)
	<-e.slots
	e.wg.Done()
}

func (e *engine) addTimeout(l *lookup) {
	e.wheelMu.Lock()
	pos := (e.wheelPos + int(e.cfg.timeout/wheelTick) + 1) % len(e.wheel)
	e.wheel[pos] = append(e.wheel[pos], timeoutEntry{l, l.sock, l.id, l.attempt})
	e.wheelMu.Unlock()
}

// expire advances the timeout wheel every tick and retries lookups that are still waiting on that attempt
func (e *engine) expire(stop <-chan struct{}) {
	ticker := time.NewTicker(wheelTick)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}

		e.wheelMu.Lock()
		e.wheelPos = (e.wheelPos + 1) % len(e.wheel)
		due := e.wheel[e.wheelPos]
		e.wheel[e.wheelPos] = nil
		e.wheelMu.Unlock()

		for _, t := range due {
			e.mu[t.sock].Lock()
			if e.table[t.sock][t.id] != t.l || t.l.attempt != t.attempt {
				e.mu[t.sock].Unlock()
				continue
			}
			e.table[t.sock][t.id] = nil
			e.mu[t.sock].Unlock()

			t.l.res.fail()
			e.retryOrFinish(t.l, errTimeout)
		}
	}
}

func reverse(ss []string) []string {
	reversed := make([]string, len(ss))
	for i, s := range ss {
		reversed[len(ss)-1-i] = s
	}
	return reversed
}

func colorizeIPInPtr(ptr, ip string) string {
	specialHosts := []string{"localhost", "undefined.hostname.localhost", "unknown"}
	for _, host := range specialHosts {
		if strings.EqualFold(ptr, host) {
			return "[gray]" + ptr
		}
	}

	octets := strings.Split(ip, ".")

	patterns := []string{
		ip,
		strings.Join(reverse(strings.Split(ip, ".")), "."),
		strings.ReplaceAll(ip, ".", "-"),
		strings.Join(reverse(strings.Split(ip, ".")), "-"),
	}

	zeroPadded := make([]string, 4)
	for i, octet := range octets {
		zeroPadded[i] = fmt.Sprintf("%03d", parseInt(octet))
	}
	patterns = append(patterns,
		strings.Join(zeroPadded, "-"),
		strings.Join(reverse(zeroPadded), "-"),
	)

	// leftmost-first, non-overlapping matches of any pattern (same as a regex alternation)
	var matches [][2]int
	for i := 0; i < len(ptr); {
		matched := false
		for _, p := range patterns {
			if strings.HasPrefix(ptr[i:], p) {
				matches = append(matches, [2]int{i, i + len(p)})
				i += len(p)
				matched = true
				break
			}
		}
		if !matched {
			i++
		}
	}
	if matches == nil {
		return "[white]" + ptr
	}

	var result strings.Builder
	lastEnd := 0

	for _, match := range matches {
		if match[0] > lastEnd {
			result.WriteString("[white]")
			result.WriteString(ptr[lastEnd:match[0]])
		}
		result.WriteString("[aqua]")
		result.WriteString(ptr[match[0]:match[1]])
		lastEnd = match[1]
	}

	if lastEnd < len(ptr) {
		result.WriteString("[white]")
		result.WriteString(ptr[lastEnd:])
	}

	finalResult := result.String()

	if strings.HasSuffix(finalResult, ".in-addr.arpa") {
		finalResult = finalResult[:len(finalResult)-13] + ".[blue]in-addr.arpa"
	}
	if strings.HasSuffix(finalResult, ".gov") {
		finalResult = finalResult[:len(finalResult)-4] + ".[red]gov"
	}
	if strings.HasSuffix(finalResult, ".mil") {
		finalResult = finalResult[:len(finalResult)-4] + ".[red]mil"
	}

	return finalResult
}

func parseInt(s string) int {
	num := 0
	fmt.Sscanf(s, "%d", &num)
	return num
}

const maxBufferLines = 1000

// recordPrefix is the visible width of a TUI result line before the record (ip, resolver, type, ttl and separators)
const recordPrefix = 54

// panelWidth is the inner width of the TUI panels, set by the draw loop so long records can be cut to fit
var panelWidth atomic.Int64

// fitRecord cuts a record to the room left on a TUI line, ending it with an ellipsis, so lines never wrap
func fitRecord(record string) string {
	room := int(panelWidth.Load()) - recordPrefix
	runes := []rune(record)
	if room < 1 || len(runes) <= room {
		return record
	}
	return string(runes[:room-1]) + "…"
}

// handleResult counts and outputs one finished lookup. textView is nil with -j; otherwise lines are
// written to it directly (TextView.Write is goroutine-safe) and the stats loop redraws every 100ms
func handleResult(cfg *Config, stats *Stats, textView *tview.TextView, ip, server string, response DNSResponse, err error) {
	stats.increment()

	if err != nil {
		stats.incrementFailed()
		atomic.AddUint64(&stats.outcomes[outcome(err)], 1)
		if cfg.debug {
			errRecord := formatErrorAsHostname(err)
			record := formatRecord(time.Now(), ip, server, []string{errRecord}, "ERR", "", 0)
			cfg.stdout.write(record)
			cfg.output.write(record)

			if textView != nil {
				fmt.Fprintf(textView, "[purple]%15s[-] [gray]│[-] [aqua]%-15s[-] [gray]│[-] [red] ERR [-] [gray]│[-] [gray]%-7s[-] [gray]│[-] [gray]%s[-]\n",
					ip,
					server,
					"",
					errRecord)
			}
		}
		return
	}

	stats.incrementSuccess()
	if response.Target != "" {
		stats.countCNAME(response.RecordType)
	}

	// a CNAME with no PTR behind it has no names (record is left out), its target goes in cname
	names := cleanNames(response.Names)
	if len(names) == 0 && response.RecordType != "CNAME" {
		return
	}

	record := formatRecord(time.Now(), ip, server, names, response.RecordType, response.Target, response.TTL)
	cfg.stdout.write(record)
	cfg.output.write(record)
	if textView == nil {
		return
	}

	ptr := strings.Join(names, ", ")
	recordTypeColor := "[blue] PTR [-]"
	if response.RecordType == "CNAME" {
		recordTypeColor = "[fuchsia]CNAME[-]"
		ptr = strings.ToLower(response.Target)
	} else if response.Target != "" {
		ptr = fmt.Sprintf("%s -> %s", strings.ToLower(response.Target), ptr)
	}

	fmt.Fprintf(textView, "[purple]%15s[-] [gray]│[-] [aqua]%-15s[-] [gray]│[-] %-5s [gray]│[-] %s [gray]│[-] %s\n",
		ip,
		server,
		recordTypeColor,
		colorizeTTL(response.TTL),
		colorizeIPInPtr(fitRecord(ptr), ip))
}

// finishResult outputs a finished lookup, then marks it done for resume
func finishResult(cfg *Config, stats *Stats, textView *tview.TextView, j job, server string, resp DNSResponse, err error) {
	handleResult(cfg, stats, textView, ipToString(j.ip), server, resp, err)
	stats.track.done(j.round, uint64(bits.ReverseBytes32(j.ip)))
}

func parseShardArg(shard string) (int, int, error) {
	if shard == "" {
		return 1, 1, nil
	}

	parts := strings.Split(shard, "/")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid shard format (expected n/total)")
	}

	shardNum, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid shard number: %v", err)
	}

	totalShards, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid total shards: %v", err)
	}

	if shardNum < 1 || shardNum > totalShards {
		return 0, 0, fmt.Errorf("shard number must be between 1 and total shards")
	}

	return shardNum, totalShards, nil
}

// shardRange returns the [start, end) counter range for a shard of the 2^32 IPv4 space
func shardRange(shardNum, totalShards int) (uint64, uint64) {
	start := uint64(shardNum-1) * (1 << 32) / uint64(totalShards)
	end := uint64(shardNum) * (1 << 32) / uint64(totalShards)
	return start, end
}

// ipRange is an inclusive range of IPv4 addresses
type ipRange struct {
	start, end uint32
}

// loadExcludes reads CIDRs or single IPs (one per line, # comments) into sorted, merged ranges
func loadExcludes(path string) ([]ipRange, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open exclude file: %v", err)
	}
	defer file.Close()

	var ranges []ipRange
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		cidr := line
		if !strings.Contains(cidr, "/") {
			cidr += "/32"
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("invalid IPv4 CIDR in exclude file: %q", line)
		}
		start := binary.BigEndian.Uint32(prefix.Masked().Addr().AsSlice())
		ranges = append(ranges, ipRange{start, start | uint32(1<<(32-prefix.Bits())-1)})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading exclude file: %v", err)
	}

	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	var merged []ipRange
	for _, r := range ranges {
		if n := len(merged); n > 0 && uint64(r.start) <= uint64(merged[n-1].end)+1 {
			merged[n-1].end = max(merged[n-1].end, r.end)
		} else {
			merged = append(merged, r)
		}
	}
	return merged, nil
}

// excluded reports whether ip falls in one of the sorted, merged ranges
func excluded(ranges []ipRange, ip uint32) bool {
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i].end >= ip })
	return i < len(ranges) && ranges[i].start <= ip
}

// ipToString formats a big-endian IPv4 value
func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

const trackBlockSize = 4096 // resume granularity: at most this many IPs are queried again after a restart

// tracker counts unfinished lookups per block of the counter, so the state file can record the lowest
// position that is not fully done. A lookup that keeps retrying can fall far behind newer ones.
type tracker struct {
	mu     sync.Mutex
	blocks []trackBlock // in dispatch order
}

type trackBlock struct {
	round, start uint64
	pending      int
}

func (t *tracker) add(round, ctr uint64) {
	start := ctr - ctr%trackBlockSize
	t.mu.Lock()
	if n := len(t.blocks); n > 0 && t.blocks[n-1].round == round && t.blocks[n-1].start == start {
		t.blocks[n-1].pending++
	} else {
		t.blocks = append(t.blocks, trackBlock{round, start, 1})
	}
	t.mu.Unlock()
}

func (t *tracker) done(round, ctr uint64) {
	start := ctr - ctr%trackBlockSize
	t.mu.Lock()
	for i := range t.blocks {
		if t.blocks[i].round == round && t.blocks[i].start == start {
			t.blocks[i].pending--
			break
		}
	}
	for len(t.blocks) > 0 && t.blocks[0].pending == 0 {
		t.blocks = t.blocks[1:]
	}
	t.mu.Unlock()
}

// watermark returns the 0-based round and position everything before which has finished
func (t *tracker) watermark(stats *Stats) (uint64, uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.blocks) > 0 {
		return t.blocks[0].round, t.blocks[0].start
	}
	return atomic.LoadUint64(&stats.round), atomic.LoadUint64(&stats.next)
}

// feed sends every IP of the shard to jobs from the current position, then loops if -l is set.
// The counter is turned into an IP with the octets reversed (like massdns's ptr.py),
// so consecutive queries land in different /8s and each /24 is spread across the whole run
func feed(jobs chan<- job, cfg *Config, stats *Stats, start, end uint64) {
	for {
		round := atomic.LoadUint64(&stats.round)
		for i := atomic.LoadUint64(&stats.next); i < end; i++ {
			if ip := bits.ReverseBytes32(uint32(i)); cfg.excludes == nil || !excluded(cfg.excludes, ip) {
				stats.track.add(round, i)
				jobs <- job{ip, round}
			}
			atomic.StoreUint64(&stats.next, i+1)
		}

		if !cfg.loop {
			break
		}
		// round and position change together under the tracker lock so watermark never sees a mix
		stats.track.mu.Lock()
		atomic.AddUint64(&stats.round, 1)
		atomic.StoreUint64(&stats.next, start)
		stats.track.mu.Unlock()
	}
	close(jobs)
}

// loadState returns the saved 0-based round and position
func loadState(path, shard string, start, end uint64) (uint64, uint64, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, start, nil
	} else if err != nil {
		return 0, 0, err
	}

	var savedShard string
	var round, next uint64
	if _, err := fmt.Sscanf(string(data), "shard=%s round=%d next=%d", &savedShard, &round, &next); err != nil {
		return 0, 0, fmt.Errorf("invalid state file %s: %v", path, err)
	}
	if savedShard != shard {
		return 0, 0, fmt.Errorf("state file %s is for shard %s, not %s", path, savedShard, shard)
	}
	if round < 1 || next < start || next > end {
		return 0, 0, fmt.Errorf("state file %s is out of range for shard %s", path, shard)
	}

	// a finished round starts the next one from the beginning, instead of scanning nothing and exiting
	if next == end {
		return round, start, nil
	}

	return round - 1, next, nil
}

// saveState records the lowest unfinished position. Output is flushed after taking the watermark and before
// writing the file, so every lookup the file counts as done is already written out. The file goes through a
// temporary file so it is never left half written.
func saveState(path, shard string, cfg *Config, stats *Stats) error {
	round, next := stats.track.watermark(stats)
	cfg.output.flush()
	cfg.stdout.flush()

	line := fmt.Sprintf("shard=%s round=%d next=%d\n", shard, round+1, next)
	if err := os.WriteFile(path+".tmp", []byte(line), 0644); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// refreshDNSServers re-fetches the default resolver list every 24 hours (only used without -dns)
func (c *Config) refreshDNSServers() {
	for range time.Tick(24 * time.Hour) {
		resolvers, err := loadDNSServers("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to update DNS servers: %v\n", err)
			continue
		}
		parsed, err := newResolvers(resolvers)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to update DNS servers: %v\n", err)
			continue
		}
		c.mu.Lock()
		c.dnsServers = parsed
		c.serverIndex = 0
		c.mu.Unlock()
	}
}

func main() {
	concurrency := flag.Int("c", 10000, "Max lookups in flight")
	timeout := flag.Duration("t", 2*time.Second, "Timeout for DNS queries")
	retries := flag.Int("r", 2, "Number of retries for failed lookups")
	dnsFile := flag.String("dns", "", "File containing DNS servers (one per line)")
	debug := flag.Bool("debug", false, "Show unsuccessful lookups")
	outputPath := flag.String("o", "", "Path to NDJSON output file")
	shard := flag.String("shard", "", "Shard specification (e.g., 1/4 for first shard of 4)")
	loop := flag.Bool("l", false, "Loop continuously after completion")
	jsonOutput := flag.Bool("j", false, "Output NDJSON to stdout (no TUI)")
	statePath := flag.String("state", "", "State file to resume from and save progress to")
	excludePath := flag.String("exclude", "", "File of IPv4 CIDRs or IPs to skip (one per line)")
	rate := flag.Int("rate", 0, "Max queries per second (0 for unlimited)")
	statsInterval := flag.Duration("stats-interval", 10*time.Minute, "How often to log a stats line to stderr with -j (0 to turn off; the TUI shows the same live)")
	flag.Parse()

	shardNum, totalShards, err := parseShardArg(*shard)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing shard argument: %v\n", err)
		os.Exit(1)
	}

	servers, err := loadDNSServers(*dnsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading DNS servers: %v\n", err)
		os.Exit(1)
	}

	// each socket has 65536 DNS ids, keep well under that so a free id is always found quickly
	if *concurrency < 1 || *concurrency > numSockets*32768 {
		fmt.Fprintf(os.Stderr, "Concurrency must be between 1 and %d\n", numSockets*32768)
		os.Exit(1)
	}

	resolvers, err := newResolvers(servers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading DNS servers: %v\n", err)
		os.Exit(1)
	}

	cfg := &Config{
		concurrency: *concurrency,
		timeout:     *timeout,
		retries:     *retries,
		debug:       *debug,
		dnsServers:  resolvers,
		loop:        *loop,
	}

	if *dnsFile == "" {
		go cfg.refreshDNSServers()
	}

	if *excludePath != "" {
		if cfg.excludes, err = loadExcludes(*excludePath); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading excludes: %v\n", err)
			os.Exit(1)
		}
	}

	if *outputPath != "" {
		f, err := os.OpenFile(*outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", err)
			os.Exit(1)
		}
		cfg.output = newLineWriter(f)
		defer f.Close()
		defer cfg.output.flush()
	}

	if *jsonOutput {
		cfg.stdout = newLineWriter(os.Stdout)
		defer cfg.stdout.flush()
	}

	go func() {
		for range time.Tick(time.Second) {
			cfg.output.flush()
			cfg.stdout.flush()
		}
	}()

	app := tview.NewApplication()

	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetMaxLines(maxBufferLines).
		SetWrap(false)
	textView.ScrollToEnd()
	textView.SetBorder(true).SetTitle(" PTR Records ")

	progress := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	progress.SetBorder(true).SetTitle(" Progress ")

	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(textView, 0, 1, false).
		AddItem(progress, 5, 0, false)

	shardStart, shardEnd := shardRange(shardNum, totalShards)

	stats := &Stats{
		total:         shardEnd - shardStart,
		lastCheckTime: time.Now(),
		startTime:     time.Now(),
		next:          shardStart,
	}

	shardSpec := fmt.Sprintf("%d/%d", shardNum, totalShards)
	if *statePath != "" {
		stats.round, stats.next, err = loadState(*statePath, shardSpec, shardStart, shardEnd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading state: %v\n", err)
			os.Exit(1)
		}
		go func() {
			for range time.Tick(10 * time.Second) {
				if err := saveState(*statePath, shardSpec, cfg, stats); err != nil {
					fmt.Fprintf(os.Stderr, "Error saving state: %v\n", err)
				}
			}
		}()
		defer saveState(*statePath, shardSpec, cfg, stats)
	}

	// on SIGINT/SIGTERM (systemd stop) flush output and save state
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		if *statePath != "" {
			if err := saveState(*statePath, shardSpec, cfg, stats); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving state: %v\n", err)
			}
		}
		cfg.output.flush()
		cfg.stdout.flush()
		os.Exit(0)
	}()

	// stderr would draw over the TUI, so the stats line is only for -j runs
	if *statsInterval > 0 && *jsonOutput {
		go logStats(cfg, stats, shardStart, *statsInterval)
	}

	jobs := make(chan job, cfg.concurrency)
	go feed(jobs, cfg, stats, shardStart, shardEnd)

	if *jsonOutput {
		eng, err := newEngine(cfg, *rate, func(j job, server string, resp DNSResponse, err error) {
			finishResult(cfg, stats, nil, j, server, resp, err)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening sockets: %v\n", err)
			os.Exit(1)
		}
		eng.run(jobs)
		return
	}

	go func() {
		const movingAverageWindow = 5
		stats.speedHistory = make([]float64, 0, movingAverageWindow)
		stats.lastCheckTime = time.Now()

		for {
			processed := atomic.LoadUint64(&stats.processed)
			success := atomic.LoadUint64(&stats.success)
			failed := atomic.LoadUint64(&stats.failed)

			now := time.Now()
			duration := now.Sub(stats.lastCheckTime).Seconds()

			if duration >= 1.0 {
				stats.mu.Lock()
				speed := float64(processed-stats.lastProcessed) / duration
				stats.speedHistory = append(stats.speedHistory, speed)
				if len(stats.speedHistory) > movingAverageWindow {
					stats.speedHistory = stats.speedHistory[1:]
				}

				var avgSpeed float64
				for _, s := range stats.speedHistory {
					avgSpeed += s
				}
				avgSpeed /= float64(len(stats.speedHistory))

				stats.lastProcessed = processed
				stats.lastCheckTime = now
				stats.mu.Unlock()

				percent := float64(atomic.LoadUint64(&stats.next)-shardStart) / float64(stats.total) * 100
				active, totalResolvers := cfg.activeResolvers()

				app.QueueUpdateDraw(func() {
					var width int
					_, _, width, _ = progress.GetInnerRect()
					if width <= 0 {
						return
					}
					panelWidth.Store(int64(width))

					// First two lines: stats, split so they fit a ~125 column terminal even with billions counted
					statsLine := fmt.Sprintf(" [aqua]Elapsed:[:-] [white]%s [gray]│[-] [aqua]Round:[:-] [white]%d [gray]│[-] [aqua]Count:[:-] [white]%s [gray]│[-] [aqua]Progress:[:-] [darkgray]%.2f%%[-] [gray]│[-] [aqua]Rate:[:-] %s\n [aqua]CNAME only:[:-] [yellow]%s[-] [gray]│[-] [aqua]Via CNAME:[:-] [yellow]%s[-] [gray]│[-] [aqua]Successful:[:-] [green]✓ %s[-][darkgray] (%.1f%%)[-] [gray]│[-] [aqua]Failed:[:-] [red]✗ %s[-][darkgray] (%.1f%%)[-] [gray]│[-] [aqua]Resolvers:[:-] [white]%d/%d[-]\n",
						formatDuration(time.Since(stats.startTime)),
						atomic.LoadUint64(&stats.round)+1,
						formatNumber(processed),
						percent,
						colorizeSpeed(avgSpeed),
						formatNumber(atomic.LoadUint64(&stats.cnameOnly)),
						formatNumber(atomic.LoadUint64(&stats.viaCNAME)),
						formatNumber(success),
						float64(success)/float64(processed)*100,
						formatNumber(failed),
						float64(failed)/float64(processed)*100,
						active, totalResolvers)

					// Third line: progress bar
					barWidth := width - 3 // -3 for the [] and space
					if barWidth < 1 {
						progress.Clear()
						fmt.Fprint(progress, statsLine)
						return
					}

					filled := int(float64(barWidth) * (percent / 100))
					if filled > barWidth {
						filled = barWidth
					}

					barLine := fmt.Sprintf(" [%s%s]",
						strings.Repeat("█", filled),
						strings.Repeat("░", barWidth-filled))

					// Combine both lines with explicit newline
					progress.Clear()
					fmt.Fprintf(progress, "%s%s", statsLine, barLine)
				})
			}

			app.Draw()
			time.Sleep(100 * time.Millisecond)
		}
	}()

	eng, err := newEngine(cfg, *rate, func(j job, server string, resp DNSResponse, err error) {
		finishResult(cfg, stats, textView, j, server, resp, err)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening sockets: %v\n", err)
		os.Exit(1)
	}
	go func() {
		eng.run(jobs)
		app.Stop()
	}()

	if err := app.SetRoot(flex, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}

func formatNumber(n uint64) string {
	s := fmt.Sprint(n)
	parts := make([]string, 0)
	for i := len(s); i > 0; i -= 3 {
		start := i - 3
		if start < 0 {
			start = 0
		}
		parts = append([]string{s[start:i]}, parts...)
	}
	return strings.Join(parts, ",")
}

func colorizeSpeed(speed float64) string {
	switch {
	case speed >= 9000:
		return fmt.Sprintf("[green]%6.0f/s[-]", speed)
	case speed >= 6000:
		return fmt.Sprintf("[yellow]%6.0f/s[-]", speed)
	case speed >= 3000:
		return fmt.Sprintf("[orange]%6.0f/s[-]", speed)
	case speed >= 1000:
		return fmt.Sprintf("[red]%6.0f/s[-]", speed)
	default:
		return fmt.Sprintf("[gray]%6.0f/s[-]", speed)
	}
}

// cleanNames trims whitespace and the trailing dot (keeping a bare root "."), lowercases, and drops empty names
func cleanNames(names []string) []string {
	var cleaned []string
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "." {
			name = strings.TrimSuffix(name, ".")
		}
		if name != "" {
			cleaned = append(cleaned, name)
		}
	}
	return cleaned
}

// formatRecord returns one NDJSON line (without newline) for a result
func formatRecord(timestamp time.Time, ip, server string, records []string, recordType, target string, ttl uint32) string {
	record := struct {
		Timestamp  string   `json:"@timestamp"`
		IP         string   `json:"ip"`
		Nameserver string   `json:"nameserver"`
		Record     []string `json:"record,omitempty"`
		RecordType string   `json:"record_type"`
		CNAME      string   `json:"cname,omitempty"`
		TTL        uint32   `json:"ttl"`
	}{
		Timestamp:  timestamp.Format(time.RFC3339),
		IP:         ip,
		Nameserver: server,
		Record:     records,
		RecordType: recordType,
		TTL:        ttl,
	}

	// the CNAME target: the RFC 2317 delegation for a PTR, or the whole answer for record_type CNAME
	if recordType != "ERR" {
		record.CNAME = target
	}

	data, _ := json.Marshal(record)
	return string(data)
}

// lineWriter is a buffered, goroutine-safe line writer; nil means disabled
type lineWriter struct {
	mu sync.Mutex
	w  *bufio.Writer
}

func newLineWriter(f *os.File) *lineWriter {
	return &lineWriter{w: bufio.NewWriterSize(f, 64*1024)}
}

func (l *lineWriter) write(line string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.w.WriteString(line)
	l.w.WriteByte('\n')
	l.mu.Unlock()
}

func (l *lineWriter) flush() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.w.Flush()
	l.mu.Unlock()
}

// logStats writes one progress line to stderr every interval: position, rates over the interval, timeouts,
// the outcome of every finished IP and resolvers in rotation, so a long headless run leaves a history
func logStats(cfg *Config, stats *Stats, start uint64, interval time.Duration) {
	var lastProcessed, lastPTR, lastQueries, lastRetried uint64
	var lastOutcomes [numOutcomes]uint64
	began := time.Now()

	for range time.Tick(interval) {
		processed := atomic.LoadUint64(&stats.processed)
		ptr := atomic.LoadUint64(&stats.success)
		queries := atomic.LoadUint64(&cfg.queries)
		retried := atomic.LoadUint64(&cfg.retried)
		active, total := cfg.activeResolvers()

		done := processed - lastProcessed
		pct := func(n uint64) float64 {
			if done == 0 {
				return 0
			}
			return 100 * float64(n) / float64(done)
		}

		line := fmt.Sprintf("stats round=%d progress=%.3f%% next=%d elapsed=%s ips/s=%.0f ptr/s=%.0f queries/s=%.0f retries/s=%.0f ptr=%.1f%%",
			atomic.LoadUint64(&stats.round)+1,
			100*float64(atomic.LoadUint64(&stats.next)-start)/float64(stats.total),
			atomic.LoadUint64(&stats.next),
			time.Since(began).Round(time.Second),
			float64(done)/interval.Seconds(),
			float64(ptr-lastPTR)/interval.Seconds(),
			float64(queries-lastQueries)/interval.Seconds(),
			float64(retried-lastRetried)/interval.Seconds(),
			pct(ptr-lastPTR))
		// what the other IPs in the interval ended with, as a share of all IPs finished
		var outcomes [numOutcomes]uint64
		for i := range outcomes {
			outcomes[i] = atomic.LoadUint64(&stats.outcomes[i])
			line += fmt.Sprintf(" %s=%.1f%%", outcomeNames[i], pct(outcomes[i]-lastOutcomes[i]))
		}
		line += fmt.Sprintf(" lookups=%d queries=%d resolvers=%d/%d", processed, queries, active, total)
		fmt.Fprintln(os.Stderr, line)

		lastProcessed, lastPTR, lastQueries, lastRetried, lastOutcomes = processed, ptr, queries, retried, outcomes
	}
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)

	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour

	hours := d / time.Hour
	d -= hours * time.Hour

	minutes := d / time.Minute
	d -= minutes * time.Minute

	seconds := d / time.Second

	var result string

	if days > 0 {
		if hours > 0 && minutes > 0 {
			result = fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
		} else if hours > 0 {
			result = fmt.Sprintf("%dd %dh", days, hours)
		} else {
			result = fmt.Sprintf("%dd", days)
		}
	} else if hours > 0 {
		if minutes > 0 {
			result = fmt.Sprintf("%dh %dm", hours, minutes)
		} else {
			result = fmt.Sprintf("%dh", hours)
		}
	} else if minutes > 0 {
		if seconds > 0 {
			result = fmt.Sprintf("%dm %ds", minutes, seconds)
		} else {
			result = fmt.Sprintf("%dm", minutes)
		}
	} else {
		result = fmt.Sprintf("%ds", seconds)
	}

	return result
}

func colorizeTTL(ttl uint32) string {
	switch {
	case ttl >= 86400: // 1 day or more
		return fmt.Sprintf("[#00FF00::b]%-7d[-]", ttl) // Bright green with bold
	case ttl >= 3600: // 1 hour or more
		return fmt.Sprintf("[yellow]%-7d[-]", ttl)
	case ttl >= 300: // 5 minutes or more
		return fmt.Sprintf("[orange]%-7d[-]", ttl)
	case ttl >= 60: // 1 minute or more
		return fmt.Sprintf("[red]%-7d[-]", ttl)
	default: // Less than 60 seconds
		return fmt.Sprintf("[gray]%-7d[-]", ttl)
	}
}

func formatErrorAsHostname(err error) string {
	errMsg := err.Error()
	if idx := strings.LastIndex(errMsg, ": "); idx != -1 {
		errMsg = errMsg[idx+2:]
	}

	switch {
	case strings.Contains(errMsg, "i/o timeout"):
		return "FAIL.TIMEOUT.in-addr.arpa"
	case strings.Contains(errMsg, "Server Failure"):
		return "FAIL.SERVER-FAILURE.in-addr.arpa"
	case strings.Contains(errMsg, "No Such Domain"):
		return "FAIL.NXDOMAIN.in-addr.arpa"
	case strings.Contains(errMsg, "Query Refused"):
		return "FAIL.REFUSED.in-addr.arpa"
	case strings.Contains(errMsg, "no PTR records found"):
		return "FAIL.NO-PTR-RECORD.in-addr.arpa"
	case strings.Contains(errMsg, "no such host"):
		return "FAIL.NO-SUCH-HOST.in-addr.arpa"
	case strings.Contains(errMsg, "connection refused"):
		return "FAIL.CONNECTION-REFUSED.in-addr.arpa"
	case strings.Contains(errMsg, "network is unreachable"):
		return "FAIL.NETWORK-UNREACHABLE.in-addr.arpa"
	case strings.Contains(errMsg, "no route to host"):
		return "FAIL.NO-ROUTE.in-addr.arpa"
	case strings.Contains(errMsg, "Format Error"):
		return "FAIL.FORMAT-ERROR.in-addr.arpa"
	case strings.Contains(errMsg, "Not Implemented"):
		return "FAIL.NOT-IMPLEMENTED.in-addr.arpa"
	case strings.Contains(errMsg, "truncated"):
		return "FAIL.TRUNCATED.in-addr.arpa"
	default:
		return fmt.Sprintf("FAIL.%s.in-addr.arpa", strings.ReplaceAll(strings.ToUpper(errMsg), " ", "-"))
	}
}
