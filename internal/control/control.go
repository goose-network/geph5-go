// Package control ports geph5-client's control protocol
// (binaries/geph5-client/src/control_prot.rs and the ControlProtocol trait in
// libraries/geph5-misc-rpc/src/client_control.rs) to Go.
//
// The control protocol is a newline-delimited JSON-RPC 2.0 service (served by
// internal/nanorpc.Serve) that a host process (the `geph` daemon/CLI) uses to
// drive the client engine: query connection state, proxy arbitrary broker RPCs,
// start/poll user-secret registrations, fetch news/update manifests, and stop
// the daemon. Method names are snake_case (nanorpc_derive) and params are JSON
// arrays; Result<T, String>-returning methods encode the Err arm as a JSON-RPC
// error with the string as the message.
//
// Wire-compatibility notes:
//   - ConnInfo is an externally-tagged enum with tag "state": {"state":"Disconnected"},
//     {"state":"Connecting"}, {"state":"Connected","sessions":[...]}. It is
//     hand-marshaled to match serde's #[serde(tag = "state")] exactly.
//   - ConnectedInfo.bridge is Option<SocketAddr>; SocketAddr serializes through
//     serde_json as an "ip:port" string, so bridge is null or a string.
//   - start_time returns SystemTime, which serde_json serializes as seconds
//     since UNIX_EPOCH (a u64). We return start.Unix() as a JSON number.
//
// Unported dependencies (stubbed with wire-compatible return shapes):
//   - melpow puzzle solver (start_registration): the registration goroutine
//     logs a warning and leaves progress at 0.0 instead of solving.
//   - minisign verification (latest_news, get_update_manifest): the manifest is
//     fetched and parsed but its signature is NOT verified.
//   - SQLite log store (recent_logs): returns an empty array.
//   - TraffCount (stat_history): returns an empty array.
package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/geph-official/geph5-go/internal/blake3"
	"github.com/geph-official/geph5-go/internal/brokerproto"
	"github.com/geph-official/geph5-go/internal/nanorpc"
	"github.com/geph-official/geph5-go/internal/session"
	"gopkg.in/yaml.v3"
)

// ConnInfo mirrors geph5_misc_rpc::client_control::ConnInfo, an externally-
// tagged enum with tag "state".
type ConnInfo struct {
	// state is "Disconnected", "Connecting", or "Connected".
	state string
	// sessions is populated only when state == "Connected".
	sessions []ConnectedInfo
}

// Disconnected, Connecting, and Connected are the ConnInfo constructors.
func Disconnected() ConnInfo  { return ConnInfo{state: "Disconnected"} }
func Connecting() ConnInfo    { return ConnInfo{state: "Connecting"} }
func Connected(sessions []ConnectedInfo) ConnInfo {
	return ConnInfo{state: "Connected", sessions: sessions}
}

// MarshalJSON implements #[serde(tag = "state")] externally-tagged encoding.
func (c ConnInfo) MarshalJSON() ([]byte, error) {
	switch c.state {
	case "Disconnected", "Connecting":
		return json.Marshal(map[string]string{"state": c.state})
	case "Connected":
		// {"state":"Connected","sessions":[...]}
		type wire struct {
			State    string         `json:"state"`
			Sessions []ConnectedInfo `json:"sessions"`
		}
		return json.Marshal(wire{State: c.state, Sessions: c.sessions})
	}
	return json.Marshal(map[string]string{"state": "Disconnected"})
}

// UnmarshalJSON implements #[serde(tag = "state")] externally-tagged decoding.
func (c *ConnInfo) UnmarshalJSON(b []byte) error {
	var tag struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(b, &tag); err != nil {
		return err
	}
	c.state = tag.State
	switch tag.State {
	case "Disconnected", "Connecting":
		return nil
	case "Connected":
		var full struct {
			State    string          `json:"state"`
			Sessions []ConnectedInfo `json:"sessions"`
		}
		if err := json.Unmarshal(b, &full); err != nil {
			return err
		}
		c.sessions = full.Sessions
		return nil
	}
	return fmt.Errorf("control: unknown ConnInfo state %q", tag.State)
}

// ConnectedInfo mirrors geph5_misc_rpc::client_control::ConnectedInfo.
//
// Bridge is *string because Rust's Option<SocketAddr> serializes through
// serde_json as null or an "ip:port" string.
type ConnectedInfo struct {
	Protocol string                    `json:"protocol"`
	Exit     brokerproto.ExitDescriptor `json:"exit"`
	Bridge   *string                   `json:"bridge"`
}

// RegistrationProgress mirrors geph5_misc_rpc::client_control::RegistrationProgress.
type RegistrationProgress struct {
	Progress float64  `json:"progress"`
	Secret   *string  `json:"secret"`
}

// NewsItem mirrors geph5_misc_rpc::client_control::NewsItem.
type NewsItem struct {
	Title     string `json:"title"`
	DateUnix  uint64 `json:"date_unix"`
	Contents  string `json:"contents"`
	Important bool   `json:"important"`
}

// Deps holds the collaborators a ControlService needs. Each field is a function
// or pointer so the service can be constructed without circular imports.
type Deps struct {
	// LiveInfos returns the currently-alive sessions (for conn_info). May be nil.
	LiveInfos func() []session.LiveSessionInfo
	// Broker is the broker client used for broker_rpc, net_status, get_puzzle,
	// and register_user_secret. May be nil (broker-dependent methods error).
	Broker *brokerproto.BrokerClient
	// DryRun mirrors Config.dry_run: when true, conn_info reports Disconnected.
	DryRun bool
	// StartTime is the daemon start time reported by start_time.
	StartTime time.Time
	// Stop, if non-nil, is invoked by the stop method (after a 100ms delay) to
	// terminate the process. Defaults to os.Exit(0).
	Stop func()
}

// ControlService implements nanorpc.RpcService for the control protocol. It
// mirrors Rust's ControlService(ControlProtocolImpl).
type ControlService struct {
	deps Deps

	// registrations is the slab of in-flight registration progresses.
	regMu    sync.Mutex
	regNext  int
	registrations map[int]RegistrationProgress
}

// New constructs a ControlService from the given deps.
func New(deps Deps) *ControlService {
	if deps.Stop == nil {
		deps.Stop = func() { os.Exit(0) }
	}
	return &ControlService{
		deps:          deps,
		registrations: make(map[int]RegistrationProgress),
	}
}

// RespondRaw dispatches a single JSON-RPC request, mirroring
// ControlService::respond_raw. It switches on req.Method (snake_case) and
// returns a JrcResponse with ID = req.ID. Result<T, String>-returning methods
// encode the Err arm as a JSON-RPC error (code -32000, message = the string).
func (s *ControlService) RespondRaw(ctx context.Context, req *nanorpc.JrpcRequest) *nanorpc.JrpcResponse {
	resp := &nanorpc.JrpcResponse{JSONRPC: "2.0", ID: req.ID}

	// All methods take params as a JSON array. Decode it once into a slice of
	// raw values; each method pulls the arguments it needs.
	var args []json.RawMessage
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &args); err != nil {
			resp.Error = &nanorpc.JrpcError{Code: -32602, Message: "invalid params: " + err.Error()}
			return resp
		}
	}

	switch req.Method {
	case "ab_test":
		s.handleAbTest(ctx, resp, args)
	case "conn_info":
		s.handleConnInfo(resp)
	case "stat_num":
		s.handleStatNum(resp, args)
	case "start_time":
		s.handleStartTime(resp)
	case "stop":
		s.handleStop(resp)
	case "recent_logs":
		s.handleRecentLogs(resp)
	case "broker_rpc":
		s.handleBrokerRpc(ctx, resp, args)
	case "start_registration":
		s.handleStartRegistration(ctx, resp)
	case "poll_registration":
		s.handlePollRegistration(resp, args)
	case "stat_history":
		s.handleStatHistory(resp, args)
	case "net_status":
		s.handleNetStatus(ctx, resp)
	case "latest_news":
		s.handleLatestNews(resp, args)
	case "get_update_manifest":
		s.handleGetUpdateManifest(resp)
	default:
		resp.Error = &nanorpc.JrpcError{Code: -32601, Message: "method not found: " + req.Method}
	}
	return resp
}

// argString extracts the i-th param as a string, returning an error response
// helper. Returns ok=false on failure (resp.Error already set).
func argString(args []json.RawMessage, i int) (string, bool) {
	if i >= len(args) {
		return "", false
	}
	var s string
	if err := json.Unmarshal(args[i], &s); err != nil {
		return "", false
	}
	return s, true
}

// setResult marshals v into the response Result field.
func setResult(resp *nanorpc.JrpcResponse, v interface{}) {
	b, err := json.Marshal(v)
	if err != nil {
		resp.Error = &nanorpc.JrpcError{Code: -32603, Message: "marshal result: " + err.Error()}
		return
	}
	resp.Result = b
}

// setErr sets a Result<T,String> Err arm as a JSON-RPC error.
func setErr(resp *nanorpc.JrpcResponse, msg string) {
	resp.Error = &nanorpc.JrpcError{Code: -32000, Message: msg}
}

// handleAbTest: ab_test(key, secret) -> Result<bool, String>.
// id = u64::from_be_bytes(blake3::hash(secret)[0..8]); broker_rpc("opaque_abtest", [key, id]).
func (s *ControlService) handleAbTest(ctx context.Context, resp *nanorpc.JrpcResponse, args []json.RawMessage) {
	key, ok := argString(args, 0)
	if !ok {
		setErr(resp, "ab_test: missing key")
		return
	}
	secret, ok := argString(args, 1)
	if !ok {
		setErr(resp, "ab_test: missing secret")
		return
	}
	h := blake3.Hash([]byte(secret))
	var id uint64
	for i := 0; i < 8; i++ {
		id = (id << 8) | uint64(h[i])
	}
	// Forward as broker_rpc("opaque_abtest", [key, id]).
	if s.deps.Broker == nil {
		setErr(resp, "ab_test: no broker configured")
		return
	}
	params, _ := json.Marshal([]interface{}{key, id})
	bresp, err := s.deps.Broker.CallRaw(ctx, "opaque_abtest", params)
	if err != nil {
		setErr(resp, err.Error())
		return
	}
	if bresp.Error != nil {
		setErr(resp, bresp.Error.Message)
		return
	}
	// The broker returns the bool directly as the result.
	var result bool
	if err := json.Unmarshal(bresp.Result, &result); err != nil {
		setErr(resp, "ab_test: decode bool: "+err.Error())
		return
	}
	setResult(resp, result)
}

// handleConnInfo: conn_info() -> ConnInfo.
func (s *ControlService) handleConnInfo(resp *nanorpc.JrpcResponse) {
	if s.deps.DryRun {
		setResult(resp, Disconnected())
		return
	}
	if s.deps.LiveInfos == nil {
		setResult(resp, Connecting())
		return
	}
	live := s.deps.LiveInfos()
	if len(live) == 0 {
		setResult(resp, Connecting())
		return
	}
	sessions := make([]ConnectedInfo, 0, len(live))
	for _, l := range live {
		sessions = append(sessions, ConnectedInfo{
			Protocol: l.Protocol,
			Exit:     l.Exit,
			Bridge:   l.Bridge,
		})
	}
	setResult(resp, Connected(sessions))
}

// handleStatNum: stat_num(stat) -> f64. No stats infrastructure in Go; return 0.0.
func (s *ControlService) handleStatNum(resp *nanorpc.JrpcResponse, args []json.RawMessage) {
	_ = args
	setResult(resp, 0.0)
}

// handleStartTime: start_time() -> SystemTime (seconds since UNIX_EPOCH as u64).
func (s *ControlService) handleStartTime(resp *nanorpc.JrpcResponse) {
	setResult(resp, s.deps.StartTime.Unix())
}

// handleStop: stop() -> (). Spawn a goroutine that sleeps 100ms then exits.
func (s *ControlService) handleStop(resp *nanorpc.JrpcResponse) {
	stop := s.deps.Stop
	go func() {
		time.Sleep(100 * time.Millisecond)
		stop()
	}()
	// null result.
	resp.Result = json.RawMessage("null")
}

// handleRecentLogs: recent_logs() -> Vec<String>. No DB log store in Go.
func (s *ControlService) handleRecentLogs(resp *nanorpc.JrpcResponse) {
	setResult(resp, []string{})
}

// handleBrokerRpc: broker_rpc(method, params) -> Result<Value, String>.
// Forwards an arbitrary broker call and returns the result (or null).
func (s *ControlService) handleBrokerRpc(ctx context.Context, resp *nanorpc.JrpcResponse, args []json.RawMessage) {
	method, ok := argString(args, 0)
	if !ok {
		setErr(resp, "broker_rpc: missing method")
		return
	}
	if s.deps.Broker == nil {
		setErr(resp, "broker_rpc: no broker configured")
		return
	}
	// params is Vec<Value> -> a JSON array. Forward it verbatim as the params.
	var params json.RawMessage
	if len(args) >= 2 {
		params = args[1]
	} else {
		params = json.RawMessage("[]")
	}
	bresp, err := s.deps.Broker.CallRaw(ctx, method, params)
	if err != nil {
		setErr(resp, err.Error())
		return
	}
	if bresp.Error != nil {
		setErr(resp, bresp.Error.Message)
		return
	}
	if len(bresp.Result) == 0 {
		resp.Result = json.RawMessage("null")
	} else {
		resp.Result = bresp.Result
	}
}

// handleStartRegistration: start_registration() -> Result<usize, String>.
// Gets a puzzle, inserts a RegistrationProgress{0.0, None}, spawns a goroutine
// to solve+register, and returns the index. The melpow solver is not ported, so
// the goroutine logs a warning and leaves progress at 0.0.
func (s *ControlService) handleStartRegistration(ctx context.Context, resp *nanorpc.JrpcResponse) {
	if s.deps.Broker == nil {
		setErr(resp, "start_registration: no broker configured")
		return
	}
	// Fetch the puzzle to confirm the broker is reachable (mirrors Rust).
	if _, _, err := s.deps.Broker.GetPuzzle(ctx); err != nil {
		setErr(resp, err.Error())
		return
	}
	s.regMu.Lock()
	idx := s.regNext
	s.regNext++
	s.registrations[idx] = RegistrationProgress{Progress: 0.0, Secret: nil}
	s.regMu.Unlock()
	// The melpow puzzle solver is not ported. Spawn a goroutine that logs the
	// limitation and leaves the progress at 0.0 (does not block forever, does
	// not retry). This keeps the method wire-compatible (returns an index).
	go func() {
		log.Printf("control: start_registration %d: melpow puzzle solver not ported; progress left at 0.0", idx)
	}()
	setResult(resp, idx)
}

// handlePollRegistration: poll_registration(idx) -> Result<RegistrationProgress, String>.
func (s *ControlService) handlePollRegistration(resp *nanorpc.JrpcResponse, args []json.RawMessage) {
	if len(args) < 1 {
		setErr(resp, "poll_registration: missing idx")
		return
	}
	var idx int
	if err := json.Unmarshal(args[0], &idx); err != nil {
		setErr(resp, "poll_registration: bad idx: "+err.Error())
		return
	}
	s.regMu.Lock()
	defer s.regMu.Unlock()
	p, ok := s.registrations[idx]
	if !ok {
		setErr(resp, "no such registration")
		return
	}
	setResult(resp, p)
}

// handleStatHistory: stat_history(stat) -> Result<Vec<f64>, String>.
// Only "traffic" is valid; no TraffCount in Go, so return an empty array.
func (s *ControlService) handleStatHistory(resp *nanorpc.JrpcResponse, args []json.RawMessage) {
	stat, ok := argString(args, 0)
	if !ok {
		setErr(resp, "stat_history: missing stat")
		return
	}
	if stat != "traffic" {
		setErr(resp, fmt.Sprintf("bad: %s", stat))
		return
	}
	setResult(resp, []float64{})
}

// handleNetStatus: net_status() -> Result<NetStatus, String>.
// Fetches the signed net status from the broker and returns the inner NetStatus.
func (s *ControlService) handleNetStatus(ctx context.Context, resp *nanorpc.JrpcResponse) {
	if s.deps.Broker == nil {
		setErr(resp, "net_status: no broker configured")
		return
	}
	signed, err := s.deps.Broker.GetNetStatus(ctx)
	if err != nil {
		setErr(resp, err.Error())
		return
	}
	// JsonSigned { inner_literal, signature, pubkey }. inner_literal holds the
	// NetStatus serialized as a JSON string. Return it parsed back to raw JSON
	// so the caller receives the NetStatus object shape (not a quoted string).
	if signed == nil {
		resp.Result = json.RawMessage("null")
		return
	}
	var inner interface{}
	if err := json.Unmarshal([]byte(signed.InnerLiteral), &inner); err != nil {
		setErr(resp, "net_status: decode inner: "+err.Error())
		return
	}
	setResult(resp, inner)
}

// handleLatestNews: latest_news(lang) -> Result<Vec<NewsItem>, String>.
// Fetches the update manifest (no minisign verification) and extracts the news.
func (s *ControlService) handleLatestNews(resp *nanorpc.JrpcResponse, args []json.RawMessage) {
	lang, ok := argString(args, 0)
	if !ok {
		setErr(resp, "latest_news: missing lang")
		return
	}
	manifest, _, err := fetchUpdateManifest()
	if err != nil {
		setErr(resp, err.Error())
		return
	}
	news, ok := manifest["news"].([]interface{})
	if !ok {
		setErr(resp, "No news array")
		return
	}
	out := make([]NewsItem, 0, len(news))
	for _, itemRaw := range news {
		item, ok := itemRaw.(map[string]interface{})
		if !ok {
			setErr(resp, "news item is not an object")
			return
		}
		important, _ := item["important"].(bool)
		dateStr, ok := item["date"].(string)
		if !ok {
			setErr(resp, "No or invalid 'date' field in news item")
			return
		}
		dateUnix, err := parseNewsDate(dateStr)
		if err != nil {
			setErr(resp, err.Error())
			return
		}
		localized, ok := item[lang].(map[string]interface{})
		if !ok {
			setErr(resp, fmt.Sprintf("No localized data for language '%s'", lang))
			return
		}
		title, ok := localized["title"].(string)
		if !ok {
			setErr(resp, "Missing 'title' in localized news data")
			return
		}
		contents, ok := localized["contents"].(string)
		if !ok {
			setErr(resp, "Missing 'contents' in localized news data")
			return
		}
		out = append(out, NewsItem{
			Title:     title,
			DateUnix:  dateUnix,
			Contents:  contents,
			Important: important,
		})
	}
	setResult(resp, out)
}

// handleGetUpdateManifest: get_update_manifest() -> Result<(Value, String), String>.
// Returns a 2-element array [manifest, url].
func (s *ControlService) handleGetUpdateManifest(resp *nanorpc.JrpcResponse) {
	manifest, url, err := fetchUpdateManifest()
	if err != nil {
		setErr(resp, err.Error())
		return
	}
	setResult(resp, []interface{}{manifest, url})
}

// parseNewsDate parses a "%Y-%m-%d" date string to a UNIX timestamp (seconds),
// mirroring Rust's NaiveDate::parse_from_str(date_str, "%Y-%m-%d") then
// and_hms_opt(0,0,0).and_utc().timestamp() as u64.
func parseNewsDate(s string) (uint64, error) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return 0, fmt.Errorf("Invalid date format: %s", s)
	}
	return uint64(t.Unix()), nil
}

// manifestURLs mirrors the Rust urls list in updates.rs.
var manifestURLs = []string{
	"https://f001.backblazeb2.com/file/geph4-dl/geph-releases",
	"https://sos-ch-dk-2.exo.io/utopia/geph-releases-new",
}

// fetchUpdateManifest downloads metadata.yaml from the first reachable mirror,
// parses it as YAML -> JSON, and returns (manifest, url). The minisign
// signature is NOT verified (minisign is not ported).
func fetchUpdateManifest() (map[string]interface{}, string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	var lastErr error
	for _, base := range manifestURLs {
		manifest, err := fetchUpdateManifestInner(client, base)
		if err != nil {
			lastErr = err
			log.Printf("control: skipping bad manifest url %s: %v", base, err)
			continue
		}
		return manifest, base, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no urls worked for manifest")
	}
	return nil, "", lastErr
}

// fetchUpdateManifestInner fetches <base>/metadata.yaml, parses it as YAML, and
// returns it as a generic map. The signature file is intentionally not fetched
// (minisign verification is not ported).
func fetchUpdateManifestInner(client *http.Client, base string) (map[string]interface{}, error) {
	resp, err := client.Get(base + "/metadata.yaml")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// Parse YAML into a generic nested map, then re-marshal to JSON and
	// unmarshal into map[string]interface{} for uniform access. yaml.Unmarshal
	// into interface{} already yields map[string]interface{} for mappings.
	var raw interface{}
	if err := yaml.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("manifest is not a YAML mapping")
	}
	return m, nil
}

// ServeControl races the tcp, unix, and pipe control listeners, mirroring
// Rust client_main's (tcp_rpc_serve, unix_rpc_serve, pipe_rpc_serve).race().
// Each non-empty listen address is served with nanorpc.Serve; empty addresses
// block forever (std::future::pending). Returns when any listener exits or ctx
// is cancelled.
//
// The pipe variant is Windows-only and not implemented on Unix (blocks forever).
func ServeControl(ctx context.Context, svc *ControlService, tcpListen, unixListen, pipeListen string) error {
	type result struct {
		name string
		err  error
	}
	results := make(chan result, 3)

	// tcp_rpc_serve
	go func() {
		if tcpListen == "" {
			<-ctx.Done()
			results <- result{"tcp", ctx.Err()}
			return
		}
		ln, err := net.Listen("tcp", tcpListen)
		if err != nil {
			results <- result{"tcp", err}
			return
		}
		log.Printf("control: serving tcp on %s", tcpListen)
		results <- result{"tcp", nanorpc.Serve(ctx, ln, svc)}
	}()

	// unix_rpc_serve
	go func() {
		if unixListen == "" {
			<-ctx.Done()
			results <- result{"unix", ctx.Err()}
			return
		}
		// Remove an existing socket file before binding (UnixListener fails on
		// a stale path).
		_ = os.Remove(unixListen)
		ln, err := net.Listen("unix", unixListen)
		if err != nil {
			results <- result{"unix", err}
			return
		}
		log.Printf("control: serving unix on %s", unixListen)
		results <- result{"unix", nanorpc.Serve(ctx, ln, svc)}
	}()

	// pipe_rpc_serve (Windows-only; pending on Unix).
	go func() {
		_ = pipeListen
		<-ctx.Done()
		results <- result{"pipe", ctx.Err()}
	}()

	// Race: return the first result that is a real error (not a ctx-cancellation
	// from an empty/pending listener). A pending listener returns ctx.Err() on
	// shutdown, which is not a fatal error worth surfacing.
	var firstErr error
	for i := 0; i < 3; i++ {
		r := <-results
		if r.err != nil && r.err != context.Canceled && r.err != context.DeadlineExceeded {
			log.Printf("control: %s listener stopped: %v", r.name, r.err)
			if firstErr == nil {
				firstErr = r.err
			}
		}
	}
	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}
