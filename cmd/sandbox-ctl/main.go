package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

const (
	defaultSockPath   = "/run/sandbox-ctl.sock"
	defaultIOTimeout  = 5 * time.Minute
	connectRetryDelay = 500 * time.Millisecond
	maxResponseBytes  = 1024 * 1024
)

type ctlRequest struct {
	ID     string         `json:"id"`
	Method string         `json:"method"`
	Params map[string]any `json:"params"`
}

type ctlError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ctlResponse struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *ctlError       `json:"error"`
}

func main() {
	os.Exit(run())
}

func run() int {
	args := os.Args[1:]

	jsonOut := false
	for len(args) > 0 {
		a := args[0]
		if a == "--json" {
			jsonOut = true
			args = args[1:]
			continue
		}
		if a == "-h" || a == "--help" {
			usage(os.Stdout)
			return 0
		}
		if strings.HasPrefix(a, "-") {
			printErr(fmt.Errorf("unknown flag: %s", a))
			usage(os.Stderr)
			return 1
		}
		break
	}

	if len(args) == 0 {
		usage(os.Stderr)
		return 1
	}

	cmd := args[0]
	cmdArgs := args[1:]

	switch cmd {
	case "ping":
		return cmdPing(cmdArgs, jsonOut)
	case "spawn":
		return cmdSpawn(cmdArgs, jsonOut)
	case "list":
		return cmdList(cmdArgs, jsonOut)
	case "destroy":
		return cmdDestroy(cmdArgs, jsonOut)
	case "run":
		return cmdRun(cmdArgs, jsonOut)
	case "exec":
		return cmdExec(cmdArgs, jsonOut)
	default:
		printErr(fmt.Errorf("unknown command: %s", cmd))
		usage(os.Stderr)
		return 1
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  sandbox-ctl [--json] ping")
	fmt.Fprintln(w, "  sandbox-ctl [--json] spawn [--image IMAGE] [--name NAME] [--cpus N] [--memory MEM]")
	fmt.Fprintln(w, "  sandbox-ctl [--json] list")
	fmt.Fprintln(w, "  sandbox-ctl [--json] destroy NAME")
	fmt.Fprintln(w, "  sandbox-ctl [--json] run [--image IMAGE] [--timeout N] [--workdir DIR] -- COMMAND [ARGS...]")
	fmt.Fprintln(w, "  sandbox-ctl [--json] exec NAME [--timeout N] [--workdir DIR] -- COMMAND [ARGS...]")
}

func cmdPing(args []string, jsonOut bool) int {
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		printErr(err)
		return 1
	}
	if fs.NArg() != 0 {
		printErr(errors.New("ping takes no arguments"))
		return 1
	}

	resp, err := callCtl("ping", map[string]any{}, defaultIOTimeout)
	if err != nil {
		printErr(err)
		return 1
	}

	if jsonOut {
		printRawJSON(resp.Result)
		return 0
	}

	var result struct {
		OK     bool   `json:"ok"`
		Parent string `json:"parent"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		printErr(fmt.Errorf("invalid response: %w", err))
		return 1
	}
	if result.Parent != "" {
		fmt.Printf("ok (parent: %s)\n", result.Parent)
		return 0
	}
	fmt.Println("ok")
	return 0
}

func cmdSpawn(args []string, jsonOut bool) int {
	fs := flag.NewFlagSet("spawn", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	image := fs.String("image", "", "")
	name := fs.String("name", "", "")
	cpus := fs.Int("cpus", 0, "")
	memory := fs.String("memory", "", "")
	if err := fs.Parse(args); err != nil {
		printErr(err)
		return 1
	}
	if fs.NArg() != 0 {
		printErr(errors.New("spawn does not take positional arguments"))
		return 1
	}

	params := map[string]any{}
	if *image != "" {
		params["image"] = *image
	}
	if *name != "" {
		params["name"] = *name
	}
	if *cpus != 0 {
		params["cpus"] = *cpus
	}
	if *memory != "" {
		params["memory"] = *memory
	}

	resp, err := callCtl("spawn", params, defaultIOTimeout)
	if err != nil {
		printErr(err)
		return 1
	}

	if jsonOut {
		printRawJSON(resp.Result)
		return 0
	}

	var result struct {
		Name      string `json:"name"`
		Container string `json:"container"`
		Image     string `json:"image"`
		CPUs      int    `json:"cpus"`
		MemoryMB  int    `json:"memory_mb"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		printErr(fmt.Errorf("invalid response: %w", err))
		return 1
	}
	fmt.Printf("%s\n", result.Name)
	return 0
}

func cmdList(args []string, jsonOut bool) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		printErr(err)
		return 1
	}
	if fs.NArg() != 0 {
		printErr(errors.New("list takes no arguments"))
		return 1
	}

	resp, err := callCtl("list", map[string]any{}, defaultIOTimeout)
	if err != nil {
		printErr(err)
		return 1
	}

	if jsonOut {
		printRawJSON(resp.Result)
		return 0
	}

	var result struct {
		Children []struct {
			Name      string   `json:"name"`
			Image     string   `json:"image"`
			CPUs      int      `json:"cpus"`
			MemoryMB  int      `json:"memory_mb"`
			ExpiresAt *float64 `json:"expires_at"`
		} `json:"children"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		printErr(fmt.Errorf("invalid response: %w", err))
		return 1
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tIMAGE\tCPUS\tMEM(MB)\tTTL")
	now := time.Now()
	for _, c := range result.Children {
		ttl := "-"
		if c.ExpiresAt != nil && *c.ExpiresAt > 0 {
			sec, frac := math.Modf(*c.ExpiresAt)
			exp := time.Unix(int64(sec), int64(frac*1e9))
			d := exp.Sub(now)
			ttl = formatTTL(d)
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\n", c.Name, c.Image, c.CPUs, c.MemoryMB, ttl)
	}
	_ = tw.Flush()
	return 0
}

func cmdDestroy(args []string, jsonOut bool) int {
	if len(args) != 1 {
		printErr(errors.New("destroy requires a name"))
		return 1
	}
	name := args[0]

	resp, err := callCtl("destroy", map[string]any{"name": name}, defaultIOTimeout)
	if err != nil {
		printErr(err)
		return 1
	}

	if jsonOut {
		printRawJSON(resp.Result)
		return 0
	}

	fmt.Printf("%s\n", name)
	return 0
}

func cmdRun(args []string, jsonOut bool) int {
	return cmdRunExec("run", args, jsonOut)
}

func cmdExec(args []string, jsonOut bool) int {
	return cmdRunExec("exec", args, jsonOut)
}

func cmdRunExec(method string, args []string, jsonOut bool) int {
	var name string
	var flagArgs, cmdArgs []string

	fs := flag.NewFlagSet(method, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var image *string
	timeoutSec := fs.Int("timeout", 0, "")
	workdir := fs.String("workdir", "", "")

	switch method {
	case "run":
		var err error
		flagArgs, cmdArgs, err = splitDoubleDash(args)
		if err != nil {
			printErr(err)
			return 1
		}
		if len(cmdArgs) == 0 {
			printErr(errors.New("missing command after --"))
			return 1
		}
		image = fs.String("image", "", "")
	case "exec":
		if len(args) == 0 {
			printErr(errors.New("exec requires a name"))
			return 1
		}
		name = args[0]
		var err error
		flagArgs, cmdArgs, err = splitDoubleDash(args[1:])
		if err != nil {
			printErr(err)
			return 1
		}
		if len(cmdArgs) == 0 {
			printErr(errors.New("missing command after --"))
			return 1
		}
	default:
		printErr(fmt.Errorf("unknown method: %s", method))
		return 1
	}

	if err := fs.Parse(flagArgs); err != nil {
		printErr(err)
		return 1
	}
	if fs.NArg() != 0 {
		printErr(errors.New("unexpected arguments"))
		return 1
	}

	params := map[string]any{
		"command": shellJoin(cmdArgs),
	}
	if method == "exec" {
		params["name"] = name
	}
	if image != nil && *image != "" {
		params["image"] = *image
	}
	if *timeoutSec > 0 {
		params["timeout"] = *timeoutSec
	}
	if *workdir != "" {
		params["workdir"] = *workdir
	}

	overall := defaultIOTimeout
	if *timeoutSec > 0 {
		overall = time.Duration(*timeoutSec)*time.Second + time.Minute
		if overall < defaultIOTimeout {
			overall = defaultIOTimeout
		}
	}

	resp, err := callCtl(method, params, overall)
	if err != nil {
		printErr(err)
		return 1
	}

	var result struct {
		Name   string `json:"name"`
		Result struct {
			Stdout   string `json:"stdout"`
			Stderr   string `json:"stderr"`
			ExitCode int    `json:"exit_code"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		printErr(fmt.Errorf("invalid response: %w", err))
		return 1
	}

	if jsonOut {
		printRawJSON(resp.Result)
		return normalizeExitCode(result.Result.ExitCode)
	}

	printExecOutput(result.Result.Stdout, result.Result.Stderr)
	return normalizeExitCode(result.Result.ExitCode)
}

func callCtl(method string, params map[string]any, overallTimeout time.Duration) (ctlResponse, error) {
	if overallTimeout <= 0 {
		overallTimeout = defaultIOTimeout
	}

	reqID, err := newUUIDv4()
	if err != nil {
		return ctlResponse{}, err
	}
	if params == nil {
		params = map[string]any{}
	}

	req := ctlRequest{ID: reqID, Method: method, Params: params}
	data, err := json.Marshal(req)
	if err != nil {
		return ctlResponse{}, err
	}
	data = append(data, '\n')

	sock := os.Getenv("SANDBOX_CTL_SOCK")
	if sock == "" {
		sock = defaultSockPath
	}

	deadline := time.Now().Add(overallTimeout)
	respLine, err := sendNDJSON(sock, data, deadline)
	if err != nil {
		return ctlResponse{}, err
	}

	var resp ctlResponse
	if err := json.Unmarshal(respLine, &resp); err != nil {
		return ctlResponse{}, fmt.Errorf("invalid response JSON: %w", err)
	}
	if resp.ID != reqID {
		return ctlResponse{}, fmt.Errorf("mismatched response id: got %q, want %q", resp.ID, reqID)
	}
	if resp.Error != nil {
		if resp.Error.Code != "" {
			return ctlResponse{}, fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return ctlResponse{}, errors.New(resp.Error.Message)
	}
	if len(resp.Result) == 0 {
		return ctlResponse{}, errors.New("missing result")
	}
	return resp, nil
}

func sendNDJSON(sock string, reqLine []byte, deadline time.Time) ([]byte, error) {
	try := func() ([]byte, error) {
		timeLeft := time.Until(deadline)
		if timeLeft <= 0 {
			return nil, errors.New("timeout")
		}
		conn, err := net.DialTimeout("unix", sock, timeLeft)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		_ = conn.SetDeadline(deadline)

		if _, err := conn.Write(reqLine); err != nil {
			return nil, err
		}

		br := bufio.NewReader(conn)
		line, err := br.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			return nil, errors.New("empty response")
		}
		if len(line) > maxResponseBytes {
			return nil, errors.New("response too large")
		}
		return line, nil
	}

	line, err := try()
	if err == nil {
		return line, nil
	}
	time.Sleep(connectRetryDelay)
	line2, err2 := try()
	if err2 == nil {
		return line2, nil
	}
	return nil, err2
}

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:]), nil
}

func printErr(err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "sandbox-ctl: %v\n", err)
}

func printRawJSON(raw json.RawMessage) {
	os.Stdout.Write(raw)
	os.Stdout.Write([]byte("\n"))
}

func splitDoubleDash(args []string) ([]string, []string, error) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:], nil
		}
	}
	return nil, nil, errors.New("expected -- before command")
}

func shellJoin(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsRune(s, '\'') {
		return "'" + s + "'"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func printExecOutput(stdout, stderr string) {
	if stdout != "" {
		fmt.Fprint(os.Stdout, stdout)
	}
	if stderr == "" {
		return
	}
	if stdout != "" && !strings.HasSuffix(stdout, "\n") {
		fmt.Fprintln(os.Stdout)
	}
	lines := strings.Split(stderr, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		fmt.Fprintf(os.Stderr, "[stderr] %s\n", line)
	}
}

func normalizeExitCode(code int) int {
	if code == 0 {
		return 0
	}
	if code < 0 {
		return 1
	}
	if code > 255 {
		return 1
	}
	return code
}

func formatTTL(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	sec := int64(d.Round(time.Second).Seconds())
	if sec < 60 {
		return fmt.Sprintf("%ds", sec)
	}
	min := sec / 60
	sec = sec % 60
	if min < 60 {
		return fmt.Sprintf("%dm%ds", min, sec)
	}
	hr := min / 60
	min = min % 60
	return fmt.Sprintf("%dh%dm", hr, min)
}
