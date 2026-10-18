// Command interop-driver runs one role of a SPAKE2+ exchange over
// line-delimited JSON on stdin/stdout, for cross-language interop tests.
//
//	interop-driver prover|verifier <config.json>
//
// See SPEC.md, "Driver contract". The outcome is one JSON line on stderr.
// Exit codes: 0 ok, 1 protocol failure, 2 bad usage.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	spake2p "github.com/9Reg/spake2p/go"
)

type config struct {
	Context     string `json:"context"`
	IDProver    string `json:"idProver"`
	IDVerifier  string `json:"idVerifier"`
	PBKDFOutput string `json:"pbkdf_output"`
}

func main() { os.Exit(run()) }

func usage(msg string) int {
	fmt.Fprintln(os.Stderr, "interop-driver:", msg)
	fmt.Fprintln(os.Stderr, "usage: interop-driver prover|verifier <config.json>")
	return 2
}

func outcome(key []byte, err error) int {
	var o struct {
		OK      bool   `json:"ok"`
		KShared string `json:"K_shared,omitempty"`
		Error   string `json:"error,omitempty"`
	}
	code := 0
	if err == nil {
		o.OK, o.KShared = true, hex.EncodeToString(key)
	} else {
		o.Error, code = kind(err), 1
	}
	b, _ := json.Marshal(o)
	fmt.Fprintln(os.Stderr, string(b))
	return code
}

func kind(err error) string {
	for _, k := range []struct {
		e error
		n string
	}{
		{spake2p.ErrConfirmationFailed, "confirmation_failed"},
		{spake2p.ErrInvalidPoint, "invalid_point"},
		{spake2p.ErrInvalidRecord, "invalid_record"},
		{errPeerAborted, "peer_aborted"},
		{spake2p.ErrInvalidMessage, "invalid_message"},
		{spake2p.ErrInvalidScalar, "invalid_scalar"},
		{spake2p.ErrInvalidPBKDFOutput, "invalid_pbkdf_output"},
		{spake2p.ErrFinished, "finished"},
		{spake2p.ErrInvalidState, "invalid_state"},
		{spake2p.ErrRandom, "random"},
	} {
		if errors.Is(err, k.e) {
			return k.n
		}
	}
	return "io"
}

func run() int {
	if len(os.Args) != 3 || (os.Args[1] != "prover" && os.Args[1] != "verifier") {
		return usage("expected a role and a config path")
	}
	raw, err := os.ReadFile(os.Args[2])
	if err != nil {
		return usage("cannot read config")
	}
	var c config
	if json.Unmarshal(raw, &c) != nil {
		return usage("config is not valid JSON")
	}
	context, e1 := hex.DecodeString(c.Context)
	idP, e2 := hex.DecodeString(c.IDProver)
	idV, e3 := hex.DecodeString(c.IDVerifier)
	pbkdf, e4 := hex.DecodeString(c.PBKDFOutput)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return usage("config has invalid hex")
	}
	w0, w1, err := spake2p.W0W1FromPBKDFOutput(pbkdf)
	if err != nil {
		return usage("pbkdf_output must be 80 bytes")
	}

	in := bufio.NewReaderSize(os.Stdin, 1<<16)
	out := bufio.NewWriter(os.Stdout)
	send := func(m map[string]any) error {
		b, _ := json.Marshal(m)
		if _, err := out.Write(append(b, '\n')); err != nil {
			return err
		}
		return out.Flush()
	}
	recv := func(fields ...string) (map[string][]byte, bool, error) {
		line, err := in.ReadBytes('\n')
		if err != nil && len(line) == 0 {
			return nil, false, err
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			return nil, false, err
		}
		if a, _ := m["abort"].(bool); a {
			return nil, true, nil
		}
		res := map[string][]byte{}
		for _, f := range fields {
			s, _ := m[f].(string)
			b, err := hex.DecodeString(s)
			if err != nil {
				return nil, false, err
			}
			res[f] = b
		}
		return res, false, nil
	}

	if os.Args[1] == "prover" {
		p, shareP, err := spake2p.StartProver(context, idP, idV, w0, w1)
		if err != nil {
			return outcome(nil, err)
		}
		if err := send(map[string]any{"shareP": hex.EncodeToString(shareP)}); err != nil {
			return outcome(nil, err)
		}
		m, aborted, err := recv("shareV", "confirmV")
		if err != nil || aborted {
			return outcome(nil, orIO(err))
		}
		confirmP, key, err := p.Finish(spake2p.ShareV(m["shareV"]), spake2p.ConfirmV(m["confirmV"]))
		if err != nil {
			_ = send(map[string]any{"abort": true})
			return outcome(nil, err)
		}
		if err := send(map[string]any{"confirmP": hex.EncodeToString(confirmP)}); err != nil {
			return outcome(nil, err)
		}
		return outcome(key, nil)
	}

	// Verifier: derive L from w1, then forget w1.
	l, err := spake2p.Register(w1)
	w1.Zero()
	if err != nil {
		return outcome(nil, err)
	}
	m, aborted, err := recv("shareP")
	if err != nil || aborted {
		return outcome(nil, orIO(err))
	}
	v, shareV, confirmV, err := spake2p.RespondVerifier(context, idP, idV, w0, l, m["shareP"])
	if err != nil {
		return outcome(nil, err)
	}
	defer v.Close()
	if err := send(map[string]any{"shareV": hex.EncodeToString(shareV), "confirmV": hex.EncodeToString(confirmV)}); err != nil {
		return outcome(nil, err)
	}
	m, aborted, err = recv("confirmP")
	if err != nil || aborted {
		return outcome(nil, orIO(err))
	}
	key, err := v.Finish(spake2p.ConfirmP(m["confirmP"]))
	return outcome(key, err)
}

// errPeerAborted: the peer sent {"abort": true} (SPEC.md, Driver contract).
var errPeerAborted = errors.New("peer aborted")

func orIO(err error) error {
	if err == nil {
		return errPeerAborted
	}
	return err
}
