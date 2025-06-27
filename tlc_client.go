package modelfuzz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// TLCResponse represents the response from the TLC server.
type TLCResponse struct {
	// States is a list of state representations returned by the TLC server.
	States []string
	// Keys is a list of keys corresponding to the states.
	Keys []int64
}

// TLCClient is a client for communicating with the TLC server.
type TLCClient struct {
	// ClientAddr is the address of the TLC server.
	// It should be in the format "host:port".
	ClientAddr string
}

// NewTLCClient creates a new TLCClient with the specified address.
func NewTLCClient(addr string) *TLCClient {
	return &TLCClient{
		ClientAddr: addr,
	}
}

// SendTrace sends a trace to the TLC server and returns the states received in response.
func (c *TLCClient) SendTrace(trace *List[*Event]) ([]State, error) {
	trace.Append(&Event{Reset: true})
	data, err := json.Marshal(trace)
	if err != nil {
		return []State{}, fmt.Errorf("error marshalling json: %s", err)
	}
	res, err := http.Post("http://"+c.ClientAddr+"/execute", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return []State{}, fmt.Errorf("error sending trace to tlc: %s", err)
	}
	defer res.Body.Close()
	resData, err := io.ReadAll(res.Body)
	if err != nil {
		return []State{}, fmt.Errorf("error reading response from tlc: %s", err)
	}
	tlcResponse := &TLCResponse{}
	if err = json.Unmarshal(resData, tlcResponse); err != nil {
		return []State{}, fmt.Errorf("error parsing tlc response: %s", err)
	}
	result := make([]State, len(tlcResponse.States))
	for i, s := range tlcResponse.States {
		result[i] = State{Repr: s, Key: tlcResponse.Keys[i]}
	}
	return result, nil
}
