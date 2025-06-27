package modelfuzz

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
)

// CoverageStats holds the coverage statistics for the guider.
type CoverageStats struct {
	// UniqueStates is the number of unique states encountered by the guider.
	UniqueStates int
}

// Guider is an interface that defines the methods for a guider in the model fuzzing framework.
type Guider interface {
	// Check takes a trace and an event trace, checks them to return the number
	//  of new states found and the coverage ratio.
	Check(*List[*Choice], *List[*Event]) (int, float64)
	// Coverage returns the coverage statistics of the guider.
	Coverage() CoverageStats
	// Reset resets the guider's state.
	Reset(string)
}

// TLCStateGuider is a guider that uses the TLC (Temporal Logic Checker) to guide the model fuzzing process.
// It sends traces to the TLC server and receives states, which it uses to track coverage.
type TLCStateGuider struct {
	TLCAddr        string
	statesMap      map[int64]bool
	tracesMap      map[string]bool
	stateTracesMap map[string]bool
	tlcClient      *TLCClient
	recordPath     string
	recordTraces   bool
	count          int

	lock *sync.Mutex
}

var _ Guider = &TLCStateGuider{}

func NewTLCStateGuider(tlcAddr, recordPath string, recordTraces bool) *TLCStateGuider {
	if recordPath != "" {
		if _, err := os.Stat(recordPath); err == nil {
			os.RemoveAll(recordPath)
		}
		os.Mkdir(recordPath, 0777)
	}
	return &TLCStateGuider{
		TLCAddr:        tlcAddr,
		statesMap:      make(map[int64]bool),
		tracesMap:      make(map[string]bool),
		stateTracesMap: make(map[string]bool),
		tlcClient:      NewTLCClient(tlcAddr),
		recordPath:     recordPath,
		recordTraces:   recordTraces,
		count:          0,
		lock:           new(sync.Mutex),
	}
}

func (t *TLCStateGuider) Reset(key string) {
	t.lock.Lock()
	t.statesMap = make(map[int64]bool)
	t.tracesMap = make(map[string]bool)
	t.stateTracesMap = make(map[string]bool)
	t.lock.Unlock()
}

func (t *TLCStateGuider) Coverage() CoverageStats {
	t.lock.Lock()
	defer t.lock.Unlock()
	return CoverageStats{
		UniqueStates: len(t.statesMap),
	}
}

func (t *TLCStateGuider) Check(trace *List[*Choice], eventTrace *List[*Event]) (int, float64) {
	bs, _ := json.Marshal(trace)
	sum := sha256.Sum256(bs)
	hash := hex.EncodeToString(sum[:])
	t.lock.Lock()
	if _, ok := t.tracesMap[hash]; !ok {
		// fmt.Printf("New trace: %s\n", hash)
		t.tracesMap[hash] = true
	}
	t.lock.Unlock()

	t.lock.Lock()
	curStates := len(t.statesMap)
	t.lock.Unlock()
	numNewStates := 0
	if tlcStates, err := t.tlcClient.SendTrace(eventTrace); err == nil {
		t.recordTrace(trace, eventTrace, tlcStates)
		for _, s := range tlcStates {
			t.lock.Lock()
			_, ok := t.statesMap[s.Key]
			if !ok {
				numNewStates += 1
				t.statesMap[s.Key] = true
			}
			t.lock.Unlock()
		}
		bs, _ := json.Marshal(tlcStates)
		sum := sha256.Sum256(bs)
		stateTraceHash := hex.EncodeToString(sum[:])
		t.lock.Lock()
		if _, ok := t.stateTracesMap[stateTraceHash]; !ok {
			// fmt.Printf("New state trace: %s\n", stateTraceHash)
			t.stateTracesMap[stateTraceHash] = true
		}
		t.lock.Unlock()
	} else {
		panic(fmt.Sprintf("error connecting to tlc: %s", err))
	}
	return numNewStates, float64(numNewStates) / float64(max(curStates, 1))
}

func (t *TLCStateGuider) recordTrace(trace *List[*Choice], eventTrace *List[*Event], states []State) {
	if !t.recordTraces {
		return
	}
	filePath := path.Join(t.recordPath, strconv.Itoa(t.count)+".json")
	t.count += 1
	data := map[string]interface{}{
		"trace":       trace,
		"event_trace": eventTrace,
		"state_trace": parseTLCStateTrace(states),
	}
	dataB, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return
	}
	file, err := os.Create(filePath)
	if err != nil {
		return
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	writer.Write(dataB)
	writer.Flush()
}

func parseTLCStateTrace(states []State) []State {
	newStates := make([]State, len(states))
	for i, s := range states {
		repr := strings.ReplaceAll(s.Repr, "\n", ",")
		repr = strings.ReplaceAll(repr, "/\\", "")
		repr = strings.ReplaceAll(repr, "\u003e\u003e", "]")
		repr = strings.ReplaceAll(repr, "\u003c\u003c", "[")
		repr = strings.ReplaceAll(repr, "\u003e", ">")
		newStates[i] = State{
			Repr: repr,
			Key:  s.Key,
		}
	}
	return newStates
}
