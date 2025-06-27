package modelfuzz

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"
)

// Fuzzer is the main struct that holds the state of the fuzzer.
// It contains the message queues, nodes, configuration, and statistics.
// It is responsible for running the fuzzer iterations and managing the traces.
// It uses a cluster constructor to create the cluster environment for the fuzzer.
type Fuzzer struct {
	messageQueues      map[string]*Queue[Message]
	nodes              []uint64
	config             *FuzzerConfig
	mutatedTracesQueue *Queue[*List[*Choice]]
	rand               *rand.Rand
	clusterConstructor ClusterConstructor

	stats map[string]interface{}
}

type traceCtx struct {
	trace          *List[*Choice]
	mimicTrace     *List[*Choice]
	eventTrace     *List[*Event]
	nodeChoices    *Queue[*Choice]
	booleanChoices *Queue[bool]
	integerChoices *Queue[int]
	crashPoints    map[int]uint64
	startPoints    map[int]uint64
	clientRequests map[int]string
	rand           *rand.Rand

	Error  error
	fuzzer *Fuzzer
}

func (t *traceCtx) SetError(err error) {
	t.Error = err
}

func (t *traceCtx) GetError() error {
	return t.Error
}

func (t *traceCtx) IsError() bool {
	return t.Error != nil
}

func (t *traceCtx) GetNextNodeChoice() (uint64, uint64, int) {
	var fromChoice uint64
	var toChoice uint64
	var maxMessages int
	if t.nodeChoices.Size() > 0 {
		c, _ := t.nodeChoices.Pop()
		fromChoice = c.From
		toChoice = c.To
		maxMessages = c.MaxMessages
	} else {
		i := t.rand.Intn(len(t.fuzzer.nodes))
		j := t.rand.Intn(len(t.fuzzer.nodes))
		fromChoice = t.fuzzer.nodes[i]
		toChoice = t.fuzzer.nodes[j]
		maxMessages = t.rand.Intn(t.fuzzer.config.MaxMessages)
	}
	t.trace.Append(&Choice{
		Type:        "Node",
		From:        fromChoice,
		To:          toChoice,
		MaxMessages: maxMessages,
	})

	return fromChoice, toChoice, maxMessages
}

func (t *traceCtx) CanCrash(step int) (uint64, bool) {
	node, ok := t.crashPoints[step]
	if ok {
		t.eventTrace.Append(&Event{
			Name: "Remove",
			Node: node,
			Params: map[string]interface{}{
				"i": int(node),
			},
		})
		t.trace.Append(&Choice{
			Type: "StopNode",
			Node: node,
			Step: step,
		})
	}
	return node, ok
}

func (t *traceCtx) CanStart(step int) (uint64, bool) {
	node, ok := t.startPoints[step]
	if ok {
		t.eventTrace.Append(&Event{
			Name: "Add",
			Node: node,
			Params: map[string]interface{}{
				"i": int(node),
			},
		})
		t.trace.Append(&Choice{
			Type: "StartNode",
			Node: node,
			Step: step,
		})
	}
	return node, ok
}

func (t *traceCtx) IsClientRequest(step int) (string, bool) {
	req, ok := t.clientRequests[step]
	if ok {
		t.trace.Append(&Choice{
			Type:    "ClientRequest",
			Request: req,
		})
	}
	return req, ok
}

// FuzzerConfig holds the configuration for the fuzzer.
type FuzzerConfig struct {
	// Iterations is the number of iterations to run the fuzzer.
	Iterations int
	// Steps is the number of steps to run in each iteration.
	Steps int
	// Mutator is the mutator to use for generating new traces.
	Mutator Mutator
	// Guider is the guider to use for checking the coverage and guiding the fuzzer.
	Guider Guider
	// NumNodes is the number of nodes in the cluster.
	NumNodes int
	// ClusterConstructor is the constructor for creating the cluster environment.
	ClusterConstructor ClusterConstructor
	// MutPerTrace is the number of mutations to perform per trace.
	MutPerTrace int
	// SeedPopulationSize is the number of seed traces to generate at the start.
	// It is used to populate the mutated traces queue.
	SeedPopulationSize int
	// NumberRequests is the number of client requests to generate in each iteration.
	NumberRequests int
	// CrashQuota is the number of crash points to generate in each iteration.
	CrashQuota int
	// MaxMessages is the maximum number of messages to send in each node choice.
	MaxMessages int
	// ReseedFrequency is the frequency at which to reseed the mutated traces queue.
	// It determines how often the fuzzer will generate new seed traces.
	ReseedFrequency int
}

// NewFuzzer creates a new Fuzzer instance with the given configuration.
func NewFuzzer(config *FuzzerConfig) *Fuzzer {
	f := &Fuzzer{
		config:             config,
		nodes:              make([]uint64, 0),
		messageQueues:      make(map[string]*Queue[Message]),
		mutatedTracesQueue: NewQueue[*List[*Choice]](),
		rand:               rand.New(rand.NewSource(time.Now().UnixNano())),
		clusterConstructor: config.ClusterConstructor,
		stats:              make(map[string]interface{}),
	}
	for i := 0; i <= f.config.NumNodes; i++ {
		f.nodes = append(f.nodes, uint64(i))
		for j := 0; j <= f.config.NumNodes; j++ {
			key := fmt.Sprintf("%d_%d", i, j)
			f.messageQueues[key] = NewQueue[Message]()
		}
	}
	f.stats["random_executions"] = 0
	f.stats["mutated_executions"] = 0
	f.stats["execution_errors"] = make(map[string]bool, 0)
	f.stats["error_executions"] = make(map[string][]string)
	f.stats["buggy_executions"] = make(map[string]bool, 0)
	return f
}

// Schedule retrieves messages from the message queues for the given node pair.
func (f *Fuzzer) Schedule(from uint64, to uint64, maxMessages int) []Message {
	key := fmt.Sprintf("%d_%d", from, to)
	queue, ok := f.messageQueues[key]
	if !ok || queue.Size() == 0 {
		return []Message{}
	}
	messages := make([]Message, 0)
	for i := 0; i < maxMessages; i++ {
		message, ok := queue.Pop()
		if !ok {
			break
		}
		messages = append(messages, message)
	}
	return messages
}

func recordReceive(message Message, eventTrace *List[*Event]) {
	eventTrace.Append(&Event{
		Name: "DeliverMessage",
		Node: message.To(),
		Params: map[string]interface{}{
			"type":   message.Type(),
			"params": message.Params(),
			"from":   message.From(),
			"to":     message.To(),
		},
	})
}

func recordSend(message Message, eventTrace *List[*Event]) {
	eventTrace.Append(&Event{
		Name: "SendMessage",
		Node: message.From(),
		Params: map[string]interface{}{
			"type":   message.Type(),
			"params": message.Params(),
			"from":   message.From(),
			"to":     message.To(),
		},
	})
}

func (f *Fuzzer) seed() {
	f.mutatedTracesQueue.Reset()
	for i := 0; i < f.config.SeedPopulationSize; i++ {
		trace, _ := f.RunIteration(fmt.Sprintf("pop_%d", i), nil)
		f.mutatedTracesQueue.Push(copyTrace(trace, defaultCopyFilter()))
	}
}

// Run executes the fuzzer for the specified number of iterations.
// During each iteration, it either uses a mutated trace from the queue or generates a new random trace.
// If a mutated trace is used, it attempts to mutate it further based on the guider's feedback.
// The fuzzer collects coverage statistics and execution errors throughout the process.
// The final coverage statistics are returned after all iterations.
func (f *Fuzzer) Run() CoverageStats {
	coverages := make([]CoverageStats, 0)
	for i := 0; i < f.config.Iterations; i++ {
		if i%f.config.ReseedFrequency == 0 {
			f.seed()
		}
		fmt.Printf("\rRunning iteration: %d/%d", i+1, f.config.Iterations)
		var mimic *List[*Choice] = nil
		if f.mutatedTracesQueue.Size() > 0 {
			f.stats["mutated_executions"] = f.stats["mutated_executions"].(int) + 1
			mimic, _ = f.mutatedTracesQueue.Pop()
		} else {
			f.stats["random_executions"] = f.stats["random_executions"].(int) + 1
		}
		trace, eventTrace := f.RunIteration(fmt.Sprintf("fuzz_%d", i), mimic)
		if _, numNewStates := f.config.Guider.Check(trace, eventTrace); numNewStates > 0 {
			numMutations := int(numNewStates) * f.config.MutPerTrace
			for j := 0; j < numMutations; j++ {
				new, ok := f.config.Mutator.Mutate(trace, eventTrace)
				if ok {
					f.mutatedTracesQueue.Push(copyTrace(new, defaultCopyFilter()))
				}
			}
		}
		coverages = append(coverages, f.config.Guider.Coverage())
	}
	return coverages[len(coverages)-1]
}

// RunIteration executes a single iteration of the fuzzer.
// It sets up the context for the iteration, initializes the cluster, and runs the episode loop
// where it processes node choices, crash points, and client requests.
func (f *Fuzzer) RunIteration(iteration string, mimic *List[*Choice]) (*List[*Choice], *List[*Event]) {
	// Setup the context for the iterations
	tCtx := &traceCtx{
		trace:          NewList[*Choice](),
		eventTrace:     NewList[*Event](),
		nodeChoices:    NewQueue[*Choice](),
		booleanChoices: NewQueue[bool](),
		integerChoices: NewQueue[int](),
		crashPoints:    make(map[int]uint64),
		startPoints:    make(map[int]uint64),
		clientRequests: make(map[int]string),
		rand:           f.rand,
		fuzzer:         f,
	}
	cluster := f.clusterConstructor.NewCluster(f.nodes)
	if mimic != nil {
		tCtx.mimicTrace = mimic
		for i := 0; i < mimic.Size(); i++ {
			ch, _ := mimic.Get(i)
			switch ch.Type {
			case "Node":
				tCtx.nodeChoices.Push(ch.Copy())
			case "StartNode":
				tCtx.startPoints[ch.Step] = ch.Node
			case "StopNode":
				tCtx.crashPoints[ch.Step] = ch.Node
			case "ClientRequest":
				tCtx.clientRequests[ch.Step] = ch.Request
			}
		}
	} else {
		for i := 0; i < f.config.Steps; i++ {
			var fromIdx int = 0
			for fromIdx == 0 {
				fromIdx = f.rand.Intn(len(f.nodes))
			}
			var toIdx int = 0
			for toIdx == 0 {
				toIdx = f.rand.Intn(len(f.nodes))
			}
			tCtx.nodeChoices.Push(&Choice{
				Type:        "Node",
				From:        f.nodes[fromIdx],
				To:          f.nodes[toIdx],
				MaxMessages: f.rand.Intn(f.config.MaxMessages),
			})
		}
		choices := make([]int, f.config.Steps)
		for i := 0; i < f.config.Steps; i++ {
			choices[i] = i
		}
		for _, c := range sample(choices, f.config.CrashQuota, f.rand) {
			var idx int = 0
			for idx == 0 {
				idx = f.rand.Intn(len(f.nodes))
			}
			tCtx.crashPoints[c] = uint64(idx)
			s := sample(intRange(c, f.config.Steps), 1, f.rand)[0]
			tCtx.startPoints[s] = uint64(idx)
		}
		i := 1
		for _, req := range sample(choices, f.config.NumberRequests, f.rand) {
			tCtx.clientRequests[req] = strconv.Itoa(i)
			i++
		}
	}

	// Reset the queues and environment
	for _, q := range f.messageQueues {
		q.Reset()
	}
	cluster.Reset()

	crashed := make(map[uint64]bool)
	fCtx := &FuzzContext{traceCtx: tCtx}
EpisodeLoop:
	for j := 0; j < f.config.Steps; j++ {
		if toCrash, ok := tCtx.CanCrash(j); ok {
			err := cluster.Stop(fCtx, toCrash)
			if err != nil || tCtx.IsError() {
				break EpisodeLoop
			}
			crashed[toCrash] = true
		}
		if toStart, ok := tCtx.CanStart(j); ok {
			_, isCrashed := crashed[toStart]
			if isCrashed {
				err := cluster.Start(fCtx, toStart)
				if err != nil || tCtx.IsError() {
					break EpisodeLoop
				}
				delete(crashed, toStart)
			}
		}
		from, to, maxMessages := tCtx.GetNextNodeChoice()
		if _, ok := crashed[to]; !ok {
			messages := f.Schedule(from, to, maxMessages)
			for _, m := range messages {
				recordReceive(m, tCtx.eventTrace)
				err := cluster.ReceiveMessage(fCtx, m)
				if err != nil || tCtx.IsError() {
					break EpisodeLoop
				}
			}
		}

		if reqNum, ok := tCtx.IsClientRequest(j); ok {
			err := cluster.ClientRequest(fCtx, reqNum)
			if err != nil || tCtx.IsError() {
				break EpisodeLoop
			}
		}

		for _, n := range cluster.Tick(fCtx) {
			recordSend(n, tCtx.eventTrace)
			key := fmt.Sprintf("%d_%d", n.From(), n.To())
			f.messageQueues[key].Push(n)
		}
	}
	if tCtx.IsError() {
		errS := tCtx.GetError().Error()
		f.stats["execution_errors"].(map[string]bool)[errS] = true
		if _, ok := f.stats["error_executions"].(map[string][]string)[errS]; !ok {
			f.stats["error_executions"].(map[string][]string)[errS] = make([]string, 0)
		}
		f.stats["error_executions"].(map[string][]string)[errS] = append(f.stats["error_executions"].(map[string][]string)[errS], iteration)
	}

	return tCtx.trace, tCtx.eventTrace
}

// FuzzContext holds the context for the fuzzer.
// The context is passed to the cluster and allows the cluster to
// add events to the trace.
// A new FuzzContext is created for each iteration of the fuzzer.
type FuzzContext struct {
	traceCtx *traceCtx
}

// AddEvent adds an event to the event trace.
func (f *FuzzContext) AddEvent(e *Event) {
	f.traceCtx.eventTrace.Append(e)
}
