package modelfuzz

import (
	"fmt"
	"math/rand"
	"time"
)

// Mutator is an interface that defines the method for mutating a trace.
type Mutator interface {
	// Mutate takes a trace and an event trace, and returns a mutated trace and a boolean indicating
	// whether the mutation was successful or not.
	Mutate(*List[*Choice], *List[*Event]) (*List[*Choice], bool)
}

type randomMutator struct{}

func (r *randomMutator) Mutate(_ *List[*Choice], _ *List[*Event]) (*List[*Choice], bool) {
	return nil, false
}

// RandomMutator returns a Mutator that does not perform any mutations.
func RandomMutator() Mutator {
	return &randomMutator{}
}

// SwapCrashNodeMutator is a Mutator that swaps the nodes of crash choices in a trace.
// It randomly selects pairs of crash choices and swaps their nodes.
// It requires a specified number of swaps to be performed.
type SwapCrashNodeMutator struct {
	NumSwaps int
	r        *rand.Rand
}

var _ Mutator = &SwapCrashNodeMutator{}

func NewSwapCrashNodeMutator(swaps int) *SwapCrashNodeMutator {
	return &SwapCrashNodeMutator{
		NumSwaps: swaps,
		r:        rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (s *SwapCrashNodeMutator) Mutate(trace *List[*Choice], eventTrace *List[*Event]) (*List[*Choice], bool) {
	swaps := make(map[int]int)

	nodeChoices := make([]int, 0)
	for i, ch := range trace.Iter() {
		if ch.Type == "Crash" {
			nodeChoices = append(nodeChoices, i)
		}
	}

	if len(nodeChoices) < s.NumSwaps*2 {
		return nil, false
	}

	for len(swaps) < s.NumSwaps {
		sp := sample(nodeChoices, 2, s.r)
		swaps[sp[0]] = sp[1]
	}

	newTrace := trace.Copy()
	for i, j := range swaps {
		iCh, _ := newTrace.Get(i)
		jCh, _ := newTrace.Get(j)

		iChNew := iCh.Copy()
		iChNew.Node = jCh.Node
		jChNew := jCh.Copy()
		jChNew.Node = iCh.Node

		newTrace.Set(i, iChNew)
		newTrace.Set(j, jChNew)
	}
	return newTrace, true
}

// SwapNodeMutator is a Mutator that swaps the nodes of node choices in a trace.
// It randomly selects pairs of node choices and swaps their nodes.
// It requires a specified number of swaps to be performed.
type SwapNodeMutator struct {
	NumSwaps int
	rand     *rand.Rand
}

var _ Mutator = &SwapNodeMutator{}

func NewSwapNodeMutator(swaps int) *SwapNodeMutator {
	return &SwapNodeMutator{
		NumSwaps: swaps,
		rand:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (s *SwapNodeMutator) Mutate(trace *List[*Choice], _ *List[*Event]) (*List[*Choice], bool) {
	nodeChoiceIndices := make([]int, 0)
	for i, choice := range trace.Iter() {
		if choice.Type == "Node" {
			nodeChoiceIndices = append(nodeChoiceIndices, i)
		}
	}
	numNodeChoiceIndices := len(nodeChoiceIndices)
	if numNodeChoiceIndices == 0 {
		return nil, false
	}
	choices := numNodeChoiceIndices
	if s.NumSwaps < choices {
		choices = s.NumSwaps
	}
	toSwap := make(map[string]map[int]int)
	for len(toSwap) < choices {
		i := nodeChoiceIndices[s.rand.Intn(numNodeChoiceIndices)]
		j := nodeChoiceIndices[s.rand.Intn(numNodeChoiceIndices)]
		key := fmt.Sprintf("%d_%d", i, j)
		if _, ok := toSwap[key]; !ok {
			toSwap[key] = map[int]int{i: j}
		}
	}
	newTrace := trace.Copy()
	for _, v := range toSwap {
		for i, j := range v {
			first, _ := newTrace.Get(i)
			second, _ := newTrace.Get(j)
			newTrace.Set(i, second.Copy())
			newTrace.Set(j, first.Copy())
		}
	}
	return newTrace, true
}

// SwapMaxMessagesMutator is a Mutator that swaps the MaxMessages field of node choices in a trace.
// It randomly selects pairs of node choices and swaps their MaxMessages values.
// It requires a specified number of swaps to be performed.
type SwapMaxMessagesMutator struct {
	NumSwaps int
	r        *rand.Rand
}

var _ Mutator = &SwapMaxMessagesMutator{}

func NewSwapMaxMessagesMutator(swaps int) *SwapMaxMessagesMutator {
	return &SwapMaxMessagesMutator{
		NumSwaps: swaps,
		r:        rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (s *SwapMaxMessagesMutator) Mutate(trace *List[*Choice], eventTrace *List[*Event]) (*List[*Choice], bool) {
	swaps := make(map[int]int)

	nodeChoices := make([]int, 0)
	for i, ch := range trace.Iter() {
		if ch.Type == "Node" {
			nodeChoices = append(nodeChoices, i)
		}
	}

	if len(nodeChoices) < s.NumSwaps {
		return nil, false
	}

	for len(swaps) < s.NumSwaps {
		sp := sample(nodeChoices, 2, s.r)
		swaps[sp[0]] = sp[1]
	}

	newTrace := trace.Copy()
	for i, j := range swaps {
		iCh, _ := newTrace.Get(i)
		jCh, _ := newTrace.Get(j)

		iChNew := iCh.Copy()
		iChNew.MaxMessages = jCh.MaxMessages
		jChNew := jCh.Copy()
		jChNew.MaxMessages = iCh.MaxMessages

		newTrace.Set(i, iChNew)
		newTrace.Set(j, jChNew)
	}
	return newTrace, true
}

type combinedMutator struct {
	mutators []Mutator
}

var _ Mutator = &combinedMutator{}

func (c *combinedMutator) Mutate(trace *List[*Choice], eventTrace *List[*Event]) (*List[*Choice], bool) {
	curTrace := trace.Copy()
	for _, m := range c.mutators {
		nextTrace, ok := m.Mutate(curTrace, eventTrace)
		if !ok {
			return nil, false
		}
		curTrace = nextTrace
	}
	return curTrace, true
}

// CombineMutators combines multiple Mutators into a single Mutator.
// It applies each Mutator in sequence to the trace, returning the final mutated trace.
func CombineMutators(mutators ...Mutator) Mutator {
	return &combinedMutator{
		mutators: mutators,
	}
}

func sample(l []int, size int, r *rand.Rand) []int {
	if size >= len(l) {
		return l
	}
	indexes := make(map[int]bool)
	for len(indexes) < size {
		i := r.Intn(len(l))
		indexes[i] = true
	}
	samples := make([]int, size)
	i := 0
	for k := range indexes {
		samples[i] = l[k]
		i++
	}
	return samples
}

func intRange(start, end int) []int {
	res := make([]int, end-start)
	for i := start; i < end; i++ {
		res[i-start] = i
	}
	return res
}
