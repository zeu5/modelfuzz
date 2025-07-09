package modelfuzz

import "encoding/json"

// Choice represents a choice made during the execution of a trace.
type Choice struct {
	// Type is the type of the choice (e.g., "message", "start", "stop").
	Type string
	// Node is the identifier of the node where the choice was made.
	Node uint64
	// From is the identifier of the node that sent the message (if applicable).
	From uint64
	// To is the identifier of the node that received the message (if applicable).
	To uint64
	Op string
	// Step is the step number in the trace where this choice was made.
	Step int
	// MaxMessages is the maximum number of messages that can be processed in this choice.
	// This is used to limit the number of messages processed in a single step.
	MaxMessages int
	// Request is a string representing the request made in this choice.
	Request string
}

func (c *Choice) Copy() *Choice {
	return &Choice{
		Type:        c.Type,
		Node:        c.Node,
		From:        c.From,
		To:          c.To,
		Op:          c.Op,
		Step:        c.Step,
		MaxMessages: c.MaxMessages,
		Request:     c.Request,
	}
}

// State represents a state in the model fuzzing process.
// It contains a string representation of the state and a unique key identifier.
type State struct {
	Repr string
	Key  int64
}

// Trace represents a sequence of choices made during the execution of a model fuzzing process.
// It contains a list of choices that were made.
type Trace struct {
	Choices []*Choice
}

func (t *Trace) Copy() *Trace {
	new := &Trace{
		Choices: make([]*Choice, len(t.Choices)),
	}
	for i, ch := range t.Choices {
		new.Choices[i] = ch.Copy()
	}
	return new
}

// NewTrace creates a new Trace instance with an empty list of choices.
func NewTrace() *Trace {
	return &Trace{
		Choices: make([]*Choice, 0),
	}
}

// Add appends a copy of the given Choice to the Trace's list of choices.
func (t *Trace) Add(ch *Choice) {
	t.Choices = append(t.Choices, ch.Copy())
}

// Event represents an event in the model fuzzing process.
type Event struct {
	// Name is the name of the event (e.g., "start", "stop", "message").
	Name string
	// Node is the identifier of the node where the event occurred.
	Node uint64 `json:"-"`
	// Params is a map of parameters associated with the event.
	Params map[string]interface{}
	// Reset indicates whether this event should reset the state of the system.
	Reset bool
}

func (e Event) Copy() Event {
	new := Event{
		Name:   e.Name,
		Node:   e.Node,
		Params: make(map[string]interface{}),
		Reset:  e.Reset,
	}
	for k, v := range e.Params {
		new.Params[k] = v
	}
	return new
}

// EventTrace represents a trace of events that occurred during the model fuzzing process.
// It contains a list of events that were recorded.
type EventTrace struct {
	Events []Event
}

// NewEventTrace creates a new EventTrace instance with an empty list of events.
// It initializes the Events slice to hold Event instances.
func NewEventTrace() *EventTrace {
	return &EventTrace{
		Events: make([]Event, 0),
	}
}

func (e *EventTrace) Copy() *EventTrace {
	new := &EventTrace{
		Events: make([]Event, len(e.Events)),
	}
	for i, e := range e.Events {
		new.Events[i] = e.Copy()
	}
	return new
}

// Add appends a copy of the given Event to the EventTrace's list of events.
func (et *EventTrace) Add(e Event) {
	et.Events = append(et.Events, e.Copy())
}

// Queue is a generic queue data structure that holds elements of type T.
// It provides methods to push elements to the end of the queue, pop elements from the front,
// check the size of the queue, and reset the queue to an empty state.
// The queue is implemented using a slice to hold the elements.
type Queue[T any] struct {
	q []T
}

// NewQueue creates a new Queue instance with an empty slice to hold elements of type T.
func NewQueue[T any]() *Queue[T] {
	return &Queue[T]{
		q: make([]T, 0),
	}
}

// Push adds an element of type T to the end of the queue.
func (q *Queue[T]) Push(elem T) {
	q.q = append(q.q, elem)
}

// PushAll adds multiple elements of type T to the end of the queue.
func (q *Queue[T]) PushAll(elems ...T) {
	q.q = append(q.q, elems...)
}

// Pop removes and returns the first element of type T from the queue.
func (q *Queue[T]) Pop() (elem T, ok bool) {
	if len(q.q) < 1 {
		ok = false
		return
	}
	elem = q.q[0]
	q.q = q.q[1:]
	ok = true
	return
}

// Size returns the number of elements currently in the queue.
func (q *Queue[T]) Size() int {
	return len(q.q)
}

// Reset clears the queue, removing all elements and resetting it to an empty state.
func (q *Queue[T]) Reset() {
	q.q = make([]T, 0)
}

type List[T any] struct {
	l []T
}

func NewList[T any]() *List[T] {
	return &List[T]{
		l: make([]T, 0),
	}
}

func (l *List[T]) Append(elem T) {
	l.l = append(l.l, elem)
}

func (l *List[T]) Size() int {
	return len(l.l)
}

func (l *List[T]) Get(index int) (elem T, ok bool) {
	if len(l.l) <= index {
		ok = false
		return
	}
	elem = l.l[index]
	ok = true
	return
}

func (l *List[T]) Set(index int, elem T) bool {
	if len(l.l) <= index {
		return false
	}
	l.l[index] = elem
	return true
}

func (l *List[T]) Iter() []T {
	return l.l
}

func (l *List[T]) Reset() {
	l.l = make([]T, 0)
}

func (l *List[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.l)
}

func (l *List[T]) UnmarshalJSON(data []byte) error {
	values := make([]T, 0)
	err := json.Unmarshal(data, &values)
	if err != nil {
		return err
	}
	l.l = values
	return nil
}

func (l *List[T]) Copy() *List[T] {
	newL := NewList[T]()
	for _, e := range l.Iter() {
		newL.Append(e)
	}
	return newL
}
