package modelfuzz

import "encoding/json"

type Choice struct {
	Type        string
	Node        uint64
	From        uint64
	To          uint64
	Op          string
	Step        int
	MaxMessages int
	Request     string
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

type State struct {
	Repr string
	Key  int64
}

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

func NewTrace() *Trace {
	return &Trace{
		Choices: make([]*Choice, 0),
	}
}

func (t *Trace) Add(ch *Choice) {
	t.Choices = append(t.Choices, ch.Copy())
}

type Event struct {
	Name   string
	Node   uint64 `json:"-"`
	Params map[string]interface{}
	Reset  bool
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

type EventTrace struct {
	Events []Event
}

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

func (et *EventTrace) Add(e Event) {
	et.Events = append(et.Events, e.Copy())
}

type Queue[T any] struct {
	q []T
}

func NewQueue[T any]() *Queue[T] {
	return &Queue[T]{
		q: make([]T, 0),
	}
}

func (q *Queue[T]) Push(elem T) {
	q.q = append(q.q, elem)
}

func (q *Queue[T]) PushAll(elems ...T) {
	q.q = append(q.q, elems...)
}

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

func (q *Queue[T]) Size() int {
	return len(q.q)
}

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
