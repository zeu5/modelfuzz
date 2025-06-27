# ModelFuzz

A generic distributed systems fuzzer to test an implementation using the TLA+ model

To use the fuzzer on a distributed system environment,

First, Implement a concrete `Cluster` implementing the following interface

```go
type Cluster interface {
    Reset()
    Stop(fCtx *FuzzContext, nodes uint64) error
    Start(fCtx *FuzzContext, nodes uint64) error
    ReceiveMessage(fCtx *FuzzContext, message Message) error
    ClientRequest(fCtx *FuzzContext, reqNum string) error
    Tick(fCtx *FuzzContext) []Message
}
```

Then, Create a `Fuzzer` and pass the `ClusterConstructor` as follows

```go
fConfig := &FuzzerConfig{
    Iterations : 10,
    Steps: 10,
    Mutator: RandomMutator()
    Guider: NewTLCStateGuider("tlc_server", "results", true),
    NumNodes: 3,
    ClusterConstructor: clusterCons,

    ...
}
f := NewFuzzer(fConfig)
```

Finally, run the fuzzer,

```go
coverage := f.Run()
fmt.Printf("Total states covered : %d\n", coverage.UniqueStates)

...
```
