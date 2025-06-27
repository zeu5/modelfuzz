package modelfuzz

type Cluster interface {
	Reset()
	Stop(fCtx *FuzzContext, nodes uint64) error
	Start(fCtx *FuzzContext, nodes uint64) error
	ReceiveMessage(fCtx *FuzzContext, message Message) error
	ClientRequest(fCtx *FuzzContext, reqNum string) error
	Tick(fCtx *FuzzContext) []Message
}

type ClusterConstructor interface {
	NewCluster(nodes []uint64) Cluster
}

type Message interface {
	From() uint64
	To() uint64
	Type() string
	Params() map[string]interface{}
}
