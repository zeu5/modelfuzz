package modelfuzz

// Cluster interface defines the methods required for a cluster in a distributed system.
type Cluster interface {
	// Reset resets the state of the cluster.
	// It will be called at the start of each fuzzing iteration.
	// This allows the cluster to be in a clean state for each fuzzing run.
	Reset()
	// Stop instructs the cluster to stop a particular node and report any events to the
	// FuzzContext. The node parameter indicates which node should be stopped.
	Stop(fCtx *FuzzContext, node uint64) error
	// Start instructs the cluster to start a particular node and report any events to the
	// FuzzContext. The node parameter indicates which node should be started.
	Start(fCtx *FuzzContext, node uint64) error
	// ReceiveMessage processes a message received by the cluster.
	// The message parameter is the Message instance that needs to be processed.
	ReceiveMessage(fCtx *FuzzContext, message Message) error
	// ClientRequest simulates a client request to the cluster.
	// The reqNum parameter is a string that identifies the request.
	ClientRequest(fCtx *FuzzContext, reqNum string) error
	// Tick is called to advance the cluster's state by one tick.
	// It returns a slice of Message instances that represent messages sent by the cluster
	// during this tick.
	Tick(fCtx *FuzzContext) []Message
}

// ClusterConstructor interface defines a method to create a new cluster with a given set of nodes.
// The nodes are represented as a slice of uint64 identifiers.
type ClusterConstructor interface {
	// NewCluster creates a new Cluster instance with the specified nodes.
	NewCluster(nodes []uint64) Cluster
}

// Message interface defines the structure of a message in the distributed system.
type Message interface {
	// From returns the identifier of the node that sent the message.
	From() uint64
	// To returns the identifier of the node that is the intended recipient of the message.
	To() uint64
	// Type returns the type of the message as a string.
	Type() string
	// Params returns a map of parameters associated with the message.
	Params() map[string]interface{}
}
