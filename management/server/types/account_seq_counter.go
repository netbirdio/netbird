package types

// AccountSeqEntity identifies the kind of component that uses a per-account sequence.
type AccountSeqEntity string

const (
	AccountSeqEntityPolicy          AccountSeqEntity = "policy"
	AccountSeqEntityGroup           AccountSeqEntity = "group"
	AccountSeqEntityRoute           AccountSeqEntity = "route"
	AccountSeqEntityNetworkResource AccountSeqEntity = "network_resource"
	AccountSeqEntityNetworkRouter   AccountSeqEntity = "network_router"
	AccountSeqEntityNameserverGroup AccountSeqEntity = "nameserver_group"
	AccountSeqEntityNetwork         AccountSeqEntity = "network"
	AccountSeqEntityPostureCheck    AccountSeqEntity = "posture_check"
)

// AccountSeqCounter tracks the next per-account integer id for a given component
// kind. Reads/writes go through the store inside the same transaction as the
// component insert so two concurrent inserts cannot collide on the same id.
type AccountSeqCounter struct {
	AccountID string `gorm:"primaryKey;size:255"`
	Entity    string `gorm:"primaryKey;size:32"`
	NextID    uint32 `gorm:"not null;default:1"`
}

// TableName overrides the GORM-derived table name.
func (AccountSeqCounter) TableName() string {
	return "account_seq_counters"
}
