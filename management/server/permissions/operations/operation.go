package operations

type Operation string

const (
	Create Operation = "create"
	Read   Operation = "read"
	Update Operation = "update"
	Delete Operation = "delete"
	Job    Operation = "job"
)
