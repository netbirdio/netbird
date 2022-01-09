package server

type IDPManager interface {
	UpdateUserMetadata(userId string, metadata Metadata) error
}

type Metadata map[string]string
