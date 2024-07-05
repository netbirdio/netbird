package auth

type Validator interface {
	Validate(any) error
}
