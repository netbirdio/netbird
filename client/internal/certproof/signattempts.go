package certproof

import "errors"

// signAttempts tracks the identities tried to sign with, for a certificate that can match
// more than one of them.
type signAttempts struct {
	errs []error
}

// try runs sign and reports its signature and whether it succeeded. A failure is kept.
func (a *signAttempts) try(sign func() ([]byte, error)) ([]byte, bool) {
	signature, err := sign()
	if err != nil {
		a.errs = append(a.errs, err)
		return nil, false
	}
	return signature, true
}

// err joins the failures of the attempts, nil when there were none.
func (a *signAttempts) err() error {
	return errors.Join(a.errs...)
}
