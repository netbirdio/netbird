package auth

import (
	"crypto/subtle"
	"net/http"
)

const (
	userId = "pin-user"
	formId = "pin"
)

type Pin struct {
	pin string
}

func NewPin(pin string) Pin {
	return Pin{
		pin: pin,
	}
}

func (Pin) Type() Method {
	return MethodPIN
}

// Authenticate attempts to authenticate the request using a form
// value passed in the request.
// If authentication fails, the required HTTP form ID is returned
// so that it can be injected into a request from the UI so that
// authentication may be successful.
func (p Pin) Authenticate(r *http.Request) (string, bool, any) {
	pin := r.FormValue(formId)

	// Compare the passed pin with the expected pin.
	if subtle.ConstantTimeCompare([]byte(pin), []byte(p.pin)) == 1 {
		return userId, false, nil
	}

	return "", false, formId
}

func (p Pin) Middleware(next http.Handler) http.Handler {
	return next
}
