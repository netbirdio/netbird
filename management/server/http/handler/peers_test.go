package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wiretrustee/wiretrustee/management/server/mock_server"
)

func TestHandlePeer(t *testing.T) {
	var tt = []struct {
		request *http.Request
		want    []byte
	}{
		{httptest.NewRequest(http.MethodGet, "", nil), []byte(`{"Name": "Bob"}`)},
		{httptest.NewRequest(http.MethodGet, "", nil), []byte(`{"Name": "Bob"}`)},
		{httptest.NewRequest(http.MethodDelete, "", nil), []byte(`{"Name": "Bob"}`)},
		{httptest.NewRequest(http.MethodPut, "", nil), []byte(`{"Name": "Bob"}`)},
	}

	//
	rr := httptest.NewRecorder()
	p := &Peers{
		accountManager: &mock_server.MockAccountManager{},
	}

	for _, tv := range tt {
		p.HandlePeer(rr, tv.request)

		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusOK)
		}

		if bytes.Compare([]byte(rr.Body.String()), tv.want) != 0 {
			t.Errorf("handler returned unexpected body: got %v want %v",
				rr.Body.String(), tv.want)
		}
	}
}
