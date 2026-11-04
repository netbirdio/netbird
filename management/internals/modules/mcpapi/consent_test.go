package mcpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

// renderConsentPage renders the consent page and returns its parsed document.
func renderConsentPage(t *testing.T, page consentPage) *html.Node {
	t.Helper()
	rec := httptest.NewRecorder()
	renderConsent(rec, page)
	require.Equal(t, http.StatusOK, rec.Code)
	doc, err := html.Parse(strings.NewReader(rec.Body.String()))
	require.NoError(t, err)
	return doc
}

// checkboxes returns the page's checkbox inputs in document order.
func checkboxes(n *html.Node) []*html.Node {
	var found []*html.Node
	for d := range n.Descendants() {
		if d.Type == html.ElementNode && d.Data == "input" && attr(d, "type") == "checkbox" {
			found = append(found, d)
		}
	}
	return found
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func hasAttr(n *html.Node, key string) bool {
	for _, a := range n.Attr {
		if a.Key == key {
			return true
		}
	}
	return false
}

func TestConsentPageWriteCheckbox(t *testing.T) {
	page := consentPage{ClientName: "Claude Code", RedirectHost: "localhost:33418", Loopback: true, Request: "sealed", Action: "/authorize"}

	t.Run("write is offered unticked", func(t *testing.T) {
		page := page
		page.WriteRequested = true
		boxes := checkboxes(renderConsentPage(t, page))
		require.Len(t, boxes, 2, "a read box and a write box")

		read, write := boxes[0], boxes[1]
		assert.True(t, hasAttr(read, "checked"), "read is always granted and shown ticked")
		assert.True(t, hasAttr(read, "disabled"), "read cannot be unticked")
		assert.Empty(t, attr(read, "name"), "the read box submits nothing")

		assert.Equal(t, "write", attr(write, "name"))
		assert.Equal(t, "on", attr(write, "value"), "the value decide() checks for")
		assert.False(t, hasAttr(write, "checked"), "write must be opted into, never pre-ticked")
		assert.False(t, hasAttr(write, "disabled"), "write can be ticked")
	})

	t.Run("write is absent when the client did not ask for it", func(t *testing.T) {
		boxes := checkboxes(renderConsentPage(t, page))
		require.Len(t, boxes, 1, "only the read box")
		assert.NotEqual(t, "write", attr(boxes[0], "name"), "no write box is offered")
	})
}

func TestConsentPageClientName(t *testing.T) {
	render := func(name string) string {
		rec := httptest.NewRecorder()
		renderConsent(rec, consentPage{ClientName: name, RedirectHost: "localhost:33418", Request: "sealed", Action: "/authorize"})
		return rec.Body.String()
	}

	body := render(`<b>NetBird</b>`)
	assert.Contains(t, body, `<title>Authorize “&lt;b&gt;NetBird&lt;/b&gt;” - NetBird</title>`, "the title quotes and escapes the name")
	assert.Contains(t, body, `<span class="nb-client">“&lt;b&gt;NetBird&lt;/b&gt;”</span>`, "the heading quotes and escapes the name")

	body = render("")
	assert.Contains(t, body, "Allow an unnamed application to access NetBird?", "a client without a name is not quoted as if it had one")
	assert.NotContains(t, body, "“”", "no empty quotes")
}
