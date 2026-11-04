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
	assert.Contains(t, body, `<title>Authorize &#x2068;“&lt;b&gt;NetBird&lt;/b&gt;”&#x2069; - NetBird</title>`, "the title quotes, escapes and isolates the name")
	assert.Contains(t, body, `<span class="nb-client">“<bdi>&lt;b&gt;NetBird&lt;/b&gt;</bdi>”</span>`, "the heading quotes and escapes the name")

	body = render("")
	assert.Contains(t, body, "Allow an unnamed application to access NetBird?", "a client without a name is not quoted as if it had one")
	assert.NotContains(t, body, "“”", "no empty quotes")
}

func TestConsentPageNameIsIsolated(t *testing.T) {
	rec := httptest.NewRecorder()
	renderConsent(rec, consentPage{ClientName: "Evil", RedirectHost: "localhost:33418", Request: "sealed", Action: "/authorize"})
	// bdi keeps right-to-left text in the name from reordering the words around it.
	assert.Contains(t, rec.Body.String(), `<span class="nb-client">“<bdi>Evil</bdi>”</span>`, "the name is isolated inside the quotes")
}

func TestDisplayName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "Claude Code", "Claude Code"},
		{"surrounding space", "  Claude Code\n", "Claude Code"},
		{"non-latin text is kept", "Café 日本語 Клиент", "Café 日本語 Клиент"},
		{"bidi override", "Evil\u202eabc def", "Evilabc def"},
		{"bidi isolates and marks", "\u2066a\u2069\u200eb\u200f\u061c", "ab"},
		{"zero width only", "\u200b", ""},
		{"zero width around space", "\ufeff \u200b \u2060", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, displayName(tt.in), "format characters are dropped and space trimmed")
		})
	}
}

// submitButtons returns the form's submit buttons in document order.
func submitButtons(n *html.Node) []*html.Node {
	var found []*html.Node
	for d := range n.Descendants() {
		if d.Type == html.ElementNode && d.Data == "button" && attr(d, "type") == "submit" {
			found = append(found, d)
		}
	}
	return found
}

func TestConsentPageEnterDenies(t *testing.T) {
	page := consentPage{ClientName: "Claude Code", RedirectHost: "localhost:33418", WriteRequested: true, Request: "sealed", Action: "/authorize"}
	buttons := submitButtons(renderConsentPage(t, page))
	require.NotEmpty(t, buttons, "the form has submit buttons")

	// Enter in a form control clicks the first submit button, so it must deny.
	first := buttons[0]
	assert.Equal(t, "action", attr(first, "name"), "the default button is a decision")
	assert.Equal(t, "deny", attr(first, "value"), "Enter on the write checkbox must cancel, not approve")

	var approve, deny int
	for _, b := range buttons {
		switch attr(b, "value") {
		case "approve":
			approve++
			assert.Equal(t, "approve", attr(b, "id"), "the arming script finds the approve button by id")
		case "deny":
			deny++
		}
	}
	assert.Equal(t, 1, approve, "one approve button")
	assert.Equal(t, 2, deny, "the visible Cancel and the default deny")
}
