package llm

import "strings"

// promptTurn is one role-tagged piece of a request's conversation, as
// ExtractPrompt renders it: "role: text", or the bare text when the
// request names no role.
type promptTurn struct {
	role string
	text string
}

// isInstructionRole reports whether role carries the agent's standing
// instructions rather than a conversation turn: the system prompt, and
// OpenAI's developer messages that replace it on newer models.
func isInstructionRole(role string) bool {
	return role == "system" || role == "developer"
}

// joinPromptTurns renders turns one per line, the conversation first and
// the instructions after it, each group in request order. The captured
// prompt is cut from the end, and coding agents send system prompts of
// tens of kilobytes, so instructions go last for the cut to drop first.
func joinPromptTurns(turns []promptTurn) string {
	var b strings.Builder
	write := func(t promptTurn) {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		if t.role != "" {
			b.WriteString(t.role)
			b.WriteString(": ")
		}
		b.WriteString(t.text)
	}
	for _, t := range turns {
		if !isInstructionRole(t.role) {
			write(t)
		}
	}
	for _, t := range turns {
		if isInstructionRole(t.role) {
			write(t)
		}
	}
	return b.String()
}
