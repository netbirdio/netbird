package status

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/proto"
)

type SystemEventOutput struct {
	ID          string            `json:"id" yaml:"id"`
	Severity    string            `json:"severity" yaml:"severity"`
	Category    string            `json:"category" yaml:"category"`
	Message     string            `json:"message" yaml:"message"`
	UserMessage string            `json:"userMessage" yaml:"userMessage"`
	Timestamp   time.Time         `json:"timestamp" yaml:"timestamp"`
	Metadata    map[string]string `json:"metadata" yaml:"metadata"`
}

func mapEvents(protoEvents []*proto.SystemEvent) []SystemEventOutput {
	events := make([]SystemEventOutput, len(protoEvents))
	for i, event := range protoEvents {
		events[i] = SystemEventOutput{
			ID:          event.GetId(),
			Severity:    event.GetSeverity().String(),
			Category:    event.GetCategory().String(),
			Message:     event.GetMessage(),
			UserMessage: event.GetUserMessage(),
			Timestamp:   event.GetTimestamp().AsTime(),
			Metadata:    event.GetMetadata(),
		}
	}
	return events
}

func parseEvents(events []SystemEventOutput) string {
	if len(events) == 0 {
		return " No events recorded"
	}

	var eventsString strings.Builder
	for _, event := range events {
		timeStr := timeAgo(event.Timestamp)

		metadataStr := ""
		if len(event.Metadata) > 0 {
			pairs := make([]string, 0, len(event.Metadata))
			for k, v := range event.Metadata {
				pairs = append(pairs, fmt.Sprintf("%s: %s", k, v))
			}
			sort.Strings(pairs)
			metadataStr = fmt.Sprintf("\n    Metadata: %s", strings.Join(pairs, ", "))
		}

		eventsString.WriteString(fmt.Sprintf("\n  [%s] %s (%s)"+
			"\n    Message: %s"+
			"\n    Time: %s%s",
			event.Severity,
			event.Category,
			event.ID,
			event.Message,
			timeStr,
			metadataStr,
		))
	}
	return eventsString.String()
}
