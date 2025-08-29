package errors

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-multierror"
)

func formatError(es []error) string {
	if len(es) == 1 {
		return fmt.Sprintf("1 error occurred:\n\t* %s", es[0])
	}

	points := make([]string, len(es))
	for i, err := range es {
		points[i] = fmt.Sprintf("* %s", err)
	}

	return fmt.Sprintf(
		"%d errors occurred:\n\t%s",
		len(es), strings.Join(points, "\n\t"))
}

func FormatErrorOrNil(err *multierror.Error) error {
	if err != nil {
		err.ErrorFormat = formatError
	}
	return err.ErrorOrNil()
}
