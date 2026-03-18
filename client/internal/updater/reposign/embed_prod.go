//go:build !devartifactsign

package reposign

import "embed"

//go:embed certs
var embeddedCerts embed.FS

const embeddedCertsDir = "certs"
