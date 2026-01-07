//go:build devartifactsign

package reposign

import "embed"

//go:embed certsdev
var embeddedCerts embed.FS

const embeddedCertsDir = "certsdev"
