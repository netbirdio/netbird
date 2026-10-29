package web

import (
	"embed"
	"io/fs"
)

//go:embed static/* templates/* themes/* robots.txt
var files embed.FS

// FS returns the embedded web assets filesystem.
func FS() fs.FS {
	return files
}
