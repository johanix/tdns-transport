/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The package's import boundary (cleanup plan step 8, F3): transport knows
 * nothing about the multi-provider application. It may import tdns for the
 * resolver, the CHUNK record and the EDNS0 option, and its own sibling
 * packages; a tdns-mp import, or a new tdns package, fails here and is a
 * decision to record, not a merge conflict to resolve.
 */

package transport

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var allowedJohanixImports = map[string]bool{
	"github.com/johanix/tdns-transport/v2/crypto":  true,
	"github.com/johanix/tdns-transport/v2/distrib": true,
	"github.com/johanix/tdns/v2":                   true, // imr.go: the resolver engine and Globals
	"github.com/johanix/tdns/v2/core":              true, // the CHUNK RR and message constants
	"github.com/johanix/tdns/v2/edns0":             true, // the CHUNK option
}

func TestImportBoundary(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(fset, f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(path, "tdns-mp") {
				t.Errorf("%s imports the application: %s", f, path)
			}
			if strings.HasPrefix(path, "github.com/johanix/") && !allowedJohanixImports[path] {
				t.Errorf("%s imports %s, outside the recorded boundary", f, path)
			}
		}
	}
}
