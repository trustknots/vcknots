package wallet

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/trustknots/vcknots/wallet/profile"
)

// Every error an option causes names it through profile.Refused, and a caller
// branches on that name (profile.OptionError.Option). A misspelt name would
// silently name no option, so every literal the library passes is checked
// against the names Options.String spells.
func TestRefusedNamesAnOption(t *testing.T) {
	known := map[string]bool{}
	// HAIPOptions turns every HAIP option on, so its String names each of
	// them; the checks HAIP leaves to the Wallet are added.
	every := profile.HAIPOptions()
	every.RequireStatusListSignerBinding = true
	for _, element := range strings.Split(every.String(), ";") {
		name, _, _ := strings.Cut(element, "=")
		known[name] = true
	}
	refused := regexp.MustCompile(`profile\.Refused\("([^"]*)"\)`)
	seen := 0
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == "examples" || entry.Name() == "testdata") {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, match := range refused.FindAllStringSubmatch(string(source), -1) {
			seen++
			if !known[match[1]] {
				t.Errorf("%s: profile.Refused(%q) names no option", path, match[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen == 0 {
		t.Fatal("found no profile.Refused call")
	}
}
