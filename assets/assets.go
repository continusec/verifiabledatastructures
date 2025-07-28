package assets

import (
	"embed"
	_ "embed"
	"fmt"
	"strings"
)

//go:embed static/*
var static embed.FS

func Asset(name string) (_ []byte, retErr error) {
	localName, ok := strings.CutPrefix(name, "assets/")
	if !ok {
		return nil, fmt.Errorf("bad path for asset: %s", name)
	}
	return static.ReadFile(localName)
}
