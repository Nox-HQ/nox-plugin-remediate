package main

import (
	"testing"

	"github.com/nox-hq/nox/sdk"
)

func TestConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunConformance(t, srv)
}
