package web

import "embed"

//go:embed templates/* static/*
var EmbeddedFS embed.FS
