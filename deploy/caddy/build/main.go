// Caddy with its standard modules only, compiled from source (see ../Dockerfile).
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func main() { caddycmd.Main() }
