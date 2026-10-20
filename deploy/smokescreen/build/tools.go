//go:build tools

// Pins smokescreen in go.mod so the build resolves only from go.sum (see ../Dockerfile).
package tools

import _ "github.com/stripe/smokescreen"
