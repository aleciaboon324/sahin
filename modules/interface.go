package modules

import (
	"context"
	"github.com/sahin-security/sahin/core/engine"
)

type Module interface {
	Name() string
	Description() string
	Category() string
	Requires() []string
	Run(ctx context.Context, sc *engine.ScanContext) error
}
