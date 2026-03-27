package db

import "time"

type Workspace struct {
	ID          uint
	Name        string
	Target      string
	Description string
	StartedAt   time.Time
	FinishedAt  *time.Time
}

type Asset struct {
	ID          uint
	WorkspaceID uint
	Type        string
	Value       string
	Source      string
}

type Finding struct {
	ID          uint
	WorkspaceID uint
	Title       string
	Severity    string
	Module      string
	Evidence    string
	FoundAt     time.Time
}
