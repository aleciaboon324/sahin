package engine

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Workflow struct {
	Kind        string      `yaml:"kind"`
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Author      string      `yaml:"author"`
	Version     string      `yaml:"version"`
	Params      []Param     `yaml:"params"`
	Modules     []ModuleRef `yaml:"modules"`
}

type Param struct {
	Name    string `yaml:"name"`
	Default string `yaml:"default"`
	Help    string `yaml:"help"`
}

type ModuleRef struct {
	Name      string            `yaml:"name"`
	DependsOn []string          `yaml:"depends_on"`
	Condition string            `yaml:"condition"`
	Params    map[string]string `yaml:"params"`
	Timeout   string            `yaml:"timeout"`
	Parallel  bool              `yaml:"parallel"`
	Disabled  bool              `yaml:"disabled"`
}

type ScanContext struct {
	Target    string
	Workspace string
	OutputDir string // ~/.sahin/workspaces
	Threads   int
	Stealth   bool
	Verbose   bool
	Params    map[string]string
	StartedAt time.Time
	Results   chan Result
}

type Result struct {
	Module   string
	Step     string
	Output   string
	Error    error
	Duration time.Duration
	Severity string
}

func NewScanContext(target, workspace, outputDir string) *ScanContext {
	return &ScanContext{
		Target:    target,
		Workspace: workspace,
		OutputDir: outputDir,
		Threads:   5,
		Params:    make(map[string]string),
		StartedAt: time.Now(),
		Results:   make(chan Result, 256),
	}
}

func ParseWorkflow(path string) (*Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("workflow okunamadı: %w", err)
	}
	var wf Workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("parse hatası: %w", err)
	}
	if wf.Name == "" {
		return nil, fmt.Errorf("workflow adı boş")
	}
	return &wf, nil
}
