// Package runner manages concurrent module execution.
package runner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/sahin-security/sahin/core/engine"
)

type ModuleFunc func(ctx context.Context, sc *engine.ScanContext) error

var (
	registryMu sync.RWMutex
	Registry   = map[string]ModuleFunc{}
)

func Register(name string, fn ModuleFunc) {
	registryMu.Lock()
	defer registryMu.Unlock()
	Registry[name] = fn
}

type Runner struct {
	sc *engine.ScanContext
}

func New(sc *engine.ScanContext) *Runner {
	return &Runner{sc: sc}
}

// RunModule tek bir modülü ismiyle çalıştırır.
func (r *Runner) RunModule(ctx context.Context, name string) error {
	registryMu.RLock()
	fn, ok := Registry[name]
	registryMu.RUnlock()
	if !ok {
		return fmt.Errorf("modül bulunamadı: '%s' — mevcut: %v", name, registeredNames())
	}
	return fn(ctx, r.sc)
}

// RunWorkflow bir workflow'u çalıştırır.
// depends_on destekler: bağımlı modüller tamamlanmadan başlamaz.
// parallel: true olan modüller eş zamanlı çalışır.
func (r *Runner) RunWorkflow(ctx context.Context, wf *engine.Workflow) error {
	color.Cyan("\n[*] Workflow : %s", wf.Name)
	color.Cyan("[*] Açıklama: %s", wf.Description)
	color.Cyan("[*] Hedef   : %s\n", r.sc.Target)

	// Tamamlanan modülleri takip et
	completed := map[string]bool{}
	var mu sync.Mutex

	// Seri ve paralel grupları ayır
	for i := 0; i < len(wf.Modules); i++ {
		ref := wf.Modules[i]

		if ref.Disabled {
			color.Yellow("  [-] Atlandı (disabled): %s", ref.Name)
			continue
		}

		// Koşul kontrolü (basit: "stealth == false" gibi)
		if ref.Condition != "" && !evalCondition(ref.Condition, r.sc) {
			color.Yellow("  [-] Atlandı (koşul): %s — %s", ref.Name, ref.Condition)
			continue
		}

		// Bağımlılıkları bekle
		if len(ref.DependsOn) > 0 {
			if err := r.waitDependencies(ctx, ref.DependsOn, completed, &mu); err != nil {
				return err
			}
		}

		// Paralel grup bul: aynı noktada parallel:true olan modülleri grupla
		if ref.Parallel {
			parallelGroup := []engine.ModuleRef{ref}
			j := i + 1
			for j < len(wf.Modules) && wf.Modules[j].Parallel {
				parallelGroup = append(parallelGroup, wf.Modules[j])
				j++
			}
			i = j - 1

			if err := r.runParallel(ctx, parallelGroup, completed, &mu); err != nil {
				return err
			}
			continue
		}

		// Seri çalıştır
		if err := r.runOne(ctx, ref, completed, &mu); err != nil {
			color.Red("  [!] %s modülü hata verdi: %v", ref.Name, err)
			// Hata olsa bile devam et (workflow kırılmasın)
		}
	}

	return nil
}

// runOne tek bir modülü çalıştırır, sonucu completed map'e ekler.
func (r *Runner) runOne(ctx context.Context, ref engine.ModuleRef, completed map[string]bool, mu *sync.Mutex) error {
	registryMu.RLock()
	fn, ok := Registry[ref.Name]
	registryMu.RUnlock()

	if !ok {
		color.Red("  [✗] Modül bulunamadı: %s", ref.Name)
		mu.Lock()
		completed[ref.Name] = true
		mu.Unlock()
		return nil
	}

	// Modüle özel parametreleri sc.Params'a ekle
	for k, v := range ref.Params {
		r.sc.Params[k] = v
	}

	color.Green("\n  [▶] Başlıyor: %s", ref.Name)
	start := time.Now()

	err := fn(ctx, r.sc)
	elapsed := time.Since(start).Round(time.Second)

	if err != nil {
		color.Red("  [✗] %s hata (%v): %v", ref.Name, elapsed, err)
	} else {
		color.Green("  [✓] %s tamamlandı (%v)", ref.Name, elapsed)
	}

	mu.Lock()
	completed[ref.Name] = true
	mu.Unlock()

	return err
}

// runParallel birden fazla modülü eş zamanlı çalıştırır.
func (r *Runner) runParallel(ctx context.Context, refs []engine.ModuleRef, completed map[string]bool, mu *sync.Mutex) error {
	color.Cyan("  [||] Paralel çalıştırılıyor: %v", moduleNames(refs))

	var wg sync.WaitGroup
	errs := make(chan error, len(refs))

	for _, ref := range refs {
		wg.Add(1)
		go func(ref engine.ModuleRef) {
			defer wg.Done()
			if err := r.runOne(ctx, ref, completed, mu); err != nil {
				errs <- err
			}
		}(ref)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// waitDependencies bağımlı modüllerin tamamlanmasını bekler.
func (r *Runner) waitDependencies(ctx context.Context, deps []string, completed map[string]bool, mu *sync.Mutex) error {
	color.White("  [⏳] Bağımlılıklar bekleniyor: %v", deps)

	deadline := time.Now().Add(30 * time.Minute)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		mu.Lock()
		allDone := true
		for _, dep := range deps {
			if !completed[dep] {
				allDone = false
				break
			}
		}
		mu.Unlock()

		if allDone {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("bağımlılık zaman aşımı: %v", deps)
}

// evalCondition basit koşul değerlendirici.
func evalCondition(condition string, sc *engine.ScanContext) bool {
	condition = strings.TrimSpace(condition)
	switch condition {
	case "stealth == false":
		return !sc.Stealth
	case "stealth == true":
		return sc.Stealth
	}
	// target TLD koşulları
	if strings.HasPrefix(condition, "target.endsWith(") {
		suffix := strings.TrimSuffix(strings.TrimPrefix(condition, "target.endsWith('"), "')")
		return strings.HasSuffix(sc.Target, suffix)
	}
	return true // bilinmeyen koşul → çalıştır
}

func registeredNames() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(Registry))
	for name := range Registry {
		names = append(names, name)
	}
	return names
}

func moduleNames(refs []engine.ModuleRef) []string {
	names := make([]string, len(refs))
	for i, r := range refs {
		names[i] = r.Name
	}
	return names
}
