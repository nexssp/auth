package roles_test

import (
	"os"
	"sync/atomic"
	"testing"

	"github.com/nexssp/auth/roles"
)

func TestRoles_RunSingle(t *testing.T) {
	// Not t.Parallel() because it modifies os.Environ
	os.Setenv("NEXSS_ROLE", "api")
	defer os.Unsetenv("NEXSS_ROLE")

	var apiCount, workerCount atomic.Int32

	r := roles.New().
		Add("api", func() { apiCount.Add(1) }).
		Add("worker", func() { workerCount.Add(1) })

	r.Run("NEXSS_ROLE")

	if apiCount.Load() != 1 {
		t.Errorf("expected API role to run once, got %d", apiCount.Load())
	}
	if workerCount.Load() != 0 {
		t.Errorf("expected Worker role to not run, got %d", workerCount.Load())
	}
}

func TestRoles_RunAlias(t *testing.T) {
	os.Setenv("NEXSS_ROLE", "monolith")
	defer os.Unsetenv("NEXSS_ROLE")

	var apiCount, workerCount, adminCount atomic.Int32

	r := roles.New().
		Add("api", func() { apiCount.Add(1) }).
		Add("worker", func() { workerCount.Add(1) }).
		Add("admin", func() { adminCount.Add(1) }).
		AddAlias("monolith", "api", "worker")

	r.Run("NEXSS_ROLE")

	if apiCount.Load() != 1 || workerCount.Load() != 1 {
		t.Error("expected API and Worker roles to run via alias")
	}
	if adminCount.Load() != 0 {
		t.Error("expected Admin role to NOT run")
	}
}
