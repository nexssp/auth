package nexssflow

import (
	"context"
	"io/fs"
	"testing"

	"github.com/nexssp/flow/compiler"
	"github.com/nexssp/flow/native"
	"github.com/nexssp/flow/runner"
	"github.com/nexssp/transport/thttp"
	thttpflow "github.com/nexssp/transport/thttp/nexssflow"
)

func TestBundleExportsAuthRouteSourceModule(t *testing.T) {
	bundle := Bundle(nil)
	if err := compiler.ValidateBundle(bundle); err != nil {
		t.Fatalf("auth bundle validation: %v", err)
	}
	if len(bundle.ExportedModules) != 1 || bundle.ExportedModules[0] != AuthRoutesModule {
		t.Fatalf("exported modules = %v, want [%s]", bundle.ExportedModules, AuthRoutesModule)
	}
	if _, err := fs.ReadFile(bundle.SourceModules, AuthRoutesModule); err != nil {
		t.Fatalf("read exported auth route module: %v", err)
	}

	bundle.Alias = "auth"
	config, err := runner.BuildConfig(append(native.Bundles(), bundle, thttpflow.Bundle(nil)))
	if err != nil {
		t.Fatalf("build Flow config: %v", err)
	}
	compiled, err := runner.Compile(context.Background(), config,
		"@include auth:nflows/auth.nflow AS auth_api\nnoop",
		"auth_route_import_test.nflow",
	)
	if err != nil {
		t.Fatalf("compile imported auth routes: %v", err)
	}

	wantRoutes := map[string]thttp.HTTPRoute{
		"auth_current_session": {Method: "GET", Path: "/auth/session"},
		"auth_register":        {Method: "POST", Path: "/auth/register"},
		"auth_login":           {Method: "POST", Path: "/auth/login"},
		"auth_logout":          {Method: "POST", Path: "/auth/logout"},
		"auth_password_forgot": {Method: "POST", Path: "/auth/password/forgot"},
		"auth_password_reset":  {Method: "POST", Path: "/auth/password/reset"},
		"auth_email_verify":    {Method: "POST", Path: "/auth/email/verify"},
		"auth_email_resend":    {Method: "POST", Path: "/auth/email/resend"},
	}
	for name, want := range wantRoutes {
		t.Run(name, func(t *testing.T) {
			act, ok := compiled.Resolver.Action("auth_api.pipeline." + name)
			if !ok {
				t.Fatalf("included route pipeline %q was not registered", name)
			}
			bindings := act.GetBindings()
			if len(bindings) != 1 {
				t.Fatalf("route bindings = %v, want exactly one", bindings)
			}
			got, ok := bindings[0].(thttp.HTTPRoute)
			if !ok {
				t.Fatalf("route binding type = %T, want thttp.HTTPRoute", bindings[0])
			}
			if got != want {
				t.Fatalf("route = %#v, want %#v", got, want)
			}
		})
	}
	if _, ok := compiled.Resolver.Action("auth_api.pipeline.auth_listen"); ok {
		t.Fatal("auth module unexpectedly registered its own listener")
	}
}
