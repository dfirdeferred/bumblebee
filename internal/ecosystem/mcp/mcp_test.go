package mcp

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestInferPackageFromArgs(t *testing.T) {
	cases := []struct {
		cmd          string
		args         []string
		wantSpec     string
		wantLauncher string
	}{
		{"/usr/bin/npx", []string{"-y", "@modelcontextprotocol/server-github"}, "@modelcontextprotocol/server-github", ""},
		{"uvx", []string{"mcp-server-time"}, "mcp-server-time", "uv"},
		{"python3", []string{"-m", "mypkg.server"}, "python:mypkg.server", ""},
		{"node", []string{"/x/y.js"}, "", ""},
		{"npx", []string{"-y", "@playwright/mcp@latest"}, "@playwright/mcp@latest", ""},
		{"npx", []string{"left-pad@1.2.3"}, "left-pad@1.2.3", ""},
		{"pnpm", []string{"dlx", "@modelcontextprotocol/server-github"}, "@modelcontextprotocol/server-github", ""},
		{"pnpm", []string{"dlx", "-y", "@playwright/mcp@latest"}, "@playwright/mcp@latest", ""},
		{"yarn", []string{"dlx", "@modelcontextprotocol/server-time"}, "@modelcontextprotocol/server-time", ""},
		{"bun", []string{"x", "left-pad@1.2.3"}, "left-pad@1.2.3", ""},
		{"npm", []string{"exec", "--", "@modelcontextprotocol/server-github"}, "@modelcontextprotocol/server-github", ""},
		{"/usr/local/bin/pnpm", []string{"dlx", "mcp-server-time"}, "mcp-server-time", ""},
		{"npm", []string{"exec", "--package=@modelcontextprotocol/server-time", "--", "server-time"}, "@modelcontextprotocol/server-time", ""},
		{"npm", []string{"exec", "--package", "@modelcontextprotocol/server-time", "--", "server-time"}, "@modelcontextprotocol/server-time", ""},
		{"pipx", []string{"run", "mcp-server-time"}, "mcp-server-time", "pipx"},
		{"pipx", []string{"run", "--spec", "bugcrowd-mcp", "bugcrowd"}, "bugcrowd-mcp", "pipx"},
		{"/usr/local/bin/pipx", []string{"run", "some-mcp"}, "some-mcp", "pipx"},
		{"uv", []string{"tool", "run", "mcp-server-time"}, "mcp-server-time", "uv"},
		{"uv", []string{"run", "--directory", "./backend", "mcps/foo.py"}, "", "uv"},
		{"uv", []string{"run", "mcps/foo.py"}, "", "uv"},
		{"uv", []string{"tool", "run", "--from", "bugcrowd-mcp", "bugcrowd"}, "bugcrowd-mcp", "uv"},
		{"uv", []string{"run", "--from", "bugcrowd-mcp", "bugcrowd"}, "bugcrowd-mcp", "uv"},
		{"docker", []string{"run", "-i", "--rm", "ghcr.io/example-org/example-mcp:latest"}, "ghcr.io/example-org/example-mcp:latest", "docker"},
		{"docker", []string{"run", "-e", "FOO=bar", "--name", "x", "mcp/slack"}, "mcp/slack", "docker"},
		{"docker", []string{"run", "--env-file=.env", "ghcr.io/github/github-mcp-server"}, "ghcr.io/github/github-mcp-server", "docker"},
		{"/usr/local/bin/docker", []string{"run", "mcp/slack"}, "mcp/slack", "docker"},
	}
	for _, c := range cases {
		gotSpec, gotLauncher := inferPackageFromArgs(c.cmd, c.args)
		if gotSpec != c.wantSpec || gotLauncher != c.wantLauncher {
			t.Errorf("inferPackageFromArgs(%q,%v) = (%q,%q), want (%q,%q)",
				c.cmd, c.args, gotSpec, gotLauncher, c.wantSpec, c.wantLauncher)
		}
	}
}

func TestSplitSpec(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantSel  string
	}{
		{"@playwright/mcp@latest", "@playwright/mcp", "@latest"},
		{"@playwright/mcp", "@playwright/mcp", ""},
		{"@scope/name@1.2.3", "@scope/name", "@1.2.3"},
		{"left-pad@1.2.3", "left-pad", "@1.2.3"},
		{"mcp-server-time", "mcp-server-time", ""},
		{"python:mypkg.server", "python:mypkg.server", ""},
		{"", "", ""},
		{"pkg@npm:alias@1.0.0", "pkg", "@npm:alias@1.0.0"},
		{"@scope/pkg@npm:other@2.0", "@scope/pkg", "@npm:other@2.0"},
		{"pkg@npm:alias", "pkg", "@npm:alias"},
		{"host@npm:@scope/other@1.0.0", "host", "@npm:@scope/other@1.0.0"},
	}
	for _, c := range cases {
		gotName, gotSel := splitSpec(c.in)
		if gotName != c.wantName || gotSel != c.wantSel {
			t.Errorf("splitSpec(%q) = (%q,%q), want (%q,%q)", c.in, gotName, gotSel, c.wantName, c.wantSel)
		}
	}
}

func TestScanConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_TOKEN":"shouldnotbecaptured"}
    },
    "time": {
      "command": "uvx",
      "args": ["mcp-server-time"]
    }
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 records, got %d", len(out))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if out[0].PackageName != "@modelcontextprotocol/server-github" {
		t.Errorf("inferred spec should set PackageName: %+v", out[0])
	}
	if out[0].ServerName != "github" {
		t.Errorf("ServerName not preserved: %+v", out[0])
	}
	if out[0].RootKind != model.RootKindMCPConfig {
		t.Errorf("RootKind = %q, want %q", out[0].RootKind, model.RootKindMCPConfig)
	}
	if out[0].Version != "" {
		t.Errorf("Version should be empty for MCP records: %q", out[0].Version)
	}
	if out[0].RequestedSpec != "" {
		t.Errorf("RequestedSpec should be empty when no selector: %q", out[0].RequestedSpec)
	}
	if out[1].PackageName != "mcp-server-time" {
		t.Errorf("inferred spec should set PackageName: %+v", out[1])
	}
	if out[1].ServerName != "time" {
		t.Errorf("ServerName not preserved: %+v", out[1])
	}
	if out[0].Confidence != "low" {
		t.Errorf("confidence: %q", out[0].Confidence)
	}
}

func TestScanConfig_FlatShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".mcp.json")
	body := `{
  "linear": {"command":"npx","args":["-y","@modelcontextprotocol/server-linear"]}
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].PackageName != "@modelcontextprotocol/server-linear" {
		t.Fatalf("flat shape: %+v", out)
	}
	if out[0].ServerName != "linear" {
		t.Errorf("ServerName not preserved: %+v", out[0])
	}
	if out[0].RootKind != model.RootKindMCPConfig {
		t.Errorf("RootKind = %q, want %q", out[0].RootKind, model.RootKindMCPConfig)
	}
}

func TestScanConfig_DockerAndUV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "example":  {"command":"docker","args":["run","-i","--rm","ghcr.io/example-org/example-mcp:latest"]},
    "github":   {"command":"docker","args":["run","-e","TOKEN","ghcr.io/github/github-mcp-server"]},
    "slack":    {"command":"docker","args":["run","mcp/slack"]},
    "bugcrowd": {"command":"uv","args":["tool","run","--from","bugcrowd-mcp","bugcrowd"]},
    "time":     {"command":"uvx","args":["mcp-server-time"]},
    "plugin":   {"command":"node","args":["${CLAUDE_PLUGIN_ROOT}/dist/index.js"]}
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 6 {
		t.Fatalf("want 6 records, got %d: %+v", len(out), out)
	}
	byServer := map[string]model.Record{}
	for _, r := range out {
		byServer[r.ServerName] = r
	}
	if r := byServer["example"]; r.PackageName != "ghcr.io/example-org/example-mcp" || r.Version != "latest" || r.PackageManager != "docker" {
		t.Errorf("example: %+v", r)
	}
	if r := byServer["github"]; r.PackageName != "ghcr.io/github/github-mcp-server" || r.Version != "" || r.PackageManager != "docker" {
		t.Errorf("github: %+v", r)
	}
	if r := byServer["slack"]; r.PackageName != "mcp/slack" || r.Version != "" || r.PackageManager != "docker" {
		t.Errorf("slack: %+v", r)
	}
	if r := byServer["bugcrowd"]; r.PackageName != "bugcrowd-mcp" || r.PackageManager != "uv" {
		t.Errorf("bugcrowd: %+v", r)
	}
	if r := byServer["time"]; r.PackageName != "mcp-server-time" || r.PackageManager != "uv" {
		t.Errorf("time: %+v", r)
	}
	if r := byServer["plugin"]; r.PackageName != "plugin" {
		t.Errorf("plugin (unresolved shell var): %+v", r)
	}
}

func TestSplitDockerImageRef(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantTag  string
	}{
		{"hashicorp/terraform-mcp-server:0.4.0", "hashicorp/terraform-mcp-server", "0.4.0"},
		{"ghcr.io/example-org/example-mcp:latest", "ghcr.io/example-org/example-mcp", "latest"},
		{"ghcr.io/github/github-mcp-server", "ghcr.io/github/github-mcp-server", ""},
		{"mcp/slack", "mcp/slack", ""},
		{"localhost:5000/foo/bar:1.2.3", "localhost:5000/foo/bar", "1.2.3"},
		{"localhost:5000/foo/bar", "localhost:5000/foo/bar", ""},
		{"registry.example.com:443/team/img:v1", "registry.example.com:443/team/img", "v1"},
		{"alpine@sha256:abc123", "alpine@sha256:abc123", ""},
		{"ghcr.io/foo/bar@sha256:deadbeef", "ghcr.io/foo/bar@sha256:deadbeef", ""},
		{"alpine:3.19@sha256:abc", "alpine@sha256:abc", "3.19"},
		{"ghcr.io/foo/bar:1.2.3@sha256:deadbeef", "ghcr.io/foo/bar@sha256:deadbeef", "1.2.3"},
		{"alpine:3.19", "alpine", "3.19"},
		{"", "", ""},
	}
	for _, c := range cases {
		gotName, gotTag := splitDockerImageRef(c.in)
		if gotName != c.wantName || gotTag != c.wantTag {
			t.Errorf("splitDockerImageRef(%q) = (%q,%q), want (%q,%q)", c.in, gotName, gotTag, c.wantName, c.wantTag)
		}
	}
}

func TestScanConfig_DockerPinnedTag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "terraform": {"command":"docker","args":["run","-i","--rm","hashicorp/terraform-mcp-server:0.4.0"]},
    "localreg":  {"command":"docker","args":["run","localhost:5000/team/img:1.2.3"]},
    "untagged":  {"command":"docker","args":["run","ghcr.io/example-org/example-mcp"]}
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	byServer := map[string]model.Record{}
	for _, r := range out {
		byServer[r.ServerName] = r
	}
	if r := byServer["terraform"]; r.PackageName != "hashicorp/terraform-mcp-server" || r.NormalizedName != "hashicorp/terraform-mcp-server" || r.Version != "0.4.0" || r.PackageManager != "docker" {
		t.Errorf("terraform: %+v", r)
	}
	if r := byServer["localreg"]; r.PackageName != "localhost:5000/team/img" || r.Version != "1.2.3" || r.PackageManager != "docker" {
		t.Errorf("localreg: %+v", r)
	}
	if r := byServer["untagged"]; r.PackageName != "ghcr.io/example-org/example-mcp" || r.Version != "" || r.PackageManager != "docker" {
		t.Errorf("untagged: %+v", r)
	}
}

func TestScanConfig_UVRunDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "bugcrowd":        {"command":"uv","args":["run","--directory","./backend","mcps/bugcrowd.py"]},
    "github_extended": {"command":"uv","args":["run","--directory","./backend","mcps/github_extended.py"]},
    "from-flag":       {"command":"uv","args":["run","--from","bugcrowd-mcp","bugcrowd"]}
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	byServer := map[string]model.Record{}
	for _, r := range out {
		byServer[r.ServerName] = r
	}
	if r := byServer["bugcrowd"]; r.PackageName != "bugcrowd" || r.PackageManager != "uv" || r.Confidence != "low" {
		t.Errorf("bugcrowd: %+v", r)
	}
	if r := byServer["github_extended"]; r.PackageName != "github_extended" || r.PackageManager != "uv" {
		t.Errorf("github_extended: %+v", r)
	}
	if r := byServer["from-flag"]; r.PackageName != "bugcrowd-mcp" || r.PackageManager != "uv" {
		t.Errorf("from-flag: %+v", r)
	}
}

func TestScanConfig_MalformedJSONEmitsWarn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(path, []byte(`{this is not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	type diag struct{ level, path, msg string }
	var diags []diag
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { out = append(out, r) },
		Diag:        func(level, p, msg string) { diags = append(diags, diag{level, p, msg}) },
	}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatalf("ScanConfig returned error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no records, got %+v", out)
	}
	foundWarn := false
	for _, d := range diags {
		if d.level == "warn" && d.path == path {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Fatalf("expected a warn diagnostic for malformed JSON, got %+v", diags)
	}
}

func TestScanConfig_SpecSelector(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "playwright": {"command":"npx","args":["-y","@playwright/mcp@latest"]},
    "pinned":     {"command":"npx","args":["left-pad@1.2.3"]}
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ServerName < out[j].ServerName })
	if len(out) != 2 {
		t.Fatalf("want 2 records, got %+v", out)
	}
	if out[0].PackageName != "left-pad" || out[0].RequestedSpec != "left-pad@1.2.3" || out[0].Version != "" {
		t.Errorf("pinned record: %+v", out[0])
	}
	if out[1].PackageName != "@playwright/mcp" || out[1].RequestedSpec != "@playwright/mcp@latest" || out[1].Version != "" {
		t.Errorf("playwright record: %+v", out[1])
	}
}

func TestScanConfig_DockerConfidence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "tagged":   {"command":"docker","args":["run","ghcr.io/example/example-mcp:1.2.3"]},
    "digest":   {"command":"docker","args":["run","ghcr.io/example/example-mcp@sha256:abc"]},
    "untagged": {"command":"docker","args":["run","ghcr.io/example/example-mcp"]},
    "npm":      {"command":"npx","args":["-y","@playwright/mcp@latest"]}
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	by := map[string]model.Record{}
	for _, r := range out {
		by[r.ServerName] = r
	}
	if r := by["tagged"]; r.Confidence != "medium" {
		t.Errorf("tagged docker confidence = %q, want medium: %+v", r.Confidence, r)
	}
	if r := by["digest"]; r.Confidence != "medium" {
		t.Errorf("digest docker confidence = %q, want medium: %+v", r.Confidence, r)
	}
	if r := by["untagged"]; r.Confidence != "low" {
		t.Errorf("untagged docker confidence = %q, want low: %+v", r.Confidence, r)
	}
	if r := by["npm"]; r.Confidence != "low" {
		t.Errorf("npm confidence = %q, want low: %+v", r.Confidence, r)
	}
}

func TestScanConfig_RemoteURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "sse":  {"type":"sse","url":"https://mcp.example.com/sse"},
    "alt":  {"serverUrl":"https://alt.example.com/api"},
    "http": {"httpUrl":"https://http.example.com/v1"},
    "auth": {"url":"https://user:secret@auth.example.com/mcp?token=shh#frag"}
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	by := map[string]model.Record{}
	for _, r := range out {
		by[r.ServerName] = r
	}
	if len(out) != 4 {
		t.Fatalf("want 4 remote records, got %d: %+v", len(out), out)
	}
	for _, name := range []string{"sse", "alt", "http", "auth"} {
		r, ok := by[name]
		if !ok {
			t.Fatalf("missing remote record %q: %+v", name, out)
		}
		if r.PackageManager != "mcp-remote" {
			t.Errorf("%s: package_manager = %q, want mcp-remote", name, r.PackageManager)
		}
		if r.PackageName != name {
			t.Errorf("%s: package_name = %q, want %q (server id fallback)", name, r.PackageName, name)
		}
		if r.RequestedSpec == "" {
			t.Errorf("%s: RequestedSpec empty, want sanitized URL", name)
		}
	}
	got := by["auth"].RequestedSpec
	if strings.Contains(got, "secret") || strings.Contains(got, "token") || strings.Contains(got, "user:") || strings.Contains(got, "#") || strings.Contains(got, "?") || strings.Contains(got, "/mcp") {
		t.Errorf("sanitized URL still contains secrets or path: %q", got)
	}
	if got != "https://auth.example.com" {
		t.Errorf("sanitized URL = %q, want https://auth.example.com", got)
	}
}

func TestScanConfig_FlatRemoteURL(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, body, wantHost string
	}{
		{"serverUrl", `{"alt": {"serverUrl":"https://alt.example.com/api"}}`, "https://alt.example.com"},
		{"httpUrl", `{"http": {"httpUrl":"https://http.example.com/v1"}}`, "https://http.example.com"},
	}
	for _, c := range cases {
		path := filepath.Join(dir, c.name+".mcp.json")
		if err := os.WriteFile(path, []byte(c.body), 0o644); err != nil {
			t.Fatal(err)
		}
		var out []model.Record
		s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
		if err := s.ScanConfig(path, model.Record{}); err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 {
			t.Fatalf("%s: want 1 record, got %d: %+v", c.name, len(out), out)
		}
		if out[0].PackageManager != "mcp-remote" {
			t.Errorf("%s: package_manager = %q, want mcp-remote", c.name, out[0].PackageManager)
		}
		if out[0].RequestedSpec != c.wantHost {
			t.Errorf("%s: RequestedSpec = %q, want %q", c.name, out[0].RequestedSpec, c.wantHost)
		}
	}
}

func TestSanitizeRemoteURL(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"normal", "https://example.com/mcp", "https://example.com"},
		{"query token", "https://example.com/mcp?token=abc", "https://example.com"},
		{"fragment", "https://example.com/mcp#frag", "https://example.com"},
		{"userinfo", "https://user:pass@example.com/mcp", "https://example.com"},
		{"userinfo + query + fragment", "https://user:pass@example.com/mcp?token=abc#frag", "https://example.com"},
		{"path token", "https://example.com/mcp/sk-live-abcdef", "https://example.com"},
		{"scheme-less userinfo", "//user:pass@example.com/mcp", "//example.com"},
		{"scheme-less plain", "//example.com/api", "//example.com"},
		{"path with @", "https://example.com/path/with@symbol", "https://example.com"},
		{"bare token", "sk-live-abcdef", ""},
	}
	for _, c := range cases {
		if got := sanitizeRemoteURL(c.in); got != c.want {
			t.Errorf("%s: sanitizeRemoteURL(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestIsKnownMCPConfig(t *testing.T) {
	want := []string{"mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json", "mcp_settings.json", "cline_mcp_settings.json"}
	for _, name := range want {
		if !IsKnownMCPConfig(name) {
			t.Errorf("IsKnownMCPConfig(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"package.json", "config.json", "mcp.yaml", ""} {
		if IsKnownMCPConfig(name) {
			t.Errorf("IsKnownMCPConfig(%q) = true, want false", name)
		}
	}
	if IsKnownMCPConfig("settings.json") {
		t.Errorf("IsKnownMCPConfig(\"settings.json\") = true, want false")
	}
}

func TestIsGeminiSettingsJSON(t *testing.T) {
	for _, p := range []string{"/home/alice/.gemini/settings.json", "/Users/alice/.gemini/settings.json", filepath.Join(".gemini", "settings.json")} {
		if !IsGeminiSettingsJSON(p) {
			t.Errorf("IsGeminiSettingsJSON(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"/home/alice/.vscode/settings.json", "/home/alice/.config/Code/User/settings.json", "/home/alice/.gemini/other.json", "/home/alice/gemini/settings.json", "/home/alice/.gemini/sub/settings.json", ""} {
		if IsGeminiSettingsJSON(p) {
			t.Errorf("IsGeminiSettingsJSON(%q) = true, want false", p)
		}
	}
}

func TestIsClaudeConfigJSON(t *testing.T) {
	for _, p := range []string{"/home/alice/.claude.json", "/Users/alice/.claude.json", ".claude.json"} {
		if !IsClaudeConfigJSON(p) {
			t.Errorf("IsClaudeConfigJSON(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"/home/alice/.claude/mcp.json", "/home/alice/claude.json", "/home/alice/.claude.jsonc", ""} {
		if IsClaudeConfigJSON(p) {
			t.Errorf("IsClaudeConfigJSON(%q) = true, want false", p)
		}
	}
}

func TestScanClaudeConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude.json")
	body := `{
  "numStartups": 42,
  "oauthAccount": {"emailAddress": "shouldnotbecaptured"},
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_TOKEN": "shouldnotbecaptured"}
    }
  },
  "projects": {
    "/home/alice/proj-a": {
      "allowedTools": [],
      "mcpServers": {
        "local-time": {"command": "uvx", "args": ["mcp-server-time"]}
      }
    },
    "/home/alice/proj-b": {
      "mcpServers": {
        "stripe": {"type": "http", "url": "https://user:secret@mcp.stripe.com/mcp?token=abc"}
      }
    },
    "/home/alice/proj-c": {
      "lastCost": 0.12
    }
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanClaudeConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 records, got %d: %+v", len(out), out)
	}
	byServer := map[string]model.Record{}
	for _, r := range out {
		byServer[r.ServerName] = r
	}
	if got := byServer["github"]; got.PackageName != "@modelcontextprotocol/server-github" || got.ProjectPath != dir {
		t.Errorf("github: %+v", got)
	}
	if got := byServer["local-time"]; got.PackageName != "mcp-server-time" || got.ProjectPath != "/home/alice/proj-a" {
		t.Errorf("local-time: %+v", got)
	}
	if got := byServer["stripe"]; got.ProjectPath != "/home/alice/proj-b" || got.PackageManager != "mcp-remote" || got.RequestedSpec != "https://mcp.stripe.com" {
		t.Errorf("stripe: %+v", got)
	}
}

func TestScanClaudeConfig_NoServers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude.json")
	body := `{"numStartups": 3, "oauthAccount": {"emailAddress": "x"}, "projects": {"/p": {"lastCost": 1}}}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanClaudeConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("want 0 records, got %d: %+v", len(out), out)
	}
}

func TestLooksLikePackageSpec(t *testing.T) {
	pass := []string{"@modelcontextprotocol/server-github", "@playwright/mcp@latest", "left-pad", "left-pad@1.2.3", "@scope/pkg", "@scope/pkg@1.2.3", "pkg@npm:other@1.0", "host@npm:@scope/other@1.0.0", "@scope/pkg@npm:@other/target@2.0.0", "python:mypkg.server"}
	reject := []string{"", "http://reg.example.com/pkg.tgz", "https://reg.example.com/pkg.tgz", "https://user:token@reg.example.com/", "ftp://example.com/x", "git://github.com/owner/repo.git", "git+https://github.com/owner/repo.git", "git+ssh://git@github.com/owner/repo.git", "ssh://git@github.com/owner/repo.git", "github:owner/repo", "gitlab:owner/repo", "bitbucket:owner/repo", "file:./local/path", "file:///abs/path", "/abs/path/to/pkg.tgz", "./local/pkg.tgz", "../local/pkg", "./relative/dir", "pkg.tgz", "archive.tar.gz", "archive.zip", "C:\\Users\\me\\pkg", "C:/Users/me/pkg", `server\path\here`, "user:pass@host/path", "host@npm:https://user:token@reg.example.com/pkg.tgz", "host@npm:http://reg.example.com/pkg.tgz", "host@npm:file:./local", "host@npm:file:///abs/path", "host@npm:../local", "host@npm:./local", "host@npm:/abs/path", "host@npm:pkg.tgz", "host@npm:user:pass@host/path", "host@npm:"}
	for _, s := range pass {
		if !looksLikePackageSpec(s) {
			t.Errorf("looksLikePackageSpec(%q) = false, want true", s)
		}
	}
	for _, s := range reject {
		if looksLikePackageSpec(s) {
			t.Errorf("looksLikePackageSpec(%q) = true, want false", s)
		}
	}
}

func TestInferPackageFromArgs_ValueTakingFlags(t *testing.T) {
	cases := []struct {
		name, cmd    string
		args         []string
		wantSpec     string
		wantLauncher string
	}{
		{"npx --registry URL pkg", "npx", []string{"--registry", "https://token@reg.example.com/", "@scope/pkg"}, "@scope/pkg", ""},
		{"npx --registry=URL pkg", "npx", []string{"--registry=https://token@reg.example.com/", "@scope/pkg"}, "@scope/pkg", ""},
		{"pnpm dlx --registry URL pkg", "pnpm", []string{"dlx", "--registry", "https://t@reg.example.com/", "@scope/pkg"}, "@scope/pkg", ""},
		{"yarn dlx --cache PATH pkg", "yarn", []string{"dlx", "--cache", "/some/local/cache", "left-pad@1.2.3"}, "left-pad@1.2.3", ""},
		{"bun x --cwd PATH pkg", "bun", []string{"x", "--cwd", "/tmp/work", "left-pad"}, "left-pad", ""},
		{"bunx --registry URL pkg", "bunx", []string{"--registry", "https://t@reg.example.com/", "left-pad"}, "left-pad", ""},
		{"npm exec --registry URL -- pkg", "npm", []string{"exec", "--registry", "https://t@reg.example.com/", "--", "@scope/pkg"}, "@scope/pkg", ""},
		{"npx --package <scoped> -- cmd", "npx", []string{"--package", "@scope/pkg", "--", "cmd"}, "@scope/pkg", ""},
		{"npx --package=<scoped> -- cmd", "npx", []string{"--package=@scope/pkg", "--", "cmd"}, "@scope/pkg", ""},
		{"bunx --package <scoped> -- cmd", "bunx", []string{"--package", "@scope/pkg", "--", "cmd"}, "@scope/pkg", ""},
		{"npm exec --workspaces <scoped>", "npm", []string{"exec", "--workspaces", "@scope/pkg"}, "@scope/pkg", ""},
		{"npx host@npm:@scope/other@version", "npx", []string{"-y", "host@npm:@scope/other@1.0.0"}, "host@npm:@scope/other@1.0.0", ""},
		{"npx <pkg> --package <other>", "npx", []string{"foo", "--package", "@npmcli/bar"}, "foo", ""},
		{"npx <pkg> -- --package <other>", "npx", []string{"foo", "--", "--package", "@npmcli/bar"}, "foo", ""},
		{"npm exec <pkg> -- --package <other>", "npm", []string{"exec", "foo", "--", "--package", "@npmcli/bar"}, "foo", ""},
		{"bunx --registry URL --package <scoped> -- cmd", "bunx", []string{"--registry", "https://t@reg.example.com/", "--package", "@scope/pkg", "--", "cmd"}, "@scope/pkg", ""},
		{"pnpm dlx --package=<scoped> -- cmd", "pnpm", []string{"dlx", "--package=@scope/pkg", "--", "cmd"}, "@scope/pkg", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotSpec, gotLauncher := inferPackageFromArgs(c.cmd, c.args)
			if gotSpec != c.wantSpec || gotLauncher != c.wantLauncher {
				t.Errorf("inferPackageFromArgs(%q,%v) = (%q,%q), want (%q,%q)", c.cmd, c.args, gotSpec, gotLauncher, c.wantSpec, c.wantLauncher)
			}
		})
	}
}

func TestScanConfig_NonPackageSpecsDoNotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "https-url":      {"command":"npx","args":["-y","https://user:token@reg.example.com/pkg.tgz"]},
    "http-url":       {"command":"npx","args":["http://reg.example.com/pkg"]},
    "git-plus":       {"command":"npx","args":["git+https://github.com/owner/repo.git"]},
    "git-ssh":        {"command":"npx","args":["git+ssh://git@github.com/owner/repo.git"]},
    "github-short":   {"command":"npx","args":["github:owner/repo"]},
    "file-ref":       {"command":"npx","args":["file:./local/pkg"]},
    "abs-path":       {"command":"npx","args":["/abs/path/to/pkg.tgz"]},
    "rel-path":       {"command":"npx","args":["./local/pkg"]},
    "tarball-bare":   {"command":"npx","args":["pkg.tgz"]},
    "tarball-tgz":    {"command":"npx","args":["archive.tar.gz"]},
    "win-path":       {"command":"npx","args":["C:\\\\Users\\\\me\\\\pkg"]},
    "registry-flag":  {"command":"npx","args":["--registry","https://token@reg.example.com/","valid-pkg"]},
    "registry-eq":    {"command":"npx","args":["--registry=https://token@reg.example.com/","@scope/valid"]},
    "pnpm-registry":  {"command":"pnpm","args":["dlx","--registry","https://token@reg.example.com/","@scope/valid"]},
    "yarn-cache":     {"command":"yarn","args":["dlx","--cache","/some/local/cache","left-pad@1.2.3"]},
    "bun-cwd":        {"command":"bun","args":["x","--cwd","/tmp/work","left-pad"]},
    "alias-url":      {"command":"npx","args":["-y","host@npm:https://user:token@reg.example.com/pkg.tgz"]},
    "alias-file":     {"command":"npx","args":["-y","host@npm:file:./local"]},
    "alias-relpath":  {"command":"npx","args":["-y","host@npm:../local"]}
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	by := map[string]model.Record{}
	for _, r := range out {
		by[r.ServerName] = r
	}
	leakySubstrings := []string{"://", "token", "user:", "git+", "github:", "file:", "/abs/", "./", ".tgz", ".tar.gz", "\\\\", "C:\\", "C:/"}
	rejected := []string{"https-url", "http-url", "git-plus", "git-ssh", "github-short", "file-ref", "abs-path", "rel-path", "tarball-bare", "tarball-tgz", "win-path", "alias-url", "alias-file", "alias-relpath"}
	for _, id := range rejected {
		r := by[id]
		if r.PackageName != id {
			t.Errorf("%s: PackageName = %q, want %q", id, r.PackageName, id)
		}
		if r.NormalizedName != strings.ToLower(id) {
			t.Errorf("%s: NormalizedName = %q, want %q", id, r.NormalizedName, strings.ToLower(id))
		}
		if r.RequestedSpec != "" {
			t.Errorf("%s: RequestedSpec = %q, want empty", id, r.RequestedSpec)
		}
		for _, sub := range leakySubstrings {
			if strings.Contains(r.PackageName, sub) || strings.Contains(r.RequestedSpec, sub) {
				t.Errorf("%s: leaked %q: %+v", id, sub, r)
			}
		}
	}
	if r := by["registry-flag"]; r.PackageName != "valid-pkg" {
		t.Errorf("registry-flag: %+v", r)
	}
	if r := by["registry-eq"]; r.PackageName != "@scope/valid" {
		t.Errorf("registry-eq: %+v", r)
	}
	if r := by["pnpm-registry"]; r.PackageName != "@scope/valid" {
		t.Errorf("pnpm-registry: %+v", r)
	}
	if r := by["yarn-cache"]; r.PackageName != "left-pad" || r.RequestedSpec != "left-pad@1.2.3" {
		t.Errorf("yarn-cache: %+v", r)
	}
	if r := by["bun-cwd"]; r.PackageName != "left-pad" {
		t.Errorf("bun-cwd: %+v", r)
	}
}

func TestLooksUnresolvedShellVar(t *testing.T) {
	for _, s := range []string{"${CLAUDE_PLUGIN_ROOT}/foo", "$HOME/bin/x", "%APPDATA%\\Claude\\thing"} {
		if !looksUnresolvedShellVar(s) {
			t.Errorf("looksUnresolvedShellVar(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"@scope/pkg", "plain-name", "price$99", "foo % bar % qx", "50%"} {
		if looksUnresolvedShellVar(s) {
			t.Errorf("looksUnresolvedShellVar(%q) = true, want false", s)
		}
	}
}

// ---------------------------------------------------------------------------
// Plaintext credential detection tests
// ---------------------------------------------------------------------------

// TestCredentialFinding_KnownPrefixes verifies that env values matching
// well-known API-key prefixes produce plaintext_credential findings with
// redacted values, the correct provider label, and remediation text.
func TestCredentialFinding_KnownPrefixes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "anthropic": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "OPENAI_API_KEY": "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "GITHUB_TOKEN": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE0",
        "SAFE_REF": "${ANTHROPIC_API_KEY}",
        "PATH": "/usr/bin:/usr/local/bin",
        "NODE_ENV": "production"
      }
    }
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	var records []model.Record
	var findings []model.Finding
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { records = append(records, r) },
		EmitFinding: func(f model.Finding) { findings = append(findings, f) },
	}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}

	// Package record should still be emitted.
	if len(records) != 1 {
		t.Fatalf("want 1 package record, got %d", len(records))
	}

	// Expect 4 credential findings (Anthropic, OpenAI, GitHub, AWS).
	if len(findings) != 4 {
		t.Fatalf("want 4 credential findings, got %d: %+v", len(findings), findings)
	}

	wantLabels := map[string]bool{
		"Anthropic API key":            false,
		"OpenAI project key":           false,
		"GitHub personal access token": false,
		"AWS access key ID":            false,
	}
	for _, f := range findings {
		if f.FindingType != model.FindingTypePlaintextCredential {
			t.Errorf("finding_type = %q, want %q", f.FindingType, model.FindingTypePlaintextCredential)
		}
		if f.Severity != "high" {
			t.Errorf("severity = %q, want high", f.Severity)
		}
		if f.Confidence != "high" {
			t.Errorf("confidence = %q, want high", f.Confidence)
		}
		if f.SourceFile != path {
			t.Errorf("source_file = %q, want %q", f.SourceFile, path)
		}
		wantLabels[f.CatalogName] = true

		// Evidence must contain the redacted credential.
		if !strings.Contains(f.Evidence, "***") {
			t.Errorf("evidence missing redacted value: %s", f.Evidence)
		}
		// Evidence must contain remediation instructions.
		if !strings.Contains(f.Evidence, "${") {
			t.Errorf("evidence missing remediation: %s", f.Evidence)
		}
		// Evidence must NOT contain the actual secret.
		if strings.Contains(f.Evidence, "xxxxxxx") {
			t.Errorf("evidence leaks actual secret: %s", f.Evidence)
		}
	}
	for label, found := range wantLabels {
		if !found {
			t.Errorf("missing finding for %q", label)
		}
	}
}

// TestCredentialFinding_HeuristicMatch verifies that env values with
// secret-suggesting key names and high-entropy values produce findings.
func TestCredentialFinding_HeuristicMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "custom": {
      "command": "npx",
      "args": ["-y", "some-mcp-server"],
      "env": {
        "MY_SECRET_TOKEN": "aVeryLongRandomTokenValueThatLooksLikeACredential1234567890abcdef",
        "API_KEY_INTERNAL": "xyzABC123456789012345678901234567890xyzABC",
        "SHORT_KEY": "abc",
        "FILE_PATH_KEY": "/usr/local/bin/some-tool"
      }
    }
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	var findings []model.Finding
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) {},
		EmitFinding: func(f model.Finding) { findings = append(findings, f) },
	}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}

	// MY_SECRET_TOKEN and API_KEY_INTERNAL should fire.
	// SHORT_KEY (too short) and FILE_PATH_KEY (path value) should not.
	if len(findings) != 2 {
		t.Fatalf("want 2 heuristic findings, got %d: %+v", len(findings), findings)
	}

	keys := map[string]bool{}
	for _, f := range findings {
		if strings.Contains(f.Evidence, "MY_SECRET_TOKEN") {
			keys["MY_SECRET_TOKEN"] = true
		}
		if strings.Contains(f.Evidence, "API_KEY_INTERNAL") {
			keys["API_KEY_INTERNAL"] = true
		}
		if f.CatalogName != "possible credential" {
			t.Errorf("heuristic finding should have label 'possible credential', got %q", f.CatalogName)
		}
	}
	if !keys["MY_SECRET_TOKEN"] || !keys["API_KEY_INTERNAL"] {
		t.Errorf("missing expected heuristic findings: %v", keys)
	}
}

// TestCredentialFinding_Headers verifies that hardcoded credentials in
// HTTP headers produce findings with redacted values.
func TestCredentialFinding_Headers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "remote-api": {
      "url": "https://api.example.com/mcp",
      "headers": {
        "Authorization": "Bearer sk-ant-api03-realtoken",
        "x-api-key": "hardcoded-api-key-value-that-is-long-enough",
        "Content-Type": "application/json"
      }
    }
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	var findings []model.Finding
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) {},
		EmitFinding: func(f model.Finding) { findings = append(findings, f) },
	}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}

	// Authorization and x-api-key should fire. Content-Type should not.
	if len(findings) != 2 {
		t.Fatalf("want 2 header findings, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if !strings.Contains(f.Evidence, "header") {
			t.Errorf("header finding evidence should mention 'header': %s", f.Evidence)
		}
		if strings.Contains(f.Evidence, "realtoken") || strings.Contains(f.Evidence, "hardcoded-api-key") {
			t.Errorf("evidence leaks secret: %s", f.Evidence)
		}
	}
}

// TestCredentialFinding_EnvVarRefsNotFlagged ensures that ${VAR}
// references never produce credential findings.
func TestCredentialFinding_EnvVarRefsNotFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "safe": {
      "command": "npx",
      "args": ["-y", "some-server"],
      "env": {
        "SUPER_SECRET_TOKEN": "${MY_SECRET}",
        "API_KEY": "${API_KEY}",
        "PASSWORD": "${DB_PASSWORD}",
        "AUTH_BEARER": "prefix-${TOKEN}-suffix"
      }
    }
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	var findings []model.Finding
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) {},
		EmitFinding: func(f model.Finding) { findings = append(findings, f) },
	}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("env-var references should not produce findings, got %d: %+v", len(findings), findings)
	}
}

// TestCredentialFinding_ClaudeConfig verifies credential detection in
// Claude Code's dual-scope config (top-level + per-project).
func TestCredentialFinding_ClaudeConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude.json")
	body := `{
  "mcpServers": {
    "global-server": {
      "command": "npx",
      "args": ["-y", "some-server"],
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-api03-globaltoken1234567890abcdefghijklmnop"
      }
    }
  },
  "projects": {
    "/home/alice/myproject": {
      "mcpServers": {
        "project-server": {
          "command": "uvx",
          "args": ["project-mcp"],
          "env": {
            "GITHUB_TOKEN": "ghp_projecttoken1234567890abcdefghijk"
          }
        }
      }
    }
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	var findings []model.Finding
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) {},
		EmitFinding: func(f model.Finding) { findings = append(findings, f) },
	}
	if err := s.ScanClaudeConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}

	if len(findings) != 2 {
		t.Errorf("want 2 findings (global + project), got %d: %+v", len(findings), findings)
	}
}

// TestRedactCredential verifies that the redaction function masks secrets
// while preserving identifying prefixes.
func TestRedactCredential(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"sk-ant-api03-xxxxxxxxxxxx", "sk-ant-api***"},
		{"sk-proj-xxxxxxxxxxxx", "sk-proj-***"},
		{"ghp_xxxxxxxxxxxxxxxxxxxx", "ghp_***"},
		{"AKIAIOSFODNN7EXAMPLE", "AKIA***"},
		{"AIzaSyxxxxxxxxxxxxxxxxx", "AIza***"},
		{"some-unknown-long-token", "some***"},
		{"abc", "***"},
	}
	for _, c := range cases {
		if got := redactCredential(c.in); got != c.want {
			t.Errorf("redactCredential(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestCredentialHelpers exercises detection helpers in isolation.
func TestCredentialHelpers(t *testing.T) {
	if !isEnvVarReference("${TOKEN}") {
		t.Error("isEnvVarReference(${TOKEN}) = false")
	}
	if isEnvVarReference("sk-ant-api03-xxx") {
		t.Error("isEnvVarReference(literal) = true")
	}

	if label := matchesKnownCredentialPrefix("sk-ant-api03-xxx"); label != "Anthropic API key" {
		t.Errorf("matchesKnownCredentialPrefix(Anthropic) = %q", label)
	}
	if label := matchesKnownCredentialPrefix("just-a-string"); label != "" {
		t.Errorf("matchesKnownCredentialPrefix(plain) = %q", label)
	}

	if !keyNameSuggestsSecret("MY_SECRET_TOKEN") {
		t.Error("keyNameSuggestsSecret(MY_SECRET_TOKEN) = false")
	}
	if keyNameSuggestsSecret("PATH") {
		t.Error("keyNameSuggestsSecret(PATH) = true")
	}

	if !looksLikeCredentialValue("aVeryLongRandomTokenValue1234567890abcdef") {
		t.Error("looksLikeCredentialValue(long token) = false")
	}
	if looksLikeCredentialValue("short") {
		t.Error("looksLikeCredentialValue(short) = true")
	}
	if looksLikeCredentialValue("/usr/local/bin/some-really-long-path-here") {
		t.Error("looksLikeCredentialValue(path) = true")
	}
}
