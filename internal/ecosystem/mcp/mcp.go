// Package mcp scans Model Context Protocol server configuration files.
//
// MCP configs are JSON. Several clients use slightly different envelopes
// but the same per-server shape:
//
//	{ "mcpServers": { "<id>": { "command": "...", "args": [...] } } }
//	{ "servers":    { "<id>": { ... } } }                            // some clients
//	{ "<id>": { "command": "...", "args": [...] } }                  // flat
//
// One record is emitted per configured server. PackageName is the bare
// package spec parsed from the command/args (e.g.
// "@modelcontextprotocol/server-github"); when the configured argument
// includes a selector ("@latest", "@1.2.3"), that selector is preserved
// in RequestedSpec. Version remains empty for npm/PyPI/uv launchers
// because those MCP configs reference packages by spec without resolving
// to an installed version. Docker/OCI launchers are the exception: an
// explicit image tag is split off into Version, since the tag is the
// OCI-equivalent of a pinned version. The configured server id is
// preserved in ServerName so the alias survives even when PackageName
// is derived from the command/args.
//
// Env values are never captured in package records. However, env and
// header blocks are inspected for plaintext credentials: values that
// match known API-key prefixes or that pair a secret-suggesting key
// name with a high-entropy value are emitted as plaintext_credential
// findings with the secret redacted and a remediation message. This
// surfaces hardcoded secrets in the same NDJSON output stream so
// operators can act on them alongside package-exposure findings.
//
// Remote MCP entries (sse/http transports identified by a url,
// serverUrl, or httpUrl field with no command) are emitted with
// PackageManager="mcp-remote". The configured endpoint is recorded in
// RequestedSpec reduced to "scheme://host" (or "//host" for
// scheme-less network-path references): userinfo, query, fragment,
// and path are all dropped so credentials embedded in any of those
// cannot leak. PackageName falls back to the server id; the URL is
// not treated as a package identity.
package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
)

const Ecosystem = model.EcosystemMCP

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	EmitFinding func(model.Finding)
	Diag        func(level, path, msg string)
}

// IsKnownMCPConfig returns true if the basename matches a known MCP config
// file. The walker uses this to dispatch.
func IsKnownMCPConfig(base string) bool {
	switch base {
	case "mcp.json",
		"claude_desktop_config.json",
		"mcp_config.json",
		"mcp_settings.json",
		"cline_mcp_settings.json",
		".mcp.json":
		return true
	}
	return false
}

// IsGeminiSettingsJSON reports whether path is the Gemini CLI / Gemini Code
// Assist user settings file (`<home>/.gemini/settings.json`). Dispatch is
// path-aware rather than basename-aware because `settings.json` is a
// common, ambiguous filename (notably the VS Code user settings file)
// that we must not feed to the MCP parser globally. The file's top-level
// `mcpServers` envelope is already handled by ScanConfig.
func IsGeminiSettingsJSON(path string) bool {
	return filepath.Base(path) == "settings.json" &&
		filepath.Base(filepath.Dir(path)) == ".gemini"
}

// IsClaudeConfigJSON reports whether path is Claude Code's user config
// file (`<home>/.claude.json`). This file carries MCP servers in two
// places — top-level `mcpServers` (user scope) and
// `projects.<dir>.mcpServers` (local scope) — neither of which the
// generic basename allowlist routes here, so dispatch is path-aware and
// the file is parsed by ScanClaudeConfig rather than ScanConfig.
func IsClaudeConfigJSON(path string) bool {
	return filepath.Base(path) == ".claude.json"
}

type serverEntry struct {
	Command   string                 `json:"command"`
	Args      []string               `json:"args"`
	Env       map[string]interface{} `json:"env"`
	Headers   map[string]string      `json:"headers"`
	URL       string                 `json:"url"`
	ServerURL string                 `json:"serverUrl"`
	HTTPURL   string                 `json:"httpUrl"`
	Type      string                 `json:"type"`
}

// remoteURL returns the first non-empty remote URL field on the entry.
// Multiple clients use different field names for the same thing; the
// order here mirrors the order they were standardized in. Headers, env,
// and any authorization material are deliberately not surfaced.
func (e serverEntry) remoteURL() string {
	switch {
	case e.URL != "":
		return e.URL
	case e.ServerURL != "":
		return e.ServerURL
	case e.HTTPURL != "":
		return e.HTTPURL
	}
	return ""
}

// sanitizeRemoteURL returns a representation of u safe to record. Only
// scheme + host are preserved so the record remains useful for endpoint
// identity at the host level without leaking secrets: userinfo, query,
// fragment, and path are all dropped. Tokens are commonly embedded in
// any of those four (including path segments like "/mcp/<token>"), so
// the conservative approach is to drop them all.
//
// Scheme-less network-path references ("//host/path") are recognized
// and reduced to "//host" with userinfo stripped. If parsing fails or
// no host can be recovered, the function returns "" rather than
// emitting a raw, potentially secret-bearing string.
func sanitizeRemoteURL(u string) string {
	if u == "" {
		return ""
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	host := parsed.Host
	if host == "" {
		return ""
	}
	if parsed.Scheme != "" {
		return parsed.Scheme + "://" + host
	}
	// Scheme-less network-path reference ("//host/path"): preserve the
	// "//host" form so the record still identifies a network endpoint
	// without leaking userinfo or path-embedded credentials.
	if strings.HasPrefix(u, "//") {
		return "//" + host
	}
	return ""
}

func (s *Scanner) ScanConfig(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}

	// Try envelope { mcpServers: {...} } first, then { servers: {...} }, then
	// flat object. Malformed JSON is surfaced as a warn diagnostic so the
	// file is not silently skipped.
	var env1 struct {
		MCPServers map[string]serverEntry `json:"mcpServers"`
		Servers    map[string]serverEntry `json:"servers"`
	}
	servers := map[string]serverEntry{}
	envErr := json.Unmarshal(data, &env1)
	if envErr == nil {
		for k, v := range env1.MCPServers {
			servers[k] = v
		}
		for k, v := range env1.Servers {
			if _, ok := servers[k]; !ok {
				servers[k] = v
			}
		}
	}
	var flatErr error
	if len(servers) == 0 {
		// Fall back to a flat map. Conservative widening: accept any entry
		// that carries enough signal to look like an MCP server entry
		// (command, URL, args, or an explicit transport type).
		var flat map[string]serverEntry
		flatErr = json.Unmarshal(data, &flat)
		if flatErr == nil {
			for k, v := range flat {
				if v.Command != "" || v.remoteURL() != "" || len(v.Args) > 0 || v.Type != "" {
					servers[k] = v
				}
			}
		}
	}
	if len(servers) == 0 {
		if envErr != nil && flatErr != nil {
			if s.Diag != nil {
				s.Diag("warn", path, "parse MCP config: "+envErr.Error())
			}
			return nil
		}
		if s.Diag != nil {
			s.Diag("info", path, "no MCP servers parsed")
		}
		return nil
	}

	s.emitServers(servers, base, path, filepath.Dir(path))
	return nil
}

// ScanClaudeConfig parses Claude Code's user config file
// (`<home>/.claude.json`). Unlike the single-envelope configs handled by
// ScanConfig, this file holds MCP servers at two scopes: the top-level
// `mcpServers` map (user scope, available across all projects) and a
// per-project `projects.<dir>.mcpServers` map (local scope, private to
// one project). Both are inventoried. Only those two keys are read; the
// file's many unrelated settings are ignored, and the flat-object
// fallback is deliberately not applied here so surrounding config never
// gets misread as a server entry. Per-project servers carry the project
// directory in ProjectPath; top-level servers use the config file's own
// directory.
func (s *Scanner) ScanClaudeConfig(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var doc struct {
		MCPServers map[string]serverEntry `json:"mcpServers"`
		Projects   map[string]struct {
			MCPServers map[string]serverEntry `json:"mcpServers"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		if s.Diag != nil {
			s.Diag("warn", path, "parse Claude config: "+err.Error())
		}
		return nil
	}
	s.emitServers(doc.MCPServers, base, path, filepath.Dir(path))
	projectDirs := make([]string, 0, len(doc.Projects))
	for dir := range doc.Projects {
		projectDirs = append(projectDirs, dir)
	}
	sort.Strings(projectDirs)
	for _, dir := range projectDirs {
		s.emitServers(doc.Projects[dir].MCPServers, base, path, dir)
	}
	return nil
}

// emitServers turns a map of parsed server entries into one record each,
// keyed by the configured server id. sourcePath is recorded as the
// originating file; projectPath is the directory the servers are scoped
// to (the config file's own directory for top-level entries, or the
// per-project key for nested entries). Server ids are emitted in sorted
// order so a record stream over the same config is deterministic.
func (s *Scanner) emitServers(servers map[string]serverEntry, base model.Record, sourcePath, projectPath string) {
	ids := make([]string, 0, len(servers))
	for k := range servers {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	for _, id := range ids {
		srv := servers[id]

		// Detect plaintext credentials in the env and headers blocks
		// and emit findings with redacted values and remediation.
		s.emitCredentialFindings(srv, id, base, sourcePath, projectPath)

		r := base
		r.Ecosystem = Ecosystem
		r.PackageManager = "mcp"
		r.SourceType = "mcp-config"
		r.SourceFile = sourcePath
		r.ProjectPath = projectPath
		r.RootKind = model.RootKindMCPConfig
		r.ServerName = id
		r.Confidence = "low"

		// Remote-URL entries (sse / http transports) have no command to
		// parse. Surface the sanitized endpoint via RequestedSpec and tag
		// the record as a remote MCP reference so receivers can route it
		// without re-parsing the file. Headers, env, and any userinfo or
		// query-string credentials are deliberately not retained.
		if srv.Command == "" {
			if u := sanitizeRemoteURL(srv.remoteURL()); u != "" {
				r.PackageName = id
				r.NormalizedName = strings.ToLower(id)
				r.PackageManager = "mcp-remote"
				r.RequestedSpec = u
				s.Emit(r)
			}
			continue
		}

		spec, launcher := inferPackageFromArgs(srv.Command, srv.Args)
		var name, selector, version string
		// Docker/OCI image refs encode the version as `image:tag`, not
		// as the npm-style `@selector` that splitSpec assumes. Run them
		// through the OCI splitter instead so the tag becomes Version
		// and a digest ref (`name@sha256:...`) is preserved on the name
		// side. Conservative around registry-port refs like
		// `localhost:5000/foo/bar:1.2.3`: only split on the colon after
		// the last slash.
		if launcher == "docker" {
			name, version = splitDockerImageRef(spec)
		} else {
			name, selector = splitSpec(spec)
		}
		// Drop unresolved shell variables — these are not package identities.
		// Example: `${CLAUDE_PLUGIN_ROOT}/foo` left literal by the loader.
		if looksUnresolvedShellVar(name) {
			name = ""
			spec = ""
			selector = ""
		}
		// Reject obvious non-package references (URLs, git refs, local
		// paths, tarballs) so a raw URL/path never round-trips into
		// PackageName or RequestedSpec. npm-style launchers accept these
		// forms, but they carry no package identity and may embed
		// credentials (e.g. a --registry value or a tarball URL with a
		// userinfo segment). Docker image refs are validated separately
		// by splitDockerImageRef and stay on this path.
		if launcher != "docker" && !looksLikePackageSpec(spec) {
			name = ""
			spec = ""
			selector = ""
		}
		if name == "" {
			name = id
		}
		r.PackageName = name
		r.NormalizedName = strings.ToLower(name)
		// Surface non-npm launchers (docker images, python tools) on the
		// record so receivers can tell a container image apart from an npm
		// spec without re-parsing the args.
		if launcher != "" {
			r.PackageManager = launcher
		}
		if version != "" {
			r.Version = version
		}
		if selector != "" {
			r.RequestedSpec = spec
		}
		// Pinned docker image refs are the only MCP shape that ties a
		// configured server to an immutable identity: a tag or digest
		// names a specific image. Bump confidence to "medium" so
		// exposure consumers can distinguish these from the larger pool
		// of spec-only npm/uv launches. Wording elsewhere stays
		// conservative — this is still a configured reference, not a
		// running process.
		if launcher == "docker" && (version != "" || strings.Contains(name, "@sha256:")) {
			r.Confidence = "medium"
		}
		s.Emit(r)
	}
}

// looksUnresolvedShellVar reports whether s contains a literal variable
// reference the loader never expanded, in any of the common forms:
// ${VAR}, $VAR (POSIX), or %VAR% (Windows %APPDATA%-style). We treat
// such values as opaque rather than packages.
func looksUnresolvedShellVar(s string) bool {
	if strings.Contains(s, "${") {
		return true
	}
	// $VAR — require a leading "$" followed by an identifier char so a
	// literal "$" elsewhere in a path doesn't trigger.
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '$' {
			c := s[i+1]
			if c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				return true
			}
		}
	}
	// %VAR% — Windows-style with at least one identifier char between
	// the percents.
	if first := strings.Index(s, "%"); first >= 0 {
		if second := strings.Index(s[first+1:], "%"); second > 0 {
			between := s[first+1 : first+1+second]
			ok := true
			for _, c := range between {
				if !(c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
	}
	return false
}

// inferPackageFromArgs returns a best-effort package spec for common
// command/args shapes and an optional launcher tag.
//
// Returned launcher is one of "", "docker", "uv". An empty launcher
// preserves the default package_manager ("mcp"). A non-empty launcher
// signals that the value is not an npm/pypi spec — callers should mark
// the record so a docker image or a uv tool is not later interpreted as
// an npm package by exposure matching.
//
// Supported launchers:
//
//	npx / bunx                          -> first non-flag arg
//	pnpm/yarn/bun/npm dlx|exec|x|run    -> first non-flag arg past sub
//	uvx / pipx                          -> first non-flag arg
//	uv / uv tool run                    -> first non-flag arg past sub,
//	                                       also honors --from <pkg>
//	docker run                          -> last positional non-flag is image
//	python / python3 -m mod             -> "python:<mod>"
func inferPackageFromArgs(cmd string, args []string) (spec, launcher string) {
	bn := filepath.Base(cmd)
	switch bn {
	case "npx", "bunx":
		if spec := scanExplicitPackage(args, nil); spec != "" {
			return spec, ""
		}
		return firstNonFlag(args, nil, npmValueTakingFlags), ""
	case "pnpm", "yarn", "bun", "npm":
		subcommands := map[string]bool{
			"dlx": true, "exec": true, "x": true, "run": true,
		}
		if spec := scanExplicitPackage(args, subcommands); spec != "" {
			return spec, ""
		}
		return firstNonFlag(args, subcommands, npmValueTakingFlags), ""
	case "uvx":
		return firstNonFlag(args, nil, nil), "uv"
	case "uv":
		hasTool := false
		for _, a := range args {
			if a == "tool" {
				hasTool = true
				break
			}
		}
		for i := 0; i < len(args); i++ {
			if args[i] == "--from" && i+1 < len(args) {
				return args[i+1], "uv"
			}
		}
		if !hasTool {
			return "", "uv"
		}
		return firstNonFlag(args, map[string]bool{
			"tool": true, "run": true,
		}, nil), "uv"
	case "pipx":
		for i := 0; i < len(args); i++ {
			if args[i] == "--spec" && i+1 < len(args) {
				return args[i+1], "pipx"
			}
		}
		return firstNonFlag(args, map[string]bool{"run": true}, nil), "pipx"
	case "docker", "podman":
		valueTakingFlags := map[string]bool{
			"-e": true, "--env": true, "--env-file": true,
			"-v": true, "--volume": true, "--mount": true,
			"-p": true, "--publish": true,
			"--name": true, "--network": true, "--user": true, "-u": true,
			"--workdir": true, "-w": true,
			"--entrypoint": true, "--label": true, "-l": true,
			"--add-host": true, "--platform": true,
		}
		started := false
		for i := 0; i < len(args); i++ {
			a := args[i]
			if !started {
				if a == "run" || a == "container" {
					started = true
					continue
				}
				started = true
			}
			if strings.HasPrefix(a, "-") {
				if strings.Contains(a, "=") {
					continue
				}
				if valueTakingFlags[a] && i+1 < len(args) {
					i++
				}
				continue
			}
			return a, "docker"
		}
		return "", "docker"
	case "python", "python3":
		for i, a := range args {
			if a == "-m" && i+1 < len(args) {
				return "python:" + args[i+1], ""
			}
		}
	}
	return "", ""
}

// firstNonFlag returns the first arg that is neither a flag (leading "-")
// nor a member of skip. When valueTaking is non-nil, flags listed there
// also consume the following argument so a flag's value is not mistaken
// for the package spec. The "--flag=value" form is skipped entirely.
//
// Without value-taking flag consumption, a launcher like
// "npx --registry https://token@reg.example.com/ pkg" would return the
// registry URL as the package, leaking the userinfo into PackageName /
// RequestedSpec downstream.

// scanExplicitPackage looks for "--package <pkg>" / "--package=<pkg>" in
// the launcher-parsed prefix of args. The scan stops at "--" (npm/npx do
// not interpret options past it) and at the first positional non-flag
// token that is not in the skip set of recognized subcommands
// (dlx/exec/x/run). Other value-taking flags are consumed so their values
// are not misread as --package. Returns the explicit package spec when
// found, otherwise "".
func scanExplicitPackage(args []string, skip map[string]bool) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return ""
		}
		if strings.HasPrefix(a, "--package=") {
			return strings.TrimPrefix(a, "--package=")
		}
		if a == "--package" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "=") {
				continue
			}
			if npmValueTakingFlags[a] && i+1 < len(args) {
				i++
			}
			continue
		}
		if skip[a] {
			continue
		}
		return ""
	}
	return ""
}

func firstNonFlag(args []string, skip map[string]bool, valueTaking map[string]bool) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "=") {
				continue
			}
			if valueTaking[a] && i+1 < len(args) {
				i++
			}
			continue
		}
		if skip[a] {
			continue
		}
		return a
	}
	return ""
}

var npmValueTakingFlags = map[string]bool{
	"--registry":          true,
	"--reg":               true,
	"--cache":             true,
	"--prefix":            true,
	"--userconfig":        true,
	"--globalconfig":      true,
	"--node-options":      true,
	"--node-version":      true,
	"--workspace":         true,
	"-w":                  true,
	"--filter":            true,
	"--otp":               true,
	"--access":            true,
	"--auth-type":         true,
	"--tag":               true,
	"--call":              true,
	"-c":                  true,
	"--package":           true,
	"--shell":             true,
	"--script-shell":      true,
	"--cwd":               true,
	"--loglevel":          true,
	"--store":             true,
	"--store-dir":         true,
	"--virtual-store-dir": true,
	"--lockfile-dir":      true,
	"--config":            true,
	"--config-file":       true,
}

func looksLikePackageSpec(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "python:") {
		return true
	}
	if strings.HasPrefix(s, "/") {
		return false
	}
	if len(s) >= 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') {
		c := s[0]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			return false
		}
	}
	if strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || strings.HasPrefix(s, ".\\") || strings.HasPrefix(s, "..\\") {
		return false
	}
	if strings.Contains(s, "\\") {
		return false
	}
	lower := strings.ToLower(s)
	urlPrefixes := []string{
		"http://", "https://", "ftp://", "ftps://",
		"ssh://", "git://", "git+", "svn://", "svn+",
		"file://", "file:",
		"github:", "gitlab:", "bitbucket:", "gist:",
		"npm:",
	}
	for _, p := range urlPrefixes {
		if strings.HasPrefix(lower, p) {
			return false
		}
	}
	tarballSuffixes := []string{".tgz", ".tar.gz", ".tar.bz2", ".tar", ".zip"}
	for _, suf := range tarballSuffixes {
		if strings.HasSuffix(lower, suf) {
			return false
		}
	}
	if i := strings.Index(s, "@"); i > 0 {
		if strings.HasPrefix(s[i:], "@npm:") {
			target := s[i+len("@npm:"):]
			if target == "" {
				return false
			}
			return looksLikePackageSpec(target)
		}
		if j := strings.Index(s[i:], "/"); j > 0 {
			return false
		}
	}
	return true
}

func splitSpec(spec string) (name, selector string) {
	if spec == "" {
		return "", ""
	}
	if strings.HasPrefix(spec, "python:") {
		return spec, ""
	}
	start := 0
	if strings.HasPrefix(spec, "@") {
		start = 1
	}
	if i := strings.Index(spec[start:], "@npm:"); i >= 0 {
		cut := start + i
		return spec[:cut], spec[cut:]
	}
	idx := strings.LastIndex(spec[start:], "@")
	if idx <= 0 {
		return spec, ""
	}
	cut := start + idx
	return spec[:cut], spec[cut:]
}

func splitDockerImageRef(ref string) (name, tag string) {
	if ref == "" {
		return "", ""
	}
	if at := strings.Index(ref, "@"); at >= 0 {
		head := ref[:at]
		digest := ref[at:]
		lastSlash := strings.LastIndex(head, "/")
		tail := head
		if lastSlash >= 0 {
			tail = head[lastSlash+1:]
		}
		if colon := strings.LastIndex(tail, ":"); colon >= 0 {
			cut := colon
			if lastSlash >= 0 {
				cut = lastSlash + 1 + colon
			}
			return head[:cut] + digest, head[cut+1:]
		}
		return ref, ""
	}
	lastSlash := strings.LastIndex(ref, "/")
	tail := ref
	if lastSlash >= 0 {
		tail = ref[lastSlash+1:]
	}
	colon := strings.LastIndex(tail, ":")
	if colon < 0 {
		return ref, ""
	}
	cut := colon
	if lastSlash >= 0 {
		cut = lastSlash + 1 + colon
	}
	return ref[:cut], ref[cut+1:]
}

// ---------------------------------------------------------------------------
// Plaintext credential detection
//
// MCP config files commonly carry API tokens and secrets in their env and
// headers blocks. Best practice is to use environment variable references
// (${VAR_NAME}) so the secret is never written to disk in the config file.
// The functions below detect hardcoded credentials and emit
// plaintext_credential findings with the secret redacted and a
// remediation message telling the user exactly how to fix it.
// ---------------------------------------------------------------------------

// credentialDetection holds the result of inspecting a single env or
// header value that appears to be a hardcoded credential.
type credentialDetection struct {
	source      string // "env" or "header"
	keyName     string // the env var or header name
	label       string // human-readable provider label (e.g. "Anthropic API key")
	redacted    string // the value with the secret portion masked
	remediation string // actionable fix instructions
}

// secretKeyPatterns are substrings that, when found case-insensitively in
// an env key name, suggest the value may be a secret.
var secretKeyPatterns = []string{
	"token", "key", "secret", "password", "passwd", "auth",
	"credential", "cred", "api_key", "apikey", "access_key",
	"bearer", "jwt",
}

// knownCredentialPrefixes maps well-known API-key and token value prefixes
// to human-readable provider labels. Order matters: longer prefixes are
// listed first so "sk-ant-api" matches before the shorter "sk-" catch-all.
var knownCredentialPrefixes = []struct {
	prefix string
	label  string
}{
	{"sk-ant-api", "Anthropic API key"},
	{"sk-proj-", "OpenAI project key"},
	{"sk-", "OpenAI/generic API key"},
	{"ghp_", "GitHub personal access token"},
	{"gho_", "GitHub OAuth token"},
	{"ghs_", "GitHub server-to-server token"},
	{"ghu_", "GitHub user-to-server token"},
	{"github_pat_", "GitHub fine-grained PAT"},
	{"glpat-", "GitLab personal access token"},
	{"AKIA", "AWS access key ID"},
	{"AIza", "Google API key"},
	{"xoxb-", "Slack bot token"},
	{"xoxp-", "Slack user token"},
	{"xapp-", "Slack app-level token"},
	{"SG.", "SendGrid API key"},
	{"hf_", "Hugging Face token"},
	{"r8_", "Replicate API token"},
	{"pk_live_", "Stripe live publishable key"},
	{"sk_live_", "Stripe live secret key"},
	{"pk_test_", "Stripe test publishable key"},
	{"sk_test_", "Stripe test secret key"},
}

// knownNonSecretKeys are env key names (compared case-insensitively) that
// never hold secrets. Without this allowlist, keys like PATH (contains
// "key" noise via substring matching) would false-positive.
var knownNonSecretKeys = map[string]bool{
	"path": true, "home": true, "user": true, "username": true,
	"shell": true, "term": true, "lang": true, "lc_all": true,
	"lc_ctype": true, "tz": true, "display": true, "pwd": true,
	"oldpwd": true, "hostname": true, "logname": true, "editor": true,
	"visual": true, "node_path": true, "pythonpath": true, "gopath": true,
	"goroot": true, "java_home": true, "tmpdir": true, "temp": true,
	"tmp": true, "http_proxy": true, "https_proxy": true, "no_proxy": true,
	"all_proxy": true, "debug": true, "verbose": true, "log_level": true,
	"ci": true, "node_env": true, "rails_env": true, "rack_env": true,
	"flask_env": true, "django_settings_module": true,
	"github_actions": true, "gitlab_ci": true,
	"xdg_config_home": true, "xdg_data_home": true, "xdg_cache_home": true,
	"xdg_runtime_dir": true, "shlvl": true, "colorterm": true,
	"term_program": true,
}

// sensitiveHeaderNames are HTTP header names (compared case-insensitively)
// whose values typically carry authentication credentials.
var sensitiveHeaderNames = map[string]bool{
	"authorization": true,
	"x-api-key":     true,
	"api-key":       true,
	"x-auth-token":  true,
}

// isEnvVarReference reports whether value contains an environment variable
// reference like ${VAR_NAME}, indicating the secret is fetched at runtime
// rather than stored inline.
func isEnvVarReference(value string) bool {
	return strings.Contains(value, "${")
}

// matchesKnownCredentialPrefix returns a human-readable label if value
// starts with a recognized API-key or token prefix, or "" if no match.
func matchesKnownCredentialPrefix(value string) string {
	for _, kp := range knownCredentialPrefixes {
		if strings.HasPrefix(value, kp.prefix) {
			return kp.label
		}
	}
	return ""
}

// keyNameSuggestsSecret reports whether key (case-insensitive) contains a
// substring that suggests the associated value is a secret, while not
// being a known non-secret key.
func keyNameSuggestsSecret(key string) bool {
	lower := strings.ToLower(key)
	if knownNonSecretKeys[lower] {
		return false
	}
	for _, pat := range secretKeyPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

// looksLikeCredentialValue applies heuristics to decide whether a string
// value is likely a hardcoded credential: at least 20 characters, not a
// file path or URL, and over 80% alphanumeric (token-like entropy).
func looksLikeCredentialValue(value string) bool {
	if len(value) < 20 {
		return false
	}
	if strings.HasPrefix(value, "/") ||
		strings.HasPrefix(value, "http://") ||
		strings.HasPrefix(value, "https://") {
		return false
	}
	if len(value) >= 3 && value[1] == ':' && (value[2] == '\\' || value[2] == '/') {
		return false
	}
	if strings.HasPrefix(value, "@") && strings.Contains(value, "/") {
		return false
	}
	alnum := 0
	for _, c := range value {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' {
			alnum++
		}
	}
	return float64(alnum)/float64(len(value)) > 0.80
}

// redactCredential masks the secret portion of a credential value,
// preserving only the identifying prefix so the provider is recognizable.
// For known prefixes, the prefix is shown followed by "***". For unknown
// credentials, the first 4 characters are shown followed by "***".
func redactCredential(value string) string {
	for _, kp := range knownCredentialPrefixes {
		if strings.HasPrefix(value, kp.prefix) {
			return kp.prefix + "***"
		}
	}
	if len(value) > 4 {
		return value[:4] + "***"
	}
	return "***"
}

// detectEnvCredentials inspects the env block of an MCP server entry for
// values that appear to be hardcoded credentials rather than environment
// variable references. Returns a detection for each flagged value.
func detectEnvCredentials(env map[string]interface{}) []credentialDetection {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []credentialDetection
	for _, key := range keys {
		val, ok := env[key].(string)
		if !ok || val == "" {
			continue
		}
		if isEnvVarReference(val) {
			continue
		}

		remediation := fmt.Sprintf(
			"Replace the hardcoded value of %q with an environment variable reference "+
				"in the MCP config: {\"%s\": \"${%s}\"} — then set the actual value "+
				"in your shell environment or a secrets manager.",
			key, key, key,
		)

		if label := matchesKnownCredentialPrefix(val); label != "" {
			out = append(out, credentialDetection{
				source:      "env",
				keyName:     key,
				label:       label,
				redacted:    redactCredential(val),
				remediation: remediation,
			})
			continue
		}
		if keyNameSuggestsSecret(key) && looksLikeCredentialValue(val) {
			out = append(out, credentialDetection{
				source:      "env",
				keyName:     key,
				label:       "possible credential",
				redacted:    redactCredential(val),
				remediation: remediation,
			})
		}
	}
	return out
}

// detectHeaderCredentials inspects the headers block of an MCP server
// entry for hardcoded credentials in authentication-related headers.
func detectHeaderCredentials(headers map[string]string) []credentialDetection {
	if len(headers) == 0 {
		return nil
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []credentialDetection
	for _, key := range keys {
		if !sensitiveHeaderNames[strings.ToLower(key)] {
			continue
		}
		val := headers[key]
		if val == "" || isEnvVarReference(val) {
			continue
		}
		out = append(out, credentialDetection{
			source:   "header",
			keyName:  key,
			label:    "hardcoded " + key + " header",
			redacted: redactCredential(val),
			remediation: fmt.Sprintf(
				"Replace the hardcoded %q header value with an environment variable "+
					"reference, or configure the MCP server to read the credential "+
					"from an environment variable instead.",
				key,
			),
		})
	}
	return out
}

// emitCredentialFindings detects plaintext credentials in the env and
// headers blocks of an MCP server entry, then emits a
// plaintext_credential finding for each detection. Each finding carries
// a redacted preview of the credential and a remediation message.
func (s *Scanner) emitCredentialFindings(srv serverEntry, serverName string, base model.Record, sourcePath, projectPath string) {
	if s.EmitFinding == nil {
		return
	}
	var detections []credentialDetection
	detections = append(detections, detectEnvCredentials(srv.Env)...)
	detections = append(detections, detectHeaderCredentials(srv.Headers)...)

	for _, d := range detections {
		evidence := fmt.Sprintf(
			"%s %q contains a hardcoded %s (%s)",
			d.source, d.keyName, d.label, d.redacted,
		)

		f := model.Finding{
			SchemaVersion:  base.SchemaVersion,
			ScannerName:    base.ScannerName,
			ScannerVersion: base.ScannerVersion,
			RunID:          base.RunID,
			ScanTime:       base.ScanTime,
			Endpoint:       base.Endpoint,
			Profile:        base.Profile,
			FindingType:    model.FindingTypePlaintextCredential,
			Severity:       "high",
			CatalogID:      "plaintext-credential",
			CatalogName:    d.label,
			Ecosystem:      Ecosystem,
			PackageName:    serverName,
			NormalizedName: strings.ToLower(serverName),
			RootKind:       model.RootKindMCPConfig,
			ProjectPath:    projectPath,
			SourceType:     "mcp-config",
			SourceFile:     sourcePath,
			Confidence:     "high",
			Evidence:       evidence + "; " + d.remediation,
		}
		s.EmitFinding(f)
	}
}

func (s *Scanner) readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if s.MaxFileSize > 0 && info.Size() > s.MaxFileSize {
		if s.Diag != nil {
			s.Diag("warn", path, fmt.Sprintf("skipping: size %d exceeds max %d", info.Size(), s.MaxFileSize))
		}
		return nil, fmt.Errorf("file %s exceeds max size %d", path, s.MaxFileSize)
	}
	return io.ReadAll(f)
}
