package command

// File operations, differentiated for monitoring. A monitor wants to know
// which commands change the filesystem and how — not that `rm` ran with two
// operands. FileChange is that answer; FileOperator is how a command gives it;
// ParsedCommand.FileChanges is the one call a monitor makes (it also derives
// changes for PathMutators and from resource tags, so `curl -o f` and
// `chmod 600 f` show up without extra code).
//
// Two data-driven types cover most tools: FileTool applies one op to every
// operand (rm, mkdir, touch, truncate, shred); TransferTool moves sources to a
// destination (mv, cp, ln). Archives, compressors, tee, dd and mktemp have
// their own small types below.

import (
	"path"
	"strings"
)

// FileOp is the kind of filesystem change.
type FileOp string

const (
	FileCreate  FileOp = "create"
	FileWrite   FileOp = "write"  // create-or-overwrite / modify in place
	FileAppend  FileOp = "append" // create-or-append (the shell's `>> f`)
	FileTouch   FileOp = "touch"
	FileDelete  FileOp = "delete"
	FileMove    FileOp = "move"
	FileCopy    FileOp = "copy"
	FileLink    FileOp = "link"
	FileExtract FileOp = "extract"
	FileMode    FileOp = "mode"
	FileOwner   FileOp = "owner"
	FileAttr    FileOp = "attr"
	FileACL     FileOp = "acl"
	FileContext FileOp = "context"
)

// FileChange is one filesystem change an invocation makes.
type FileChange struct {
	Op        FileOp
	Path      string // the path changed (the destination for move/copy/link)
	From      string // the source for move/copy/link/extract
	Recursive bool
}

func (c FileChange) String() string {
	s := string(c.Op) + " "
	if c.From != "" {
		s += c.From + " → "
	}
	s += c.Path
	if c.Recursive {
		s += " (recursive)"
	}
	return s
}

// Resource renders the change as an audit resource.
func (c FileChange) Resource() Resource {
	v := c.Path
	if c.From != "" {
		v = c.From + " → " + c.Path
	}
	return Resource{Kind: "path", Action: string(c.Op), Value: v}
}

// FileOperator is implemented by commands that change the filesystem.
type FileOperator interface {
	FileChanges(p ParsedCommand) []FileChange
}

// permOps maps a PathMutator command to the op it performs.
var permOps = map[string]FileOp{
	"chmod": FileMode, "chown": FileOwner, "chgrp": FileOwner, "chattr": FileAttr,
	"chflags": FileAttr, "xattr": FileAttr, "setfacl": FileACL, "chcon": FileContext, "install": FileWrite,
}

// resourceOps maps a path resource's action to a file op, for commands that
// only describe themselves through resource tags (curl -o, wget -O, sed -i …).
var resourceOps = map[string]FileOp{
	"write": FileWrite, "modify": FileWrite, "create": FileCreate, "delete": FileDelete,
	"extract": FileExtract, "touch": FileTouch,
}

// FileChanges lists the filesystem changes this invocation makes: from the
// command's FileOperator, else its PathMutator targets, else its path
// resources with a mutating action. Read-only commands return nil.
func (p ParsedCommand) FileChanges() []FileChange {
	if f, ok := p.cmd.(FileOperator); ok {
		return f.FileChanges(p)
	}
	if m, ok := p.cmd.(PathMutator); ok {
		op, known := permOps[p.Name]
		if !known {
			op = FileWrite
		}
		paths, rec := m.Targets(p)
		var cs []FileChange
		for _, path := range paths {
			cs = append(cs, FileChange{Op: op, Path: path, Recursive: rec})
		}
		return cs
	}
	var cs []FileChange
	for _, r := range p.Resources() {
		if op, ok := resourceOps[r.Action]; ok && (r.Kind == "path" || r.Kind == "archive") {
			cs = append(cs, FileChange{Op: op, Path: r.Value})
		}
	}
	return cs
}

// changeResources renders changes as audit resources.
func changeResources(cs []FileChange) []Resource {
	rs := make([]Resource, len(cs))
	for i, c := range cs {
		rs[i] = c.Resource()
	}
	return rs
}

// FileTool applies Op to every operand (rm, mkdir, touch, …). It is a Builtin.
type FileTool struct {
	Aliases        []string
	Spec           Spec
	Op             FileOp
	RecursiveFlags []string
}

func (t FileTool) Names() []string                { return t.Aliases }
func (t FileTool) Parse(a []string) ParsedCommand { return t.Spec.Parse(a) }
func (FileTool) builtin()                         {}
func (t FileTool) FileChanges(p ParsedCommand) []FileChange {
	rec := len(t.RecursiveFlags) > 0 && p.HasFlag(t.RecursiveFlags...)
	var cs []FileChange
	for _, o := range p.Operands {
		cs = append(cs, FileChange{Op: t.Op, Path: o, Recursive: rec})
	}
	return cs
}
func (t FileTool) Resources(p ParsedCommand) []Resource { return changeResources(t.FileChanges(p)) }

// TransferTool moves/copies/links SOURCE… to DEST (mv, cp, ln). With -t DIR
// every operand is a source. It is a Builtin.
type TransferTool struct {
	Aliases        []string
	Spec           Spec
	Op             FileOp
	RecursiveFlags []string
	TargetDirFlags []string
}

func (t TransferTool) Names() []string                { return t.Aliases }
func (t TransferTool) Parse(a []string) ParsedCommand { return t.Spec.Parse(a) }
func (TransferTool) builtin()                         {}
func (t TransferTool) FileChanges(p ParsedCommand) []FileChange {
	rec := len(t.RecursiveFlags) > 0 && p.HasFlag(t.RecursiveFlags...)
	srcs, dest := p.Operands, ""
	if dir, ok := p.FirstValue(t.TargetDirFlags...); ok {
		dest = dir
	} else if len(srcs) >= 2 {
		srcs, dest = srcs[:len(srcs)-1], srcs[len(srcs)-1]
	} else if len(srcs) == 1 && t.Op == FileLink {
		dest = path.Base(srcs[0]) // `ln -s target` links into the cwd
	} else {
		return nil
	}
	cs := make([]FileChange, 0, len(srcs))
	for _, s := range srcs {
		cs = append(cs, FileChange{Op: t.Op, From: s, Path: dest, Recursive: rec})
	}
	return cs
}
func (t TransferTool) Resources(p ParsedCommand) []Resource { return changeResources(t.FileChanges(p)) }

// Mktemp creates a temp file or directory (-d) from a template.
type Mktemp struct{}

var mktempSpec = Spec{ValueFlags: NewSet("-p", "--tmpdir", "--suffix")}

func (Mktemp) Names() []string                { return []string{"mktemp"} }
func (Mktemp) Parse(a []string) ParsedCommand { return mktempSpec.Parse(a) }
func (Mktemp) builtin()                       {}
func (Mktemp) FileChanges(p ParsedCommand) []FileChange {
	tmpl := "$TMPDIR/tmp.XXXXXXXXXX"
	if len(p.Operands) > 0 {
		tmpl = p.Operands[0]
	}
	if dir, ok := p.FirstValue("-p", "--tmpdir"); ok && !strings.HasPrefix(tmpl, "/") {
		tmpl = path.Join(dir, tmpl)
	}
	return []FileChange{{Op: FileCreate, Path: tmpl, Recursive: p.HasFlag("-d", "--directory")}}
}
func (m Mktemp) Resources(p ParsedCommand) []Resource { return changeResources(m.FileChanges(p)) }

// Tee copies stdin to stdout and to every file operand (-a appends).
type Tee struct{}

func (Tee) Names() []string                { return []string{"tee"} }
func (Tee) Parse(a []string) ParsedCommand { return Spec{}.Parse(a) }
func (Tee) builtin()                       {}
func (Tee) FileChanges(p ParsedCommand) []FileChange {
	var cs []FileChange
	for _, o := range p.Operands {
		cs = append(cs, FileChange{Op: FileWrite, Path: o})
	}
	return cs
}
func (t Tee) Resources(p ParsedCommand) []Resource {
	rs := []Resource{streamResource("stdin", "read")}
	rs = append(rs, changeResources(t.FileChanges(p))...)
	return append(rs, streamResource("stdout", "write"))
}

// Unzip extracts ARCHIVE [MEMBER…] into -d DIR (default the cwd).
type Unzip struct{}

var unzipSpec = Spec{ValueFlags: NewSet("-d", "-x", "-P")}

func (Unzip) Names() []string                { return []string{"unzip"} }
func (Unzip) Parse(a []string) ParsedCommand { return unzipSpec.Parse(a) }
func (Unzip) builtin()                       {}
func (Unzip) SecretFlags() []string          { return []string{"-P"} } // archive password
func (Unzip) FileChanges(p ParsedCommand) []FileChange {
	if len(p.Operands) == 0 || p.HasFlag("-l", "-t", "-z") { // list / test only
		return nil
	}
	dest, ok := p.FlagValue("-d")
	if !ok || dest == "" {
		dest = "."
	}
	return []FileChange{{Op: FileExtract, From: p.Operands[0], Path: dest, Recursive: true}}
}
func (u Unzip) Resources(p ParsedCommand) []Resource {
	if len(p.Operands) == 0 {
		return nil
	}
	rs := []Resource{{Kind: "archive", Action: "read", Value: p.Operands[0]}}
	return append(rs, changeResources(u.FileChanges(p))...)
}

// Compress covers gzip/bzip2/xz/zstd and their un* forms: by default the input
// file is replaced by its (de)compressed sibling; -c streams instead; -k keeps.
type Compress struct{}

var compressExt = map[string]string{"gzip": ".gz", "bzip2": ".bz2", "xz": ".xz", "zstd": ".zst", "lz4": ".lz4"}

func (Compress) Names() []string {
	return []string{"gzip", "gunzip", "bzip2", "bunzip2", "xz", "unxz", "zstd", "unzstd", "lz4", "unlz4"}
}
func (Compress) Parse(a []string) ParsedCommand {
	return Spec{ClusterShort: true, ValueFlags: NewSet("-S", "--suffix", "-T", "--threads")}.Parse(a)
}
func (Compress) builtin() {}
func (Compress) FileChanges(p ParsedCommand) []FileChange {
	if len(p.Operands) == 0 || p.HasFlag("-c", "--stdout", "--to-stdout", "-t", "--test", "-l", "--list") {
		return nil
	}
	tool := strings.TrimPrefix(strings.TrimPrefix(p.Name, "un"), "g")
	if p.Name == "gunzip" || p.Name == "gzip" {
		tool = "gzip"
	}
	ext := compressExt[tool]
	decompress := strings.HasPrefix(p.Name, "un") || p.Name == "gunzip" || p.HasFlag("-d", "--decompress", "--uncompress")
	var cs []FileChange
	for _, f := range p.Operands {
		out := f + ext
		if decompress {
			out = strings.TrimSuffix(f, ext)
		}
		cs = append(cs, FileChange{Op: FileWrite, From: f, Path: out})
		if !p.HasFlag("-k", "--keep") {
			cs = append(cs, FileChange{Op: FileDelete, Path: f})
		}
	}
	return cs
}
func (c Compress) Resources(p ParsedCommand) []Resource {
	if cs := c.FileChanges(p); len(cs) > 0 {
		return changeResources(cs)
	}
	rs := filesOrStdin(p.Operands)
	return append(rs, streamResource("stdout", "write"))
}

// Dd copies if= to of= (key=value operands, not flags). of= may be a device.
type Dd struct{}

func (Dd) Names() []string                { return []string{"dd"} }
func (Dd) Parse(a []string) ParsedCommand { return Spec{}.Parse(a) }
func (Dd) builtin()                       {}
func ddOperand(p ParsedCommand, key string) string {
	for _, o := range p.Operands {
		if v, ok := strings.CutPrefix(o, key+"="); ok {
			return v
		}
	}
	return ""
}
func (Dd) FileChanges(p ParsedCommand) []FileChange {
	if of := ddOperand(p, "of"); of != "" {
		return []FileChange{{Op: FileWrite, From: ddOperand(p, "if"), Path: of}}
	}
	return nil
}
func (d Dd) Resources(p ParsedCommand) []Resource {
	var rs []Resource
	if in := ddOperand(p, "if"); in != "" {
		rs = append(rs, Resource{Kind: "path", Action: "read", Value: in})
	} else {
		rs = append(rs, streamResource("stdin", "read"))
	}
	if cs := d.FileChanges(p); len(cs) > 0 {
		return append(rs, changeResources(cs)...)
	}
	return append(rs, streamResource("stdout", "write"))
}

// Tar and Sed are Builtins with Describers elsewhere; their changes are the
// extracted tree / written archive, and the files edited in place.
func (Tar) FileChanges(p ParsedCommand) []FileChange {
	f, _ := p.FirstValue("-f", "--file")
	dir, hasDir := p.FirstValue("-C", "--directory")
	if !hasDir {
		dir = "."
	}
	switch {
	case p.HasFlag("-x", "--extract", "--get"):
		return []FileChange{{Op: FileExtract, From: f, Path: dir, Recursive: true}}
	case p.HasFlag("-c", "--create", "-r", "-u") && f != "" && f != "-":
		return []FileChange{{Op: FileWrite, Path: f}}
	}
	return nil
}

func (Sed) FileChanges(p ParsedCommand) []FileChange {
	if !p.HasFlag("-i", "--in-place") {
		return nil
	}
	files := p.Operands
	if !p.HasFlag("-e", "--expression", "-f", "--file") && len(files) > 0 {
		files = files[1:]
	}
	var cs []FileChange
	for _, f := range files {
		cs = append(cs, FileChange{Op: FileWrite, Path: f})
	}
	return cs
}

// Rsync and Scp write their local destination.
func (Rsync) FileChanges(p ParsedCommand) []FileChange {
	return transferChanges(rsyncParamsFrom(p).Paths, true)
}
func (Scp) FileChanges(p ParsedCommand) []FileChange {
	return transferChanges(scpParamsFrom(p).Paths, p.HasFlag("-r"))
}

func transferChanges(paths []string, rec bool) []FileChange {
	if len(paths) < 2 {
		return nil
	}
	dest := paths[len(paths)-1]
	if _, remote := remoteOperand([]string{dest}); remote {
		return nil
	}
	return []FileChange{{Op: FileCopy, From: strings.Join(paths[:len(paths)-1], " "), Path: dest, Recursive: rec}}
}

// fileTool / transferTool are shorthands for the registry.
func fileTool(op FileOp, recursive []string, names ...string) FileTool {
	return FileTool{Aliases: names, Spec: Spec{ClusterShort: true}, Op: op, RecursiveFlags: recursive}
}

func transferTool(op FileOp, recursive []string, names ...string) TransferTool {
	return TransferTool{Aliases: names, Spec: Spec{ClusterShort: true, ValueFlags: NewSet("-t", "--target-directory", "-S", "--suffix")},
		Op: op, RecursiveFlags: recursive, TargetDirFlags: []string{"-t", "--target-directory"}}
}

var fileCommands = []Builtin{
	fileTool(FileDelete, []string{"-r", "-R", "--recursive"}, "rm"),
	fileTool(FileDelete, nil, "rmdir"),
	fileTool(FileCreate, nil, "mkdir"),
	fileTool(FileTouch, nil, "touch"),
	FileTool{Aliases: names("truncate"), Spec: Spec{ValueFlags: NewSet("-s", "--size", "-r", "--reference")}, Op: FileWrite},
	FileTool{Aliases: names("shred"), Spec: Spec{ClusterShort: true, ValueFlags: NewSet("-n", "--iterations", "-s", "--size")}, Op: FileDelete},
	transferTool(FileMove, nil, "mv"),
	transferTool(FileCopy, []string{"-r", "-R", "-a", "--recursive", "--archive"}, "cp"),
	transferTool(FileLink, nil, "ln"),
	Mktemp{}, Tee{}, Unzip{}, Compress{}, Dd{},
}
