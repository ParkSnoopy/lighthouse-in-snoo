package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// ExitError signals a non-zero exit code after diagnostics have been printed.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit status %d", e.Code)
}

func (e *ExitError) Unwrap() error {
	return e.Err
}

// ValueKind identifies the typed parsing mode of an Option.
type ValueKind int

const (
	KindString ValueKind = iota
	KindBool
	KindDuration
)

// Option defines a CLI flag accepting --long, -long, and optional -s / --s forms.
type Option struct {
	Long      string
	Short     rune
	ValueName string
	ShortHelp string
	LongHelp  string
	EnvVar    string
	Default   string
	Required  bool
	Kind      ValueKind

	strDst  *string
	boolDst *bool
	durDst  *time.Duration
	isSet   bool
}

// Command defines a CLI command or nested subcommand.
type Command struct {
	Name        string
	Version     string
	ShortAbout  string
	LongAbout   string
	Examples    []string
	Options     []*Option
	Subcommands []*Command
	Run         func(ctx *Context) error

	parent *Command
}

// Context provides IO streams and parsed positional arguments to a Command handler.
type Context struct {
	Command *Command
	Args    []string
	Stdout  io.Writer
	Stderr  io.Writer
}

// StringOpt binds a string option to dst and registers it on c.
func (c *Command) StringOpt(dst *string, opt Option) *Option {
	opt.Kind = KindString
	opt.strDst = dst
	if opt.ValueName == "" {
		opt.ValueName = "VALUE"
	}
	o := &opt
	c.Options = append(c.Options, o)
	return o
}

// BoolOpt binds a boolean flag to dst and registers it on c.
func (c *Command) BoolOpt(dst *bool, opt Option) *Option {
	opt.Kind = KindBool
	opt.boolDst = dst
	o := &opt
	c.Options = append(c.Options, o)
	return o
}

// DurationOpt binds a time.Duration option to dst and registers it on c.
func (c *Command) DurationOpt(dst *time.Duration, opt Option) *Option {
	opt.Kind = KindDuration
	opt.durDst = dst
	if opt.ValueName == "" {
		opt.ValueName = "DURATION"
	}
	o := &opt
	c.Options = append(c.Options, o)
	return o
}

// AddSubcommand attaches sub under c.
func (c *Command) AddSubcommand(sub *Command) {
	sub.parent = c
	c.Subcommands = append(c.Subcommands, sub)
}

// Execute parses args against the command tree, renders clap-like help or diagnostics,
// and runs the resolved command. Returns nil on success (including --help/--version)
// or an *ExitError on usage/parse/runtime errors.
func (c *Command) Execute(args []string, stdout, stderr io.Writer) error {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	c.linkParents()
	return c.exec(args, stdout, stderr)
}

func (c *Command) linkParents() {
	for _, sub := range c.Subcommands {
		sub.parent = c
		sub.linkParents()
	}
}

func (c *Command) fullPath() string {
	var parts []string
	for cur := c; cur != nil; cur = cur.parent {
		parts = append(parts, cur.Name)
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, " ")
}

func (c *Command) exec(args []string, stdout, stderr io.Writer) error {
	// Dispatch to subcommand if this command owns subcommands.
	if len(c.Subcommands) > 0 {
		if len(args) == 0 {
			RenderHelp(stderr, c, false)
			return &ExitError{Code: 2}
		}

		first := args[0]
		switch first {
		case "-h", "--h":
			RenderHelp(stdout, c, false)
			return nil
		case "--help", "-help":
			RenderHelp(stdout, c, true)
			return nil
		case "-V", "--V", "--version", "-version":
			if c.Version != "" {
				fmt.Fprintf(stdout, "%s %s\n", c.Name, c.Version)
				return nil
			}
		case "help":
			target, err := c.resolveHelpTarget(args[1:])
			if err != nil {
				c.printUsageError(stderr, err.Error(), "")
				return &ExitError{Code: 2, Err: err}
			}
			RenderHelp(stdout, target, true)
			return nil
		}

		if sub := c.findSubcommand(first); sub != nil {
			return sub.exec(args[1:], stdout, stderr)
		}

		if strings.HasPrefix(first, "-") {
			msg := fmt.Sprintf("unexpected argument '%s' found", first)
			c.printUsageError(stderr, msg, "")
			return &ExitError{Code: 2, Err: errors.New(msg)}
		}

		msg := fmt.Sprintf("unrecognized subcommand '%s'", first)
		tip := ""
		if suggestion := suggestSubcommand(first, c.Subcommands); suggestion != "" {
			tip = fmt.Sprintf("a similar subcommand exists: '%s'", suggestion)
		}
		c.printUsageError(stderr, msg, tip)
		return &ExitError{Code: 2, Err: errors.New(msg)}
	}

	// Leaf command: parse flags (accepting both -- and - for all options).
	posArgs, helpMode, versionHit, err := c.parseLeafArgs(args, stderr)
	if err != nil {
		return err
	}
	if helpMode == helpShort {
		RenderHelp(stdout, c, false)
		return nil
	}
	if helpMode == helpLong {
		RenderHelp(stdout, c, true)
		return nil
	}
	if versionHit {
		root := c
		for root.parent != nil {
			root = root.parent
		}
		fmt.Fprintf(stdout, "%s %s\n", root.Name, root.Version)
		return nil
	}

	if c.Run == nil {
		RenderHelp(stdout, c, true)
		return nil
	}
	if err := c.Run(&Context{
		Command: c,
		Args:    posArgs,
		Stdout:  stdout,
		Stderr:  stderr,
	}); err != nil {
		var exitErr *ExitError
		if errors.As(err, &exitErr) {
			return exitErr
		}
		return &ExitError{Code: 1, Err: err}
	}
	return nil
}

type helpRequest int

const (
	helpNone helpRequest = iota
	helpShort
	helpLong
)

func (c *Command) parseLeafArgs(args []string, stderr io.Writer) ([]string, helpRequest, bool, error) {
	// Initialize defaults and environment fallbacks first.
	for _, opt := range c.Options {
		opt.isSet = false
		if opt.EnvVar != "" {
			if envVal, ok := os.LookupEnv(opt.EnvVar); ok && envVal != "" {
				if err := opt.applyValue(envVal); err != nil {
					msg := fmt.Sprintf("invalid value '%s' from env '%s' for '%s': %v", envVal, opt.EnvVar, opt.displayRef(), err)
					c.printUsageError(stderr, msg, "")
					return nil, helpNone, false, &ExitError{Code: 2, Err: errors.New(msg)}
				}
				opt.isSet = true
				continue
			}
		}
		if opt.Default != "" {
			if err := opt.applyValue(opt.Default); err != nil {
				return nil, helpNone, false, &ExitError{Code: 2, Err: err}
			}
		} else if opt.Kind == KindBool && opt.boolDst != nil {
			*opt.boolDst = false
		} else if opt.Kind == KindString && opt.strDst != nil {
			*opt.strDst = ""
		} else if opt.Kind == KindDuration && opt.durDst != nil {
			*opt.durDst = 0
		}
	}

	var positional []string
	endOfFlags := false

	for i := 0; i < len(args); i++ {
		tok := args[i]
		if endOfFlags {
			positional = append(positional, tok)
			continue
		}
		if tok == "--" {
			endOfFlags = true
			continue
		}
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			positional = append(positional, tok)
			continue
		}

		// Strip either "--" or "-" prefix so every option works identically with both!
		raw := strings.TrimPrefix(tok, "--")
		if len(raw) == len(tok) {
			raw = strings.TrimPrefix(tok, "-")
		}

		name := raw
		hasEq := false
		eqVal := ""
		if eqIdx := strings.IndexByte(raw, '='); eqIdx >= 0 {
			name = raw[:eqIdx]
			eqVal = raw[eqIdx+1:]
			hasEq = true
		}

		// Built-in help & version flags.
		if !hasEq {
			switch name {
			case "help":
				return nil, helpLong, false, nil
			case "h":
				return nil, helpShort, false, nil
			case "version", "V":
				if c.hasVersion() {
					return nil, helpNone, true, nil
				}
			}
		}

		// 1. Exact long name match (works for both --flag and -flag).
		opt := c.findByLong(name)
		// 2. Exact single-rune short alias match (works for -s and --s).
		if opt == nil && len([]rune(name)) == 1 {
			opt = c.findByShort([]rune(name)[0])
		}
		// 3. Single-dash attached short value (e.g. -pfile.json) or bundled short booleans (-gu).
		if opt == nil && !strings.HasPrefix(tok, "--") && len([]rune(name)) > 1 {
			runes := []rune(name)
			if firstOpt := c.findByShort(runes[0]); firstOpt != nil {
				if firstOpt.Kind != KindBool && !hasEq {
					opt = firstOpt
					hasEq = true
					eqVal = string(runes[1:])
				} else if !hasEq && c.allShortBools(runes) {
					for _, r := range runes {
						bOpt := c.findByShort(r)
						_ = bOpt.applyValue("true")
						bOpt.isSet = true
					}
					continue
				}
			}
		}

		if opt == nil {
			msg := fmt.Sprintf("unexpected argument '%s' found", tok)
			tip := ""
			if suggestion := suggestOption(name, c.Options); suggestion != "" {
				tip = fmt.Sprintf("a similar argument exists: '--%s'", suggestion)
			}
			c.printUsageError(stderr, msg, tip)
			return nil, helpNone, false, &ExitError{Code: 2, Err: errors.New(msg)}
		}

		if opt.Kind == KindBool {
			val := "true"
			if hasEq {
				val = eqVal
			}
			if err := opt.applyValue(val); err != nil {
				msg := fmt.Sprintf("invalid value '%s' for '%s': %v", val, opt.displayRef(), err)
				c.printUsageError(stderr, msg, "")
				return nil, helpNone, false, &ExitError{Code: 2, Err: errors.New(msg)}
			}
			opt.isSet = true
			continue
		}

		var val string
		if hasEq {
			val = eqVal
		} else {
			if i+1 >= len(args) {
				msg := fmt.Sprintf("a value is required for '%s' but none was supplied", opt.displayRef())
				c.printUsageError(stderr, msg, "")
				return nil, helpNone, false, &ExitError{Code: 2, Err: errors.New(msg)}
			}
			i++
			val = args[i]
		}

		if err := opt.applyValue(val); err != nil {
			msg := fmt.Sprintf("invalid value '%s' for '%s': %v", val, opt.displayRef(), err)
			c.printUsageError(stderr, msg, "")
			return nil, helpNone, false, &ExitError{Code: 2, Err: errors.New(msg)}
		}
		opt.isSet = true
	}

	// Enforce required flags.
	var missing []string
	for _, opt := range c.Options {
		if opt.Required && !opt.isSet {
			missing = append(missing, opt.displayRef())
		}
	}
	if len(missing) > 0 {
		var sb strings.Builder
		sb.WriteString("the following required arguments were not provided:\n")
		for _, m := range missing {
			sb.WriteString("  ")
			sb.WriteString(m)
			sb.WriteByte('\n')
		}
		c.printUsageError(stderr, strings.TrimRight(sb.String(), "\n"), "")
		return nil, helpNone, false, &ExitError{Code: 2, Err: errors.New("missing required arguments")}
	}

	if len(positional) > 0 {
		msg := fmt.Sprintf("unexpected argument '%s' found", positional[0])
		c.printUsageError(stderr, msg, "")
		return nil, helpNone, false, &ExitError{Code: 2, Err: errors.New(msg)}
	}

	return positional, helpNone, false, nil
}

func (o *Option) applyValue(raw string) error {
	switch o.Kind {
	case KindString:
		if o.strDst != nil {
			*o.strDst = raw
		}
		return nil
	case KindBool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("expected boolean (true/false)")
		}
		if o.boolDst != nil {
			*o.boolDst = b
		}
		return nil
	case KindDuration:
		d, err := time.ParseDuration(raw)
		if err != nil {
			return err
		}
		if o.durDst != nil {
			*o.durDst = d
		}
		return nil
	default:
		return fmt.Errorf("unsupported option kind")
	}
}

func (o *Option) displayRef() string {
	if o.Kind == KindBool {
		return "--" + o.Long
	}
	return fmt.Sprintf("--%s <%s>", o.Long, o.ValueName)
}

func (c *Command) hasVersion() bool {
	for cur := c; cur != nil; cur = cur.parent {
		if cur.Version != "" {
			return true
		}
	}
	return false
}

func (c *Command) findSubcommand(name string) *Command {
	for _, sub := range c.Subcommands {
		if sub.Name == name {
			return sub
		}
	}
	return nil
}

func (c *Command) resolveHelpTarget(path []string) (*Command, error) {
	cur := c
	for _, seg := range path {
		next := cur.findSubcommand(seg)
		if next == nil {
			return nil, fmt.Errorf("unrecognized subcommand '%s'", seg)
		}
		cur = next
	}
	return cur, nil
}

func (c *Command) findByLong(name string) *Option {
	for _, opt := range c.Options {
		if opt.Long == name {
			return opt
		}
	}
	return nil
}

func (c *Command) findByShort(r rune) *Option {
	for _, opt := range c.Options {
		if opt.Short != 0 && opt.Short == r {
			return opt
		}
	}
	return nil
}

func (c *Command) allShortBools(runes []rune) bool {
	for _, r := range runes {
		opt := c.findByShort(r)
		if opt == nil || opt.Kind != KindBool {
			return false
		}
	}
	return true
}

func (c *Command) printUsageError(w io.Writer, msg, tip string) {
	fmt.Fprintf(w, "error: %s\n", msg)
	if tip != "" {
		fmt.Fprintf(w, "\n  tip: %s\n", tip)
	}
	fmt.Fprintf(w, "\nUsage: %s\n", c.usageLine())
	fmt.Fprintln(w, "\nFor more information, try '--help'.")
}

func suggestSubcommand(input string, subs []*Command) string {
	best := ""
	bestDist := 3
	for _, s := range subs {
		if d := levenshtein(input, s.Name); d < bestDist {
			bestDist = d
			best = s.Name
		}
	}
	return best
}

func suggestOption(input string, opts []*Option) string {
	best := ""
	bestDist := 3
	for _, o := range opts {
		if d := levenshtein(input, o.Long); d < bestDist {
			bestDist = d
			best = o.Long
		}
	}
	return best
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	if len(ra) == 0 {
		return len(rb)
	}
	if len(rb) == 0 {
		return len(ra)
	}
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}
	return prev[len(rb)]
}
