package cli

import (
	"fmt"
	"io"
	"strings"
)

// RenderHelp writes clap-style short (-h) or verbose (--help) help output for c.
func RenderHelp(w io.Writer, c *Command, verbose bool) {
	about := c.ShortAbout
	if verbose && c.LongAbout != "" {
		about = c.LongAbout
	}
	if about != "" {
		fmt.Fprintln(w, about)
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "Usage: %s\n", c.usageLine())

	if len(c.Subcommands) > 0 {
		fmt.Fprintln(w, "\nCommands:")
		maxName := len("help")
		for _, sub := range c.Subcommands {
			if len(sub.Name) > maxName {
				maxName = len(sub.Name)
			}
		}
		for _, sub := range c.Subcommands {
			fmt.Fprintf(w, "  %-*s  %s\n", maxName, sub.Name, sub.ShortAbout)
		}
		fmt.Fprintf(w, "  %-*s  %s\n", maxName, "help", "Print this message or the help of the given subcommand(s)")
	}

	fmt.Fprintln(w, "\nOptions:")
	if verbose {
		renderVerboseOptions(w, c)
	} else {
		renderCompactOptions(w, c)
	}

	if verbose && len(c.Examples) > 0 {
		fmt.Fprintln(w, "\nExamples:")
		for _, ex := range c.Examples {
			fmt.Fprintf(w, "  %s\n", ex)
		}
	}
}

func (c *Command) usageLine() string {
	path := c.fullPath()
	if len(c.Subcommands) > 0 {
		return path + " <COMMAND>"
	}
	var parts []string
	parts = append(parts, path)
	hasOptional := false
	for _, opt := range c.Options {
		if opt.Required {
			parts = append(parts, opt.displayRef())
		} else {
			hasOptional = true
		}
	}
	if hasOptional {
		parts = append(parts, "[OPTIONS]")
	}
	return strings.Join(parts, " ")
}

type renderedOpt struct {
	spec string
	desc string
	meta []string
}

func buildOptionRows(c *Command, verbose bool) []renderedOpt {
	rows := make([]renderedOpt, 0, len(c.Options)+2)
	for _, opt := range c.Options {
		spec := formatOptSpec(opt)
		desc := opt.ShortHelp
		if verbose && opt.LongHelp != "" {
			desc = opt.LongHelp
		}
		var meta []string
		if opt.Required {
			meta = append(meta, "[required]")
		}
		if opt.EnvVar != "" {
			meta = append(meta, fmt.Sprintf("[env: %s]", opt.EnvVar))
		}
		if opt.Default != "" {
			meta = append(meta, fmt.Sprintf("[default: %s]", opt.Default))
		}
		rows = append(rows, renderedOpt{spec: spec, desc: desc, meta: meta})
	}

	helpDesc := "Print help (see more with '--help')"
	if verbose {
		helpDesc = "Print help (see a summary with '-h')"
	}
	rows = append(rows, renderedOpt{
		spec: "-h, --help",
		desc: helpDesc,
	})
	if c.Version != "" {
		rows = append(rows, renderedOpt{
			spec: "-V, --version",
			desc: "Print version",
		})
	}
	return rows
}

func formatOptSpec(opt *Option) string {
	var sb strings.Builder
	if opt.Short != 0 {
		sb.WriteString(fmt.Sprintf("-%c, ", opt.Short))
	} else {
		sb.WriteString("    ")
	}
	sb.WriteString("--")
	sb.WriteString(opt.Long)
	if opt.Kind != KindBool {
		sb.WriteString(" <")
		sb.WriteString(opt.ValueName)
		sb.WriteByte('>')
	}
	return sb.String()
}

func renderCompactOptions(w io.Writer, c *Command) {
	rows := buildOptionRows(c, false)
	maxSpec := 0
	for _, r := range rows {
		if len(r.spec) > maxSpec {
			maxSpec = len(r.spec)
		}
	}
	for _, r := range rows {
		tail := r.desc
		if len(r.meta) > 0 {
			if tail != "" {
				tail += " "
			}
			tail += strings.Join(r.meta, " ")
		}
		fmt.Fprintf(w, "  %-*s  %s\n", maxSpec, r.spec, tail)
	}
}

func renderVerboseOptions(w io.Writer, c *Command) {
	rows := buildOptionRows(c, true)
	for i, r := range rows {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "  %s\n", r.spec)
		if r.desc != "" {
			for _, line := range strings.Split(r.desc, "\n") {
				fmt.Fprintf(w, "          %s\n", line)
			}
		}
		for _, m := range r.meta {
			fmt.Fprintf(w, "          %s\n", m)
		}
	}
}
