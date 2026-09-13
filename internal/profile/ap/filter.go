package ap

import (
	"strings"

	"goodkind.io/unifi-go/network"
)

type filterInterfaceReference struct {
	start, end int
	name       string
}

func filterInterfaceReferences(command string) ([]filterInterfaceReference, error) {
	// This parser cannot prove ownership across shell syntax or wildcard selectors.
	if strings.ContainsAny(command, "'\"\\!+*?[]$;|&<>()`") {
		return nil, &network.ControlError{Code: network.BaselineUnusable}
	}
	var references []filterInterfaceReference
	next := false
	for cursor := 0; cursor < len(command); {
		if filterShellWhitespace(command[cursor]) {
			cursor++
			continue
		}
		start := cursor
		if command[start] == '#' {
			return nil, &network.ControlError{Code: network.BaselineUnusable}
		}
		for cursor < len(command) && !filterShellWhitespace(command[cursor]) {
			cursor++
		}
		if !next {
			var prefix int
			prefix, next = filterInterfaceOption(command[start:cursor])
			if prefix == 0 || next {
				continue
			}
			start += prefix
		}
		name := command[start:cursor]
		if name == "" || strings.HasPrefix(name, "-") {
			return nil, &network.ControlError{Code: network.BaselineUnusable}
		}
		references = append(references, filterInterfaceReference{start: start, end: cursor, name: name})
		next = false
	}
	if next {
		return nil, &network.ControlError{Code: network.BaselineUnusable}
	}
	return references, nil
}

func filterShellWhitespace(character byte) bool {
	// Shell words and comments share these boundaries; Unicode whitespace is literal.
	return character == ' ' || character == '\t' || character == '\n'
}

func filterInterfaceOption(word string) (int, bool) {
	for _, option := range []string{"-i", "-o", "--in-interface", "--out-interface"} {
		if word == option {
			return len(word), true
		}
		prefix := option
		if strings.HasPrefix(option, "--") {
			prefix += "="
		}
		if strings.HasPrefix(word, prefix) {
			return len(prefix), false
		}
	}
	return 0, false
}

func rewriteFilterInterface(command, previous, next string) (string, error) {
	references, err := filterInterfaceReferences(command)
	if err != nil {
		return "", err
	}
	var rewritten strings.Builder
	cursor := 0
	for _, reference := range references {
		if reference.name != previous {
			continue
		}
		rewritten.WriteString(command[cursor:reference.start])
		rewritten.WriteString(next)
		cursor = reference.end
	}
	rewritten.WriteString(command[cursor:])
	return rewritten.String(), nil
}
