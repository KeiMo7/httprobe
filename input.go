package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// inputIssue describes a problem found while reading the target list. Line is
// 1-based and is the only location information reported; the line content is
// deliberately never echoed because it may contain a target address.
type inputIssue struct {
	Line int
	Err  error
}

func (i inputIssue) Error() string {
	return fmt.Sprintf("line %d: %s", i.Line, i.Err)
}

const maxInputLineBytes = 1 << 20 // 1 MiB per domain line

// readDomains reads line-delimited domains from r. It returns the domains it
// successfully read plus an issue for every line that could not be used, so a
// malformed or unreadable line is reported at its position instead of being
// silently skipped.
func readDomains(r io.Reader, maxLine int) ([]string, []inputIssue) {
	if maxLine < 1 {
		maxLine = maxInputLineBytes
	}
	br := bufio.NewReaderSize(r, 64*1024)

	var domains []string
	var issues []inputIssue
	lineNo := 0

	for {
		line, err := br.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			if lineNo == 0 {
				lineNo = 1
			}
			issues = append(issues, inputIssue{Line: lineNo, Err: fmt.Errorf("read failed: %w", err)})
			return domains, issues
		}
		if len(line) > 0 {
			lineNo++
		}

		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimPrefix(trimmed, "\ufeff")

		switch {
		case len(line) > maxLine:
			issues = append(issues, inputIssue{Line: lineNo, Err: fmt.Errorf("line exceeds %d bytes", maxLine)})
		case trimmed != "":
			domains = append(domains, trimmed)
		}

		if errors.Is(err, io.EOF) {
			return domains, issues
		}
	}
}
