package common

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestProcessNameMatchesName(t *testing.T) {
	rule, err := NewProcess("ChatGPT", "DIRECT", C.ProcessName)
	if err != nil {
		t.Fatal(err)
	}

	matched, adapter := rule.Match(&C.Metadata{
		Process:     "ChatGPT",
		ProcessPath: "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT",
	}, C.RuleMatchHelper{})
	if !matched {
		t.Fatal("expected process name to match executable name")
	}
	if adapter != "DIRECT" {
		t.Fatalf("expected adapter DIRECT, got %s", adapter)
	}
}

func TestProcessNameMatchesAbsolutePath(t *testing.T) {
	rule, err := NewProcess("/Applications/ChatGPT.app/Contents/MacOS/ChatGPT Helper", "DIRECT", C.ProcessName)
	if err != nil {
		t.Fatal(err)
	}

	matched, _ := rule.Match(&C.Metadata{
		Process:     "ChatGPT Helper",
		ProcessPath: "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT Helper",
	}, C.RuleMatchHelper{})
	if !matched {
		t.Fatal("expected process name rule with an absolute path to match process path")
	}
}

func TestProcessNameMatchesAppBundlePrefix(t *testing.T) {
	rule, err := NewProcess("/Applications/ChatGPT.app/", "DIRECT", C.ProcessName)
	if err != nil {
		t.Fatal(err)
	}

	matched, _ := rule.Match(&C.Metadata{
		Process:     "ChatGPT Helper",
		ProcessPath: "/Applications/ChatGPT.app/Contents/Frameworks/ChatGPT Helper.app/Contents/MacOS/ChatGPT Helper",
	}, C.RuleMatchHelper{})
	if !matched {
		t.Fatal("expected trailing slash process name rule to match app bundle prefix")
	}
}

func TestProcessNameAppBundlePrefixDoesNotMatchSiblingPath(t *testing.T) {
	rule, err := NewProcess("/Applications/ChatGPT.app/", "DIRECT", C.ProcessName)
	if err != nil {
		t.Fatal(err)
	}

	matched, _ := rule.Match(&C.Metadata{
		Process:     "Other",
		ProcessPath: "/Applications/ChatGPT.app.evil/Contents/MacOS/Other",
	}, C.RuleMatchHelper{})
	if matched {
		t.Fatal("expected app bundle prefix rule not to match sibling path")
	}
}

func TestProcessPathExactMatchUnchanged(t *testing.T) {
	rule, err := NewProcess("/Applications/ChatGPT.app/", "DIRECT", C.ProcessPath)
	if err != nil {
		t.Fatal(err)
	}

	matched, _ := rule.Match(&C.Metadata{
		Process:     "ChatGPT",
		ProcessPath: "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT",
	}, C.RuleMatchHelper{})
	if matched {
		t.Fatal("expected process path rule to keep exact-match semantics")
	}
}
