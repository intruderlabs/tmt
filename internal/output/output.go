// Package output provides colored, TTY-aware console output for TMT.
package output

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

var (
	step    = color.New(color.FgCyan)
	info    = color.New(color.FgWhite)
	success = color.New(color.FgGreen, color.Bold)
	warn    = color.New(color.FgYellow)
	errC    = color.New(color.FgRed, color.Bold)
	bold    = color.New(color.Bold)
)

// Banner returns the TMT startup banner: an ANSI-Shadow "TMT" with a vertical
// magenta→indigo 256-color gradient. Falls back to plain text when color is
// off (fatih/color already honors NO_COLOR and non-TTY output).
func Banner() string {
	art := []string{
		"████████╗███╗   ███╗████████╗",
		"╚══██╔══╝████╗ ████║╚══██╔══╝",
		"   ██║   ██╔████╔██║   ██║   ",
		"   ██║   ██║╚██╔╝██║   ██║   ",
		"   ██║   ██║ ╚═╝ ██║   ██║   ",
		"   ╚═╝   ╚═╝     ╚═╝   ╚═╝   ",
	}
	shades := []int{171, 135, 135, 99, 63, 63}
	var b strings.Builder
	b.WriteByte('\n')
	for i, line := range art {
		if color.NoColor {
			b.WriteString(line + "\n")
			continue
		}
		fmt.Fprintf(&b, "\x1b[38;5;%dm%s\x1b[0m\n", shades[i], line)
	}
	if color.NoColor {
		b.WriteString("Target My Target · AWS API Gateway reverse proxy for security testing\n")
	} else {
		b.WriteString("\x1b[38;5;141mTarget My Target\x1b[0m \x1b[2m· AWS API Gateway reverse proxy for security testing\x1b[0m\n")
	}
	return b.String()
}

func Step(format string, a ...any)    { step.Printf(format+"\n", a...) }
func Info(format string, a ...any)    { info.Printf(format+"\n", a...) }
func Success(format string, a ...any) { success.Printf(format+"\n", a...) }
func Warn(format string, a ...any)    { warn.Printf(format+"\n", a...) }
func Error(format string, a ...any)   { errC.Fprintf(os.Stderr, format+"\n", a...) }

// Confirm prints prompt and reads a y/N answer from stdin. It returns true
// only if the user answers "y" or "yes" (case-insensitive).
func Confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

const divider = "=========================================="

// UpSummary prints the boxed summary shown after a successful "up".
func UpSummary(apiName, apiID, region, target, endpoint string) {
	fmt.Println()
	bold.Println(divider)
	bold.Println(" PROXY ACTIVE")
	bold.Println(divider)
	fmt.Printf(" API Name: %s\n", apiName)
	fmt.Printf(" API ID:   %s\n", apiID)
	fmt.Printf(" Region:   %s\n", region)
	fmt.Printf(" Target:   %s\n", target)
	fmt.Printf(" Endpoint: %s\n", endpoint)
	bold.Println(divider)
	fmt.Println()
	fmt.Println("Example usage:")
	fmt.Printf("  curl -H 'Authorization: token' '%s/path/on/target'\n", endpoint)
	fmt.Println()
	fmt.Println("To tear it down:")
	fmt.Printf("  tmt down -ak '***' -sk '***' -t '%s' -r '%s'\n", target, region)
}

// JumpSummary prints the boxed summary shown after the jump-host pool is up
// and the local MITM proxy is listening. It hands the user the ready-to-paste
// -proxy line for their scanning tool.
func JumpSummary(port int, regions []string) {
	fmt.Println()
	bold.Println(divider)
	bold.Println(" JUMP PROXY ACTIVE")
	bold.Println(divider)
	fmt.Printf(" Regions:  %s\n", strings.Join(regions, ", "))
	fmt.Printf(" Listen:   http://127.0.0.1:%d\n", port)
	bold.Println(divider)
	fmt.Println()
	fmt.Println("Point your tool at the proxy (outbound calls rotate across regions):")
	fmt.Printf("  nuclei -u https://target.example.com -proxy http://127.0.0.1:%d\n", port)
	fmt.Println()
	fmt.Println("Leave this running. Ctrl-C tears the pool down.")
}

// DownSummary prints the boxed summary shown after a successful "down".
func DownSummary(apiName, apiID, region, target string) {
	fmt.Println()
	bold.Println(divider)
	bold.Println(" PROXY REMOVED")
	bold.Println(divider)
	fmt.Printf(" API Name: %s\n", apiName)
	fmt.Printf(" API ID:   %s\n", apiID)
	fmt.Printf(" Region:   %s\n", region)
	fmt.Printf(" Target:   %s\n", target)
	bold.Println(divider)
}
