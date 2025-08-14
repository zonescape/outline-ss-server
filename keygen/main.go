package main

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strings"
	"syscall"

	"github.com/jessevdk/go-flags"
	"github.com/mdp/qrterminal/v3"
	"golang.org/x/term"
)

type Opts struct {
	Address string `long:"addr" required:"true" description:"address of outline-ss-server in host:port form"`
	Cipher  string `long:"cipher" description:"cipher from config.yml" default:"chacha20-ietf-poly1305"`
	Secret  string `long:"secret" env:"SECRET" description:"secret from config.yml. It will be asked via terminal if absent."`
	Prefix  string `long:"prefix" description:"URL encoded obfuscation prefix. Visit https://developers.google.com/outline/docs/guides/service-providers/prefixing for recommended values."`
	QR      bool   `long:"qr" description:"generate QR code"`
}

func main() {
	var opts Opts
	parser := flags.NewParser(&opts, flags.HelpFlag)
	if _, err := parser.Parse(); err != nil {
		fmt.Println(err)
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	if opts.Secret == "" {
		fmt.Print("Secret: ")
		secret, err := term.ReadPassword(syscall.Stdin)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("")
		opts.Secret = string(secret)
	}

	acessKey, err := GetAcessKey(opts)
	if err != nil {
		fmt.Printf("can't generate access key: %v\n", err)
		os.Exit(1)
	}

	if opts.QR {
		qrterminal.GenerateHalfBlock(acessKey, qrterminal.M, os.Stdout)
		return
	}

	fmt.Println(acessKey)
}

func GetAcessKey(opts Opts) (string, error) {
	if opts.Cipher == "" {
		return "", fmt.Errorf("invalid cipher: %q", opts.Cipher)
	}

	if opts.Secret == "" {
		return "", fmt.Errorf("secret is absent")
	}

	userInfo := opts.Cipher + ":" + opts.Secret
	userInfo2 := base64.URLEncoding.EncodeToString([]byte(userInfo))

	if opts.Address == "" {
		return "", fmt.Errorf("invalid address: %q", opts.Address)
	}

	if err := validatePrefix(opts.Prefix); err != nil {
		return "", fmt.Errorf("invalid prefix: %v", err)
	}

	query := "outline=1"
	if opts.Prefix != "" {
		query = "outline=1&prefix=" + opts.Prefix
	}

	acessKey := fmt.Sprintf("ss://%s@%s/?%s",
		userInfo2,
		opts.Address,
		query,
	)

	return acessKey, nil
}

func validatePrefix(prefix string) error {
	if prefix == "" {
		return nil
	}

	prefixPlain, err := url.QueryUnescape(prefix)
	if err != nil {
		return fmt.Errorf("can't unescape prefix: %v", err)
	}

	// the prefix should be no longer than 16 bytes
	// https://developers.google.com/outline/docs/guides/service-providers/prefixing
	if len(prefixPlain) > 16 {
		return fmt.Errorf("prefix length exceeds 16: len = %d", len(prefixPlain))
	}

	prefix2 := encodeURIComponent(prefixPlain)
	if prefix != prefix2 {
		return fmt.Errorf("invalid prefix encoding: %q != %q", prefix, prefix2)
	}

	return nil
}

// encodeURIComponent mimics JS encodeURIComponent.
// Outline's docs say prefix should be "URL-encoded"
// https://developers.google.com/outline/docs/guides/service-providers/prefixing
// "URL encoding" is an opaque term, but the same docs suggest to use JS's encodeURIComponent().
// See also:
// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent
// https://stackoverflow.com/questions/13820280/encode-decode-urls
// https://gist.github.com/czyang/7ae30f4f625fee14cfc40c143e1b78bf
func encodeURIComponent(s string) string {
	s = url.QueryEscape(s)

	s = strings.ReplaceAll(s, "+", "%20")
	s = strings.ReplaceAll(s, "%21", "!")
	s = strings.ReplaceAll(s, "%27", "'")
	s = strings.ReplaceAll(s, "%28", "(")
	s = strings.ReplaceAll(s, "%29", ")")
	s = strings.ReplaceAll(s, "%2A", "*")

	return s
}
