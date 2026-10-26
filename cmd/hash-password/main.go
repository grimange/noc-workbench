// hash-password accepts a single password line on standard input, never argv.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if err := hash(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func hash(input io.Reader, output io.Writer) error {
	line, err := bufio.NewReader(io.LimitReader(input, 1024)).ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("cannot read password")
	}
	password := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if len(password) < 12 || len(password) > 72 {
		return fmt.Errorf("password must contain 12 through 72 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return fmt.Errorf("cannot hash password")
	}
	_, err = fmt.Fprintln(output, string(hash))
	return err
}
