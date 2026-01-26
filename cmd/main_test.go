package main

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"os"

	"github.com/stretchr/testify/require"
)

const (
	TPMB = "127.0.0.1:2321"
)

func TestMain(t *testing.T) {

	tempDirB := t.TempDir()
	for _, tc := range []struct {
		Name        string
		Args        []string
		Output      string
		ExpectError bool
	}{
		{
			Name:        "seal",
			Args:        []string{"--mode=seal", "--parentKeyType=h2", "--secret=\"data to seal\"", fmt.Sprintf("--out=%s/private.pem", tempDirB), fmt.Sprintf("-tpm-path=%s", TPMB)},
			Output:      "",
			ExpectError: false,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {

			// Create a pipe
			oldStdout := os.Stdout
			r, w, err := os.Pipe()
			require.NoError(t, err)
			os.Stdout = w

			// Restore stdout after the test
			defer func() {
				os.Stdout = oldStdout
			}()
			oldArgs := os.Args
			defer func() { os.Args = oldArgs }()

			os.Args = append(os.Args, tc.Args...)

			exitVal := run()

			err = w.Close()
			require.NoError(t, err)

			var buf bytes.Buffer
			_, err = io.Copy(&buf, r)
			require.NoError(t, err)
			if tc.ExpectError {
				require.Equal(t, 1, exitVal)
			} else {
				require.Equal(t, 0, exitVal)
			}

			require.Equal(t, tc.Output, buf.String())

			os.Stdout = oldStdout
			os.Args = oldArgs

		})
	}
}
