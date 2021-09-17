package getgopass

import (
	"context"
	"fmt"
	gopass "github.com/gopasspw/gopass/pkg/gopass/api"
	"github.com/pkg/errors"
	"os/exec"
	"strings"
)

func checkGpgAgent() error {
	cmd := exec.Command("gpg-connect-agent", "keyinfo --list", "/bye")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(output), "\n") {
		parts := strings.Split(line, " ")
		if len(parts) > 6 && parts[6] == "1" {
			return nil
		}
	}
	return fmt.Errorf("Couldn't find cached GPG key in running GPG agent")
}

func GetPassword(ctx context.Context, name string) (string, error) {
	err := checkGpgAgent()
	if err != nil {
		return "", errors.Wrap(err, "Password couldn't be retrieved as gopass store is locked")
	}
	gp, err := gopass.New(ctx)
	if err != nil {
		return "", err
	}
	secret, err := gp.Get(ctx, name, "")
	if err != nil {
		return "", err
	}
	str := secret.Password()
	return str, nil
}

func Get(ctx context.Context, name string, keyName string) (string, error) {
	err := checkGpgAgent()
	if err != nil {
		return "", errors.Wrap(err, "Password couldn't be retrieved as gopass store is locked")
	}
	gp, err := gopass.New(ctx)
	if err != nil {
		return "", err
	}
	secret, err := gp.Get(ctx, name, "")
	if err != nil {
		return "", err
	}
	str, found := secret.Get(keyName)
	if !found {
		return "", fmt.Errorf("No such key in secret: " + keyName)
	}
	return str, nil
}
