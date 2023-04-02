package traefik_plugin_encrypt

import "os"

func logError(err error, message string) {
	_, _ = os.Stderr.WriteString("traefik-plugin-encrypt error=\"" + err.Error() + "\" msg=\"" + message + "\"\n")
}
