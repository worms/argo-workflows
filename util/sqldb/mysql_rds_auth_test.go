package sqldb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/argoproj/argo-workflows/v4/config"
)

func newMySQLAWSRDSTestConfig(port int, options map[string]string) *config.MySQLConfig {
	return &config.MySQLConfig{
		DatabaseConfig: config.DatabaseConfig{
			Host:     "127.0.0.1",
			Port:     port,
			Database: "argo",
		},
		Options:     options,
		AWSRDSToken: &config.AWSRDSTokenConfig{Enabled: true, Region: "us-east-1"},
	}
}

func TestValidateMySQLAWSRDSTLS(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options map[string]string
		wantErr bool
	}{
		{"tls unset", nil, true},
		{"tls false", map[string]string{"tls": "false"}, true},
		{"tls zero", map[string]string{"tls": "0"}, true},
		{"tls preferred", map[string]string{"tls": "preferred"}, true},
		{"plaintext fallback", map[string]string{"tls": "true", "allowFallbackToPlaintext": "true"}, true},
		{"tls true", map[string]string{"tls": "true"}, false},
		{"tls TRUE", map[string]string{"tls": "TRUE"}, false},
		{"tls one", map[string]string{"tls": "1"}, false},
		{"tls skip-verify", map[string]string{"tls": "skip-verify"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMySQLAWSRDSTLS(newMySQLAWSRDSTestConfig(3306, tc.options))
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBuildMySQLAWSRDSConfig(t *testing.T) {
	cfg := newMySQLAWSRDSTestConfig(3306, map[string]string{"tls": "true"})
	noToken := func(context.Context, string, string, string) (string, error) {
		t.Fatal("token must not be built until a connection is made")
		return "", nil
	}

	mysqlCfg, err := buildMySQLAWSRDSConfig(cfg, "argo", 7*time.Second, noToken)
	require.NoError(t, err)

	assert.Equal(t, "argo", mysqlCfg.User)
	assert.Empty(t, mysqlCfg.Passwd)
	assert.Equal(t, "127.0.0.1:3306", mysqlCfg.Addr)
	assert.Equal(t, "true", mysqlCfg.TLSConfig)
	assert.True(t, mysqlCfg.AllowCleartextPasswords)
	assert.Equal(t, 7*time.Second, mysqlCfg.Timeout)
}

// writeMySQLPacket writes a single MySQL protocol packet.
func writeMySQLPacket(w io.Writer, seq byte, payload []byte) error {
	header := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}
	_, err := w.Write(append(header, payload...))
	return err
}

// readMySQLPacket reads a single MySQL protocol packet and returns its payload.
func readMySQLPacket(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	payload := make([]byte, int(header[0])|int(header[1])<<8|int(header[2])<<16)
	_, err := io.ReadFull(r, payload)
	return payload, err
}

// fakeMySQLHandshake sends a protocol v10 handshake requesting the mysql_clear_password
// auth plugin (as RDS does for IAM users) and returns the client's handshake response.
func fakeMySQLHandshake(conn net.Conn) ([]byte, error) {
	const (
		clientMySQL      = 1 << 0
		clientProtocol41 = 1 << 9
		clientSecureConn = 1 << 15
		clientPluginAuth = 1 << 19
	)
	caps := uint32(clientMySQL | clientProtocol41 | clientSecureConn | clientPluginAuth)
	var p bytes.Buffer
	p.WriteByte(10)                 // protocol version
	p.WriteString("8.0.0-fake\x00") // server version
	p.Write([]byte{1, 0, 0, 0})     // connection id
	p.WriteString("12345678")       // auth-plugin-data part 1
	p.WriteByte(0)                  // filler
	p.Write(binary.LittleEndian.AppendUint16(nil, uint16(caps)))
	p.WriteByte(0x21)     // character set
	p.Write([]byte{0, 0}) // status flags
	p.Write(binary.LittleEndian.AppendUint16(nil, uint16(caps>>16)))
	p.WriteByte(21)                   // auth-plugin-data length
	p.Write(make([]byte, 10))         // reserved
	p.WriteString("123456789012\x00") // auth-plugin-data part 2
	p.WriteString("mysql_clear_password\x00")
	if err := writeMySQLPacket(conn, 0, p.Bytes()); err != nil {
		return nil, err
	}
	return readMySQLPacket(conn)
}

// TestMySQLAWSRDSBeforeConnect locks down that the BeforeConnect hook survives
// buildMySQLConfig's FormatDSN/ParseDSN round-trip and that each new connection
// authenticates with a freshly built token sent via mysql_clear_password.
func TestMySQLAWSRDSBeforeConnect(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	responses := make(chan []byte, 2)
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			resp, handshakeErr := fakeMySQLHandshake(conn)
			if handshakeErr == nil {
				responses <- resp
			}
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	cfg := newMySQLAWSRDSTestConfig(port, map[string]string{"tls": "true"})
	var calls int
	buildToken := func(_ context.Context, endpoint, region, username string) (string, error) {
		calls++
		assert.Equal(t, "127.0.0.1:"+strconv.Itoa(port), endpoint)
		assert.Equal(t, "us-east-1", region)
		assert.Equal(t, "argo", username)
		return "rds-iam-token-" + strconv.Itoa(calls), nil
	}
	mysqlCfg, err := buildMySQLAWSRDSConfig(cfg, "argo", 5*time.Second, buildToken)
	require.NoError(t, err)
	// The fake server does not speak TLS; TLS enforcement is covered by TestBuildMySQLAWSRDSConfigRequiresTLS.
	mysqlCfg.TLSConfig = "false"
	mysqlCfg.TLS = nil

	connector, err := mysql.NewConnector(mysqlCfg)
	require.NoError(t, err)
	for i := 1; i <= 2; i++ {
		_, err := connector.Connect(t.Context())
		require.Error(t, err) // the fake server hangs up after the handshake response
		select {
		case resp := <-responses:
			token := "rds-iam-token-" + strconv.Itoa(i)
			assert.Contains(t, string(resp), token+"\x00", "token must be sent as the cleartext password")
			assert.Contains(t, string(resp), "mysql_clear_password\x00")
		case <-time.After(5 * time.Second):
			t.Fatal("no handshake response received")
		}
	}
	assert.Equal(t, 2, calls, "a token must be built for every new connection")
}

func TestMySQLAWSRDSBeforeConnectError(t *testing.T) {
	tokenErr := errors.New("no credentials")
	cfg := newMySQLAWSRDSTestConfig(3306, map[string]string{"tls": "true"})
	mysqlCfg, err := buildMySQLAWSRDSConfig(cfg, "argo", time.Second, func(context.Context, string, string, string) (string, error) {
		return "", tokenErr
	})
	require.NoError(t, err)
	connector, err := mysql.NewConnector(mysqlCfg)
	require.NoError(t, err)
	_, err = connector.Connect(t.Context())
	require.ErrorIs(t, err, tokenErr)
}
