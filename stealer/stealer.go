package stealer

import (
    "context"
    "encoding/json"
    "fmt"
    "github.com/akmalfairuz/bedrockpack/pack"
    "github.com/sandertv/gophertunnel/minecraft"
    "github.com/sandertv/gophertunnel/minecraft/auth"
    "github.com/sandertv/gophertunnel/minecraft/resource"
    "golang.org/x/oauth2"
    "io"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"
)

const (
    protocolVersion = 950 // 프로토콜 버전 1.21.21에 맞는 버전
    maxRetries      = 3   // 최대 재시도 횟수
)

func Run(serverAddress string) {
    if len(strings.Split(serverAddress, ":")) == 1 {
        serverAddress = serverAddress + ":19132"
    }
    cacheTokenBytes, err := os.ReadFile(".token_cache")
    if err == nil {
        var cacheTok *oauth2.Token
        if err := json.Unmarshal(cacheTokenBytes, &cacheTok); err == nil {
            if time.Now().Add(time.Second * 30).Before(cacheTok.Expiry) {
                fmt.Println("Using .token_cache for authentication")
                src := auth.RefreshTokenSource(cacheTok)
                handleConn(serverAddress, src)
                return
            }
        }
    }

    token, err := auth.RequestLiveToken()
    if err != nil {
        panic(err)
    }
    tokBytes, err := json.Marshal(token)
    if err := os.WriteFile(".token_cache", tokBytes, 0777); err != nil {
        panic(err)
    }

    src := auth.RefreshTokenSource(token)
    handleConn(serverAddress, src)
}

func handleConn(serverAddress string, src oauth2.TokenSource) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute) // 5분 타임아웃 설정
    defer cancel()

    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

    var serverConn *minecraft.Conn
    var err error

    for attempt := 0; attempt < maxRetries; attempt++ {
        serverConn, err = minecraft.Dialer{
            TokenSource: src,
            // 프로토콜 버전을 지원하지 않으므로 주석 처리
            // ProtocolVersion: protocolVersion,
        }.DialContext(ctx, "raknet", serverAddress)
        if err == nil {
            break
        }
        fmt.Printf("Attempt %d/%d failed: %v\n", attempt+1, maxRetries, err)
        time.Sleep(2 * time.Second) // 재시도 전 잠시 대기
    }

    if err != nil {
        panic(fmt.Sprintf("Failed to connect after %d attempts: %v", maxRetries, err))
    }

    fmt.Println("Getting resource pack information...")
    if err := serverConn.DoSpawnContext(ctx); err != nil {
        panic(err)
    }

    for i, rp := range serverConn.ResourcePacks() {
        if err := stealPack(i, serverAddress, rp); err != nil {
            panic(err)
        }
    }

    _ = serverConn.Close()
}

func stealPack(i int, serverAddress string, rp *resource.Pack) error {
    packBytes, err := downloadPack(rp)
    if err != nil {
        return err
    }
    pac, err := pack.LoadResourcePackFromBytes(packBytes)
    if err != nil {
        return fmt.Errorf("error loading resource pack: %w", err)
    }
    fmt.Printf("Decrypting resource pack %s with key %s ...\n", rp.Name(), rp.ContentKey())
    if err := pac.Decrypt([]byte(rp.ContentKey())); err != nil {
        return fmt.Errorf("error when decrypting resource pack: %w", err)
    }

    rpName := rp.Name()
    disallowedChars := []string{"\\", "/", ":", "*", "?", "\"", "<", ">", "|"} // Windows disallowed characters
    for _, char := range disallowedChars {
        rpName = strings.ReplaceAll(rpName, char, "")
    }

    prefix, _, _ := strings.Cut(serverAddress, ":")
    _ = os.Mkdir(prefix, 0777)
    savePath := fmt.Sprintf("%s/%d_%s.zip", prefix, i, rpName)

    fmt.Printf("Resource pack saved in %s\n", savePath)
    return pac.Save(savePath)
}

func downloadPack(pack *resource.Pack) ([]byte, error) {
    if pack.DownloadURL() != "" {
        fmt.Printf("Downloading resource pack %s from %s\n", pack.Name(), pack.DownloadURL())
        resp, err := http.Get(pack.DownloadURL())
        if err != nil {
            return nil, err
        }
        if resp.StatusCode >= 400 {
            return nil, fmt.Errorf("error: %v", resp.StatusCode)
        }
        packBytes, err := io.ReadAll(resp.Body)
        if err != nil {
            return nil, err
        }
        return packBytes, err
    }
    buf := make([]byte, pack.Len())
    off := 0
    for {
        n, err := pack.ReadAt(buf[off:], int64(off))
        if err != nil {
            if err == io.EOF {
                break
            }
            return nil, err
        }
        off += n
    }
    return buf, nil
}
