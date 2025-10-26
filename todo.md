# 以太坊签名机开发计划 (TODO)

## V1.0

### 第一阶段：核心服务实现

- [ ] **项目初始化**
  - [x] 初始化 Go Modules (`go mod init github.com/xueqianLu/ethsigner`)
  - [ ] 创建项目目录结构 (`cmd/signer`, `internal`, `pkg/client`)

- [ ] **API 设计与数据结构**
  - [ ] 定义交易签名请求/响应的 JSON 结构 (`internal/handler/types.go`)
  - [ ] 定义消息签名请求/响应的 JSON 结构 (`internal/handler/types.go`)

- [ ] **核心逻辑**
  - [ ] 实现密钥管理模块，从配置中加载私钥 (`internal/signer/keymanager.go`)
  - [ ] 实现交易签名逻辑，支持 Legacy 和 EIP-1559 交易 (`internal/signer/signer.go`)
  - [ ] 实现消息签名逻辑 (`internal/signer/signer.go`)

- [ ] **HTTP 服务**
  - [ ] 创建主服务入口 (`cmd/signer/main.go`)
  - [ ] 实现 HTTP 路由器和端点注册 (`internal/server/server.go`)
  - [ ] 实现 `/health` 健康检查处理器 (`internal/handler/health.go`)
  - [ ] 实现 `/accounts` 地址列表处理器 (`internal/handler/accounts.go`)
  - [ ] 实现 `/sign-transaction` 处理器 (`internal/handler/sign_tx.go`)
  - [ ] 实现 `/sign-message` 处理器 (`internal/handler/sign_message.go`)

- [ ] **安全性**
  - [ ] 实现 HMAC 认证中间件 (`internal/middleware/auth.go`)
  - [ ] 将 HMAC 中间件应用到所有需要保护的路由

### 第二阶段：客户端 SDK 开发

- [ ] **SDK 结构**
  - [ ] 创建客户端文件结构 (`pkg/client/client.go`)
  - [ ] 定义客户端 `Client` 结构体

- [ ] **SDK 功能**
  - [ ] 实现 `NewClient` 初始化函数
  - [ ] 实现 `SignTransaction` 方法，内部包含 HMAC 签名
  - [ ] 实现 `SignMessage` 方法，内部包含 HMAC 签名
  - [ ] 实现 `GetAccounts` 方法
  - [ ] 实现 `Health` 方法

- [ ] **SDK 示例**
  - [ ] 创建一个示例程序 (`pkg/client/example/main.go`) 演示如何使用 SDK 与服务进行交互

### 第三阶段：文档和收尾

- [ ] **文档**
  - [ ] 编写 `README.md`，包含项目介绍、API 文档、安全说明和使用示例
  - [ ] 为主要函数和模块添加 Go Doc 注释

- [ ] **配置**
  - [ ] 提供一个示例配置文件 `config.example.yaml`
  - [ ] 实现从文件或环境变量加载配置的逻辑

- [ ] **测试**
  - [ ] 为签名逻辑编写单元测试
  - [ ] 为 API 处理器编写集成测试

