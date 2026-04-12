# Block Config Builder

`tools/block-config-builder` 是一個基於 Next.js 風格前端交互（ESM 單頁面）構建的 **Block-based sing-box 配置組裝工具**，用於以可視化方式拼接 `sing-box` JSON 配置。

## 工具定位

- 讓使用者不需要手寫完整 JSON，也能逐塊（Block）組裝配置。
- 直接讀取 `generated/configuration-schemas/*.json`，把 schema 內容映射為可操作的欄位 UI。
- 以「左資源庫 / 中工作區 / 右預覽」三欄模式，提供快速配置、校驗、導出流程。

## 核心功能

- **動態 Schema 解析**
  - 自動發現並載入 `generated/configuration-schemas/*.json`。
  - 以 `module -> pages -> fields` 生成可新增的 Block。
- **塊式工作區**
  - 可新增 Block。
  - 可拖拽排序。
  - 可單獨啟用/停用。
  - 可刪除單個 Block。
- **向導式場景**
  - **E 透明代理網關**：TUN/TProxy 一鍵模板，默認啟用 sniff、auto_route、platform_interface、DNS 防回環檢查。
  - **F 進階策略分流**：流媒體 / 廣告 / AI 分流規則快速生成，內建 selector + url-test 與 Geo 資源提示位。
  - **G 混合入站中心**：SOCKS/HTTP/Mixed/DNS 同時啟用，帶端口衝突檢測與 inbound 精準導向。
- **智慧預設值**
  - 依 `string / integer / boolean / array / object` 自動填充初值。
- **即時合併引擎**
  - 只合併啟用中的 Block。
  - 自動映射到 `inbounds / outbounds / route / dns / endpoints / services` 等結構。
  - 已完成 **sing-box 1.14 適配**：`dns` 與 `route` 強制輸出為對象結構（不再輸出舊版 array 形態）。
  - 內建 legacy 遷移：`dns.servers[].address` 會在導出時轉換為 1.14 的 `type/server/server_port/path` 結構。
- **校驗與錯誤提示**
  - 基礎型別檢查。
  - 必填欄位檢查。
  - object JSON 解析錯誤即時提示。
  - 針對 Shadowsocks 2022 演算法增加密鑰長度校驗（base64 解碼後字節數必須符合方法要求）。
- **導出操作**
  - 一鍵複製 JSON。
  - 下載 `config.json`。
  - 支持「僅差異導出」模式（移除與推薦默認相同的字段）。
  - 支持「導入現有 JSON」並自動反向解構為 Block。
  - 重置全部塊。
- **JSON 即時預覽**
  - 右欄同步渲染語法高亮 JSON。
  - 右欄增加「規則摘要」，可視化輸出當前分流策略。

## 本地啟動

> 需用 HTTP server 啟動（避免 `file://` 下 fetch 受限）。

在倉庫根目錄執行任一方式：

```bash
python -m http.server 8000
```

或

```bash
npx serve .
```

啟動後打開：

- `http://localhost:8000/tools/block-config-builder/index.html`

## 如何擴展新的 Schema Block

1. 在 `generated/configuration-schemas/` 新增或更新 schema 檔案。
2. schema 需包含：
   - `module`
   - `pages[]`
   - `pages[].fields`（以欄位名為 key）
3. 每個欄位可定義：
   - `type`（例如 `string`, `integer`, `boolean`, `array_integer`, `array_object`, `object`）
   - `required`
   - `default`
   - `allowedValues`（會映射為 Select）
   - `description`
4. 重新整理頁面後，左側資源庫會自動出現新的 Block 頁面入口。

## 備註

- 若某些 schema JSON 格式有誤（例如無法被 `JSON.parse`），工具會在錯誤面板顯示載入失敗資訊，但不影響其他 schema 的使用。
- 後端與測試共用 `tools/core/linter.py::ProjectLinter`，用於保存前最後一層邏輯審查（去除 `__page_id` 等污染欄位、修復 DNS/Route 結構、校驗 2022 密鑰）。
- UI 與 Python linter 共享 `tools/core/schema_shared.json` 內的根級白名單與枚舉選項，避免雙端定義漂移。
