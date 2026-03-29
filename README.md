# GHOST Format Specification v1.1

**Guarded Hashed Obfuscated Secret Transcript**

バイナリファイルフォーマット仕様書 / Binary File Format Specification — 2026-03

ファイル拡張子 / File extension: `.gho`

> *CLASSIFICATION: EYES ONLY*

---

# 日本語仕様 (Japanese)

## 目次

1. [概要](#1-概要)
2. [ファイルレイアウト](#2-ファイルレイアウト)
3. [セクション詳細](#3-セクション詳細)
4. [手順](#4-手順)
5. [セキュリティ](#5-セキュリティ)
6. [CLIリファレンス](#6-cliリファレンス)
7. [Hexレイアウト例](#7-hexレイアウト例)
8. [バージョニングと拡張性](#8-バージョニングと拡張性)

---

## 1. 概要

GHOST (Guarded Hashed Obfuscated Secret Transcript) は、有効期限付きの秘密文書を格納するためのバイナリファイルフォーマットです。AES-256-GCM認証付き暗号化、zlib圧縮、SHA-256完全性検証、そして設定可能なTTL（Time-to-Live）による自動失効メカニズムを組み合わせています。

1つのファイル内に複数のコンテンツタイプを格納できます。自由形式のテキストメモ、構造化テーブルデータ、分類タグ、任意のバイナリペイロードに対応しています。すべてのコンテンツチャンクは暗号化されたVAULT内に格納され、正しいパスワードでのみアクセス可能です。

### 1.1 設計原則

- **セキュリティ最優先**: すべてのコンテンツはAES-256-GCM（認証付き暗号化）で保護
- **タイムロック**: 設定可能なTTL経過後、リーダーは復号鍵の導出を拒否。さらに、有効期限が鍵導出に組み込まれているため、バイナリレベルでの有効期限改ざんは復号失敗を引き起こす
- **改ざん検知**: SHA-256ハッシュがファイル全体をカバーし、有効期限フィールドの改ざんも検出
- **コンパクト**: オプションのzlib圧縮でペイロードサイズを削減（チャンク単位で暗号化前に適用）
- **拡張可能**: 新しいチャンクタイプを後方互換性を保ちながら追加可能

### 1.2 用語集

| 用語 | 定義 |
|------|------|
| SIGNAL | `.gho`ファイルの先頭に置かれるマジックバイト。フォーマット識別に使用 |
| CORTEX | バージョン、フラグ、チャンク数を含むファイルヘッダー |
| EXPIRY | 作成タイムスタンプ、TTL、絶対有効期限を持つタイムロックセクション |
| KEYHOLE | 鍵導出パラメータ: アルゴリズムID、反復回数、ソルト |
| INDEX | VAULT内の各チャンクのタイプ、フラグ、オフセット、サイズを記載するチャンクマップ |
| VAULT | すべてのコンテンツチャンクを含む暗号化ペイロード |
| HASH | 先行するすべてのバイトに対して計算されたSHA-256完全性シール |

---

## 2. ファイルレイアウト

GHOSTファイルは7つの連続するセクションで構成されます。すべてのマルチバイト整数はリトルエンディアンで格納されます。浮動小数点タイムスタンプはIEEE 754倍精度（8バイト）を使用します。

| セクション | 名前 | サイズ | 説明 |
|:---:|------|--------|------|
| 1 | **SIGNAL** | 6B | フォーマット識別用マジックナンバー |
| 2 | **CORTEX** | 8B | ファイルヘッダー（バージョン、フラグ、チャンク数） |
| 3 | **EXPIRY** | 24B | タイムロック（作成日時、TTL、有効期限） |
| 4 | **KEYHOLE** | 40B | 鍵導出パラメータ（ソルト、反復回数） |
| 5 | **INDEX** | 10 × N B | チャンクマップ（N = チャンク数） |
| 6 | **VAULT** | 16 + M B | 暗号化ペイロード（12Bノンス + 4Bサイズ + M暗号文） |
| 7 | **HASH** | 32B | SHA-256完全性シール |

固定オーバーヘッド（SIGNALからKEYHOLE + HASH）は合計110バイトです。

---

## 3. セクション詳細

### 3.1 SIGNAL（マジックナンバー）

先頭バイト（0x89）は意図的に非ASCIIとし、テキストファイルとの誤認を防ぎます（PNG仕様と同じテクニック）。

| Byte 0 | Byte 1 | Byte 2 | Byte 3 | Byte 4 | Byte 5 |
|:---:|:---:|:---:|:---:|:---:|:---:|
| `0x89` | `0x47` (G) | `0x48` (H) | `0x53` (S) | `0x54` (T) | `0x00` (NUL) |

### 3.2 CORTEX（ヘッダー）

| フィールド | 型 | オフセット | 説明 |
|-----------|------|:---------:|------|
| version | `uint16` | +0 | フォーマットバージョン（現在は1） |
| flags | `uint16` | +2 | グローバルフラグ（ビット0: 圧縮有効） |
| chunk_count | `uint32` | +4 | VAULT内のチャンク数 |

### 3.3 EXPIRY（タイムロック）

| フィールド | 型 | オフセット | 説明 |
|-----------|------|:---------:|------|
| created_at | `float64` | +0 | 作成タイムスタンプ（Unixエポック、UTC） |
| ttl_seconds | `uint32` | +8 | 生存時間（秒） |
| expiry_at | `float64` | +12 | 絶対有効期限タイムスタンプ（Unixエポック、UTC） |
| （パディング） | 4B | +20 | 予約済み、ゼロでなければならない |

> **セキュリティ上の注意:** EXPIRYフィールドはHASHシールでカバーされており、さらに有効期限タイムスタンプは鍵導出のソルトに組み込まれています（3.4.1項参照）。有効期限の改ざんは二重に防御されます。(1) SHA-256ハッシュ不一致による検出、(2) 鍵導出結果の変化によるAES-GCM復号失敗。

### 3.4 KEYHOLE（鍵導出パラメータ）

| フィールド | 型 | オフセット | 説明 |
|-----------|------|:---------:|------|
| algorithm | `uint8` | +0 | KDFアルゴリズムID（0x01 = PBKDF2-SHA256） |
| （パディング） | 3B | +1 | 予約済み |
| iterations | `uint32` | +4 | PBKDF2反復回数（デフォルト: 600,000） |
| salt | 32B | +8 | 暗号論的に安全なランダムソルト |

**アルゴリズムID:** `0x01` = PBKDF2-HMAC-SHA256, `0x02` = Argon2id用に予約

#### 3.4.1 有効期限バインド鍵導出（Expiry-Bound Key Derivation）

鍵導出時、`expiry_at`（8バイト、リトルエンディアンfloat64）がソルトの末尾に連結され、**実効ソルト**として使用されます。

```
effective_salt = salt(32 bytes) + expiry_at(8 bytes, LE float64)
```

攻撃者がEXPIRYフィールドを書き換えて期限を延長しようとした場合、たとえSHA-256ハッシュを再計算してHASHチェックをバイパスしても、鍵導出が異なるAES鍵を生成するため、復号は失敗します。

### 3.5 INDEX（チャンクマップ）

各10バイト × N個。オフセットは復号されたVAULTプレーンテキストの先頭からの相対値です。

| フィールド | 型 | オフセット | 説明 |
|-----------|------|:---------:|------|
| chunk_type | `uint8` | +0 | チャンクタイプ識別子 |
| chunk_flags | `uint8` | +1 | フラグ（ビット0: zlib圧縮済み） |
| offset | `uint32` | +2 | VAULT内のバイトオフセット |
| size | `uint32` | +6 | データサイズ（バイト） |

### 3.6 VAULT（暗号化ペイロード）

AES-256-GCM（AEAD）で暗号化。復号後の内部チャンクは各6バイトヘッダー（type:1 + flags:1 + data_size:4）+ データ。

**チャンクタイプ:**

| ID | 名前 | エンコーディング | 説明 |
|:---:|------|-----------------|------|
| `0x01` | **MEMO** | UTF-8 | 秘密テキスト |
| `0x02` | **GRID** | JSON配列 | テーブルデータ |
| `0x03` | **TAG** | JSON配列 | 分類ラベル |
| `0x04` | **BLOB** | 生バイト列 | 任意バイナリデータ |

### 3.7 HASH（完全性シール）

ファイル末尾の32バイトSHA-256ハッシュ。SIGNALからVAULT末尾までの全バイトをカバーします。

---

## 4. 手順

### 4.1 書き込み

1. チャンクとパスワードの存在を検証
2. 各チャンクをシリアライズ・圧縮し、VAULTプレーンテキストに連結
3. ソルト生成 → `effective_salt = salt + expiry_at` → PBKDF2-SHA256で鍵導出
4. AES-256-GCMで暗号化
5. SIGNAL → CORTEX → EXPIRY → KEYHOLE → INDEX → VAULT → HASH の順に書き込み

### 4.2 読み込み

1. SIGNAL検証 → CORTEX解析 → EXPIRY解析（**期限切れなら拒否**）
2. KEYHOLE解析 → `effective_salt = salt + expiry_at` → 鍵導出
3. INDEX解析 → VAULT読み取り → HASH検証（**不一致なら拒否**）
4. AES-256-GCM復号（**失敗なら拒否**） → 内部チャンク解析

---

## 5. セキュリティ

### 5.1 暗号選定

| コンポーネント | 選定と根拠 |
|--------------|-----------|
| 暗号化 | AES-256-GCM（認証付き暗号化） |
| 鍵導出 | PBKDF2-SHA256、600K反復（OWASP 2023推奨）。有効期限がソルトに結合 |
| ソルト | 32B (CSPRNG) + 8B (`expiry_at`) = 40B実効ソルト |
| ノンス | 12B（96ビット）、文書ごとにランダム |
| 完全性 | SHA-256、ファイル全体をカバー |

### 5.2 既知の制限事項

- カスタムリーダーがEXPIRYチェックのif文を削除し、元の`expiry_at`値で鍵導出すれば期限切れでも復号可能。ただしバイナリの期限延長は不可能
- INDEXはチャンクタイプとサイズを公開する（コンテンツは非公開）
- パスワード強度はユーザーの責任

---

## 6. CLIリファレンス

`ghost.py`（フォーマットコア + CLI統合）。コマンド: `encode`, `decode`, `info`, `hexdump`, `verify`

```bash
python ghost.py encode -o secret.gho --memo "極秘情報" --tags "URGENT" --ttl 1h
python ghost.py decode secret.gho
python ghost.py info secret.gho
python ghost.py verify secret.gho
```

---

## 7. Hexレイアウト例

| セクション | Hex | 意味 |
|-----------|-----|------|
| **SIGNAL** | `89 47 48 53 54 00` | マジックバイト |
| **CORTEX** | `01 00 01 00 01 00 00 00` | v1、圧縮有効、1チャンク |
| **EXPIRY** | `[24B: タイムスタンプ]` | 作成日時 + TTL + 有効期限 |
| **KEYHOLE** | `01 00 00 00 C0 27 09 00 [salt]` | PBKDF2、600K反復 |
| **INDEX** | `01 01 00 00 00 00 XX 00 00 00` | MEMO、圧縮済み |
| **VAULT** | `[12B nonce][4B size][ciphertext]` | AES-256-GCM |
| **HASH** | `[32B SHA-256]` | 完全性シール |

---

## 8. バージョニングと拡張性

新チャンクタイプ（0x05以降）は後方互換性を保ちながら追加可能。KEYHOLEのアルゴリズムフィールドでArgon2idなどへの移行も可能。

---

*The ghost remembers, even after it vanishes.*

---
---
---

# English Specification

## Table of Contents

1. [Overview](#1-overview)
2. [File Layout](#2-file-layout)
3. [Section Details](#3-section-details)
4. [Procedures](#4-procedures)
5. [Security](#5-security)
6. [CLI Reference](#6-cli-reference)
7. [Hex Layout Example](#7-hex-layout-example)
8. [Versioning & Extensibility](#8-versioning--extensibility)

---

## 1. Overview

GHOST (Guarded Hashed Obfuscated Secret Transcript) is a binary file format designed for storing time-limited secret documents. It combines AES-256-GCM authenticated encryption, zlib compression, SHA-256 integrity verification, and a configurable TTL (Time-to-Live) auto-expiry mechanism.

A single file can contain multiple content types: free-form text memos, structured table data, classification tags, and arbitrary binary payloads. All content chunks are stored inside an encrypted vault, accessible only with the correct password.

### 1.1 Design Principles

- **Security first**: All content is protected with AES-256-GCM (authenticated encryption)
- **Time-locked**: After the configured TTL, the reader refuses to derive the decryption key. The expiry timestamp is incorporated into key derivation, so binary-level expiry tampering causes decryption failure
- **Tamper-evident**: SHA-256 hash covers the entire file, detecting modifications to expiry fields
- **Compact**: Optional zlib compression reduces payload size (applied per-chunk before encryption)
- **Extensible**: New chunk types can be added without breaking backward compatibility

### 1.2 Glossary

| Term | Definition |
|------|-----------|
| SIGNAL | Magic bytes at the start of every `.gho` file for format identification |
| CORTEX | File header containing version, flags, and chunk count |
| EXPIRY | Time-lock section with creation timestamp, TTL, and absolute expiry time |
| KEYHOLE | Key derivation parameters: algorithm ID, iteration count, and salt |
| INDEX | Chunk map listing each chunk's type, flags, offset, and size within the vault |
| VAULT | Encrypted payload containing all content chunks |
| HASH | SHA-256 integrity seal computed over all preceding bytes |

---

## 2. File Layout

A GHOST file is composed of seven sequential sections. All multi-byte integers are stored in little-endian byte order. Floating-point timestamps use IEEE 754 double precision (8 bytes).

| # | Name | Size | Description |
|:---:|------|------|-------------|
| 1 | **SIGNAL** | 6B | Magic number for format identification |
| 2 | **CORTEX** | 8B | File header (version, flags, chunk count) |
| 3 | **EXPIRY** | 24B | Time-lock (created, TTL, expiry timestamp) |
| 4 | **KEYHOLE** | 40B | Key derivation parameters (salt, iterations) |
| 5 | **INDEX** | 10 × N B | Chunk map (N = number of chunks) |
| 6 | **VAULT** | 16 + M B | Encrypted payload (12B nonce + 4B size + M ciphertext) |
| 7 | **HASH** | 32B | SHA-256 integrity seal |

Fixed overhead (SIGNAL through KEYHOLE + HASH) totals 110 bytes.

---

## 3. Section Details

### 3.1 SIGNAL (Magic Number)

The first byte (0x89) is deliberately non-ASCII to prevent misidentification as plain text (same technique as PNG).

| Byte 0 | Byte 1 | Byte 2 | Byte 3 | Byte 4 | Byte 5 |
|:---:|:---:|:---:|:---:|:---:|:---:|
| `0x89` | `0x47` (G) | `0x48` (H) | `0x53` (S) | `0x54` (T) | `0x00` (NUL) |

### 3.2 CORTEX (Header)

| Field | Type | Offset | Description |
|-------|------|:------:|-------------|
| version | `uint16` | +0 | Format version (currently 1) |
| flags | `uint16` | +2 | Global flags (bit 0: compression enabled) |
| chunk_count | `uint32` | +4 | Number of chunks in the VAULT |

### 3.3 EXPIRY (Time-Lock)

| Field | Type | Offset | Description |
|-------|------|:------:|-------------|
| created_at | `float64` | +0 | Creation timestamp (Unix epoch, UTC) |
| ttl_seconds | `uint32` | +8 | Time-to-live in seconds |
| expiry_at | `float64` | +12 | Absolute expiry timestamp (Unix epoch, UTC) |
| (padding) | 4B | +20 | Reserved, must be zero |

> **Security note:** EXPIRY fields are covered by the HASH seal and the expiry timestamp is incorporated into key derivation salt (see 3.4.1). Expiry tampering is defended at two layers: (1) SHA-256 hash mismatch, (2) AES-GCM decryption failure due to derived key change.

### 3.4 KEYHOLE (Key Derivation Parameters)

| Field | Type | Offset | Description |
|-------|------|:------:|-------------|
| algorithm | `uint8` | +0 | KDF algorithm ID (0x01 = PBKDF2-SHA256) |
| (padding) | 3B | +1 | Reserved |
| iterations | `uint32` | +4 | PBKDF2 iteration count (default: 600,000) |
| salt | 32B | +8 | Cryptographically random salt |

**Algorithm IDs:** `0x01` = PBKDF2-HMAC-SHA256, `0x02` = Reserved for Argon2id

#### 3.4.1 Expiry-Bound Key Derivation

During key derivation, `expiry_at` (8 bytes, little-endian float64) is appended to the salt to form the **effective salt**.

```
effective_salt = salt(32 bytes) + expiry_at(8 bytes, LE float64)
```

If an attacker modifies the EXPIRY field to extend the document's lifetime, the key derivation produces a different AES key and decryption fails — even if the SHA-256 hash is recalculated to bypass the integrity check.

### 3.5 INDEX (Chunk Map)

10 bytes per entry × N entries. Offsets are relative to the start of the decrypted vault plaintext.

| Field | Type | Offset | Description |
|-------|------|:------:|-------------|
| chunk_type | `uint8` | +0 | Chunk type identifier |
| chunk_flags | `uint8` | +1 | Flags (bit 0: zlib compressed) |
| offset | `uint32` | +2 | Byte offset within vault |
| size | `uint32` | +6 | Data size (bytes) |

### 3.6 VAULT (Encrypted Payload)

Encrypted with AES-256-GCM (AEAD). Decrypted inner chunks have a 6-byte header each (type:1 + flags:1 + data_size:4) + data.

**Chunk Types:**

| ID | Name | Encoding | Description |
|:---:|------|----------|-------------|
| `0x01` | **MEMO** | UTF-8 | Secret text |
| `0x02` | **GRID** | JSON array | Table data |
| `0x03` | **TAG** | JSON array | Classification labels |
| `0x04` | **BLOB** | Raw bytes | Arbitrary binary data |

### 3.7 HASH (Integrity Seal)

Final 32-byte SHA-256 hash covering all bytes from SIGNAL through end of VAULT.

---

## 4. Procedures

### 4.1 Writing

1. Validate chunks and password exist
2. Serialize/compress each chunk, concatenate into vault plaintext
3. Generate salt → `effective_salt = salt + expiry_at` → derive key via PBKDF2-SHA256
4. Encrypt with AES-256-GCM
5. Write in order: SIGNAL → CORTEX → EXPIRY → KEYHOLE → INDEX → VAULT → HASH

### 4.2 Reading

1. Verify SIGNAL → parse CORTEX → parse EXPIRY (**reject if expired**)
2. Parse KEYHOLE → `effective_salt = salt + expiry_at` → derive key
3. Parse INDEX → read VAULT → verify HASH (**reject on mismatch**)
4. Decrypt AES-256-GCM (**reject on failure**) → parse inner chunks

---

## 5. Security

### 5.1 Cryptographic Choices

| Component | Choice & Rationale |
|-----------|-------------------|
| Encryption | AES-256-GCM (authenticated encryption) |
| Key Derivation | PBKDF2-SHA256, 600K iterations (OWASP 2023). Expiry bound into salt |
| Salt | 32B (CSPRNG) + 8B (`expiry_at`) = 40B effective salt |
| Nonce | 12B (96-bit), random per document |
| Integrity | SHA-256 over entire file |

### 5.2 Known Limitations

- A custom reader removing the expiry-check if-statement while using the original `expiry_at` for key derivation can decrypt after expiry. However, extending expiry by modifying the binary is impossible
- INDEX reveals chunk types and sizes (not content) — deliberate metadata leak
- Password strength is the user's responsibility

---

## 6. CLI Reference

`ghost.py` (format core + CLI unified). Commands: `encode`, `decode`, `info`, `hexdump`, `verify`

```bash
python ghost.py encode -o secret.gho --memo "Top secret" --tags "URGENT" --ttl 1h
python ghost.py decode secret.gho
python ghost.py info secret.gho
python ghost.py verify secret.gho
```

---

## 7. Hex Layout Example

| Section | Hex | Meaning |
|---------|-----|---------|
| **SIGNAL** | `89 47 48 53 54 00` | Magic bytes |
| **CORTEX** | `01 00 01 00 01 00 00 00` | v1, compressed, 1 chunk |
| **EXPIRY** | `[24B: timestamps]` | Created + TTL + Expiry |
| **KEYHOLE** | `01 00 00 00 C0 27 09 00 [salt]` | PBKDF2, 600K iter |
| **INDEX** | `01 01 00 00 00 00 XX 00 00 00` | MEMO, compressed |
| **VAULT** | `[12B nonce][4B size][ciphertext]` | AES-256-GCM |
| **HASH** | `[32B SHA-256]` | Integrity seal |

---

## 8. Versioning & Extensibility

New chunk types (0x05+) can be added with backward compatibility. The KEYHOLE algorithm field enables migration to stronger KDFs such as Argon2id.

---

*The ghost remembers, even after it vanishes.*
