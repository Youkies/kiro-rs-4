//! Kiro 托管门户登录 — 支持社交（Google/GitHub）和企业 IdP（Azure AD/M365）
//!
//! 双段状态机（在服务器 task 内部完成，对 service 透明）：
//!   Leg 1 /signin/callback — 社交：code → 换 Kiro token → 完成
//!                          — 企业：descriptor → OIDC 发现 → 302 到 IdP
//!   Leg 2 /oauth/callback  — 企业 IdP code → 换 IdP token → 完成
//!
//! 白名单：issuer 后缀必须为 *.microsoftonline.com / *.microsoftonline.us / *.microsoftonline.cn

use std::net::TcpListener;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::http_client::{ProxyConfig, build_client};
use crate::kiro::auth::social::{CALLBACK_PORTS, exchange_code_for_token, generate_pkce};
use crate::kiro::kiro_version;
use crate::model::config::Config;

/// 允许的外部 IdP issuer 域名后缀（防 SSRF）
const ALLOWED_ISSUER_SUFFIXES: &[&str] = &[
    ".microsoftonline.com",
    ".microsoftonline.us",
    ".microsoftonline.cn",
];

// ────────────────────────────────────────────────────────────── 公开类型 ──

/// SSO 服务器关闭句柄（Drop 时发关闭信号）
pub struct SsoServerHandle {
    _shutdown_tx: oneshot::Sender<()>,
}

/// Kiro SSO 登录完成结果
#[derive(Debug, Clone)]
pub struct KiroSsoResult {
    pub auth_method: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub email: Option<String>,
    /// External IdP token endpoint（用于后续刷新 token）
    pub token_endpoint: Option<String>,
    pub issuer_url: Option<String>,
    pub scopes: Option<String>,
    pub client_id: Option<String>,
}

/// OIDC discovery document（仅取需要的字段）
#[derive(Debug, Deserialize)]
pub struct OidcDiscovery {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub issuer: String,
}

/// External IdP token 响应（snake_case，Azure AD 标准）
#[derive(Debug, Deserialize, Serialize)]
pub struct ExternalIdpTokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

// ────────────────────────────────────────────────────────── 服务器参数 ──

/// 启动 Kiro SSO 服务器所需的参数（传入服务器 task）
struct SsoServerParams {
    auth_endpoint: String,
    state: String,
    code_verifier: String,
    redirect_uri: String,
    config: Arc<Config>,
    proxy: Option<ProxyConfig>,
    completion_tx: oneshot::Sender<Result<KiroSsoResult, String>>,
}

// ────────────────────────────────────────────────────────── 服务器启动 ──

/// 启动 Kiro SSO 回调服务器
///
/// 服务器 task 内部自主完成双段流（OIDC discovery / token exchange）。
/// 返回 (端口号, 关闭句柄, 完成 channel)。
pub fn start_kiro_sso_server(
    auth_endpoint: String,
    state: String,
    code_verifier: String,
    config: Arc<Config>,
    proxy: Option<ProxyConfig>,
) -> anyhow::Result<(
    u16,
    SsoServerHandle,
    oneshot::Receiver<Result<KiroSsoResult, String>>,
)> {
    // 在调用线程同步绑定端口，避免 service 和 server 竞争
    let (port, std_listener) = bind_sso_port()?;
    let redirect_uri = format!("http://127.0.0.1:{}", port);

    let (completion_tx, completion_rx) = oneshot::channel::<Result<KiroSsoResult, String>>();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let params = SsoServerParams {
        auth_endpoint,
        state,
        code_verifier,
        redirect_uri,
        config,
        proxy,
        completion_tx,
    };

    tokio::spawn(async move {
        run_sso_server_from_listener(std_listener, params, shutdown_rx).await;
    });

    Ok((
        port,
        SsoServerHandle {
            _shutdown_tx: shutdown_tx,
        },
        completion_rx,
    ))
}

/// 绑定可用端口（优先 KIRO_SSO_CALLBACK_BIND 指定地址）
pub(crate) fn bind_sso_port() -> anyhow::Result<(u16, std::net::TcpListener)> {
    let bind_host = std::env::var("KIRO_SSO_CALLBACK_BIND")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_string());

    for &port in CALLBACK_PORTS {
        match TcpListener::bind((bind_host.as_str(), port)) {
            Ok(listener) => {
                listener.set_nonblocking(true)?;
                return Ok((port, listener));
            }
            Err(_) => continue,
        }
    }
    anyhow::bail!(
        "Kiro SSO 回调端口均被占用 {:?}",
        CALLBACK_PORTS
    )
}

/// SSO 服务器主循环（自主完成双段流，从已绑定的 listener 启动）
async fn run_sso_server_from_listener(
    std_listener: std::net::TcpListener,
    params: SsoServerParams,
    shutdown_rx: oneshot::Receiver<()>,
) {
    let port = std_listener.local_addr().map(|a| a.port()).unwrap_or(0);
    match tokio::net::TcpListener::from_std(std_listener) {
        Ok(listener) => run_sso_server(listener, port, params, shutdown_rx).await,
        Err(e) => {
            let _ = params
                .completion_tx
                .send(Err(format!("Kiro SSO 服务器初始化失败: {}", e)));
        }
    }
}

async fn run_sso_server(
    listener: tokio::net::TcpListener,
    port: u16,
    params: SsoServerParams,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tracing::info!("Kiro SSO 回调服务器已启动: {}", &params.redirect_uri);

    // 状态机：leg1_done 后进入等待 leg-2 模式
    let mut leg2_state: Option<Leg2State> = None;
    let mut completion_tx = Some(params.completion_tx);

    loop {
        let (mut stream, _addr) = tokio::select! {
            result = listener.accept() => match result {
                Ok(s) => s,
                Err(_) => break,
            },
            _ = &mut shutdown_rx => {
                tracing::info!("Kiro SSO 服务器收到关闭信号，端口 {} 已释放", port);
                break;
            }
        };

        let mut buf = vec![0u8; 8192];
        let n = match stream.read(&mut buf).await {
            Ok(n) if n > 0 => n,
            _ => continue,
        };

        let request = String::from_utf8_lossy(&buf[..n]);
        let first_line = request.lines().next().unwrap_or("");

        let path_and_query = match first_line
            .strip_prefix("GET ")
            .and_then(|s| s.strip_suffix(" HTTP/1.1").or_else(|| s.strip_suffix(" HTTP/1.0")))
        {
            Some(p) => p.to_string(),
            None => {
                let _ = stream
                    .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                    .await;
                continue;
            }
        };

        let (path, query) = split_path_query(&path_and_query);
        let query_params = parse_query_string(query);

        if path == "/signin/callback" {
            // ── Leg-1 ──
            if let Some(err) = query_params.get("error") {
                let msg = query_params
                    .get("error_description")
                    .unwrap_or(err)
                    .clone();
                let _ = stream.write_all(error_page(&msg).as_bytes()).await;
                if let Some(tx) = completion_tx.take() {
                    let _ = tx.send(Err(format!("Kiro 门户登录失败: {}", msg)));
                }
                break;
            }

            let code = query_params.get("code").cloned().unwrap_or_default();
            let login_option = query_params.get("login_option").cloned().unwrap_or_default();
            let state_received = query_params.get("state").cloned().unwrap_or_default();

            // CSRF 校验
            if !state_received.is_empty() && state_received != params.state {
                let msg = "OAuth state 不匹配".to_string();
                let _ = stream.write_all(error_page(&msg).as_bytes()).await;
                if let Some(tx) = completion_tx.take() {
                    let _ = tx.send(Err(msg));
                }
                break;
            }

            if !code.is_empty() && login_option != "external_idp" {
                // 社交登录（Google / GitHub）— 直接换 Kiro token
                let full_redirect_uri = if login_option.is_empty() {
                    format!("{}{}", params.redirect_uri, path)
                } else {
                    format!(
                        "{}{}?login_option={}",
                        params.redirect_uri,
                        path,
                        urlencoding::encode(&login_option)
                    )
                };

                let _ = stream.write_all(success_page().as_bytes()).await;

                let auth_endpoint = params.auth_endpoint.clone();
                let config = params.config.clone();
                let proxy = params.proxy.clone();
                let code_verifier = params.code_verifier.clone();

                if let Some(tx) = completion_tx.take() {
                    match exchange_code_for_token(
                        &auth_endpoint,
                        &code,
                        &code_verifier,
                        &full_redirect_uri,
                        &config,
                        proxy.as_ref(),
                    )
                    .await
                    {
                        Ok(resp) => {
                            let _ = tx.send(Ok(KiroSsoResult {
                                auth_method: "social".to_string(),
                                access_token: resp.access_token,
                                refresh_token: resp.refresh_token,
                                expires_in: resp.expires_in,
                                email: None,
                                token_endpoint: None,
                                issuer_url: None,
                                scopes: None,
                                client_id: None,
                            }));
                        }
                        Err(e) => {
                            let _ = tx.send(Err(format!("Kiro 社交 token 换取失败: {}", e)));
                        }
                    }
                }
                break;
            }

            // 企业 IdP descriptor
            let issuer_url = query_params
                .get("issuer_url")
                .cloned()
                .unwrap_or_default();
            let ext_client_id = query_params
                .get("client_id")
                .cloned()
                .unwrap_or_default();
            let scopes = query_params
                .get("scopes")
                .cloned()
                .unwrap_or_else(|| "openid profile email offline_access".to_string());

            if issuer_url.is_empty() || ext_client_id.is_empty() {
                // 无效 leg-1，等待下次
                let _ = stream
                    .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                    .await;
                continue;
            }

            // OIDC discovery（在 HTTP 响应前完成，可能阻塞几百 ms，可接受）
            let discovery = match oidc_discover_internal(
                &issuer_url,
                params.proxy.as_ref(),
                &params.config,
            )
            .await
            {
                Ok(d) => d,
                Err(e) => {
                    let msg = format!("OIDC discovery 失败: {}", e);
                    let _ = stream.write_all(error_page(&msg).as_bytes()).await;
                    if let Some(tx) = completion_tx.take() {
                        let _ = tx.send(Err(msg));
                    }
                    break;
                }
            };

            // Leg-2 PKCE
            let (leg2_verifier, leg2_challenge) = generate_pkce();
            let leg2_state_param = format!("{}-leg2", params.state);

            let idp_url = external_idp_authorize_url(
                &discovery.authorization_endpoint,
                &ext_client_id,
                &params.redirect_uri,
                &leg2_state_param,
                &leg2_challenge,
                &scopes,
            );

            // 302 → IdP
            let redirect_response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                idp_url
            );
            let _ = stream.write_all(redirect_response.as_bytes()).await;

            leg2_state = Some(Leg2State {
                token_endpoint: discovery.token_endpoint,
                issuer_url,
                scopes,
                client_id: ext_client_id,
                code_verifier: leg2_verifier,
                state: leg2_state_param,
            });

            // 继续循环等待 leg-2
        } else if path == "/oauth/callback" {
            // ── Leg-2 ──
            if let Some(err) = query_params.get("error") {
                let msg = query_params
                    .get("error_description")
                    .unwrap_or(err)
                    .clone();
                let _ = stream.write_all(error_page(&msg).as_bytes()).await;
                if let Some(tx) = completion_tx.take() {
                    let _ = tx.send(Err(format!("IdP 登录失败: {}", msg)));
                }
                break;
            }

            let code = match query_params.get("code").cloned() {
                Some(c) if !c.is_empty() => c,
                _ => {
                    let _ = stream
                        .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    continue;
                }
            };

            let _ = stream.write_all(success_page().as_bytes()).await;

            if let Some(l2) = leg2_state.take() {
                let config = params.config.clone();
                let proxy = params.proxy.clone();
                let redirect_uri = params.redirect_uri.clone();

                if let Some(tx) = completion_tx.take() {
                    let exchange_result = exchange_external_idp_code(
                        &l2.token_endpoint,
                        &l2.client_id,
                        &code,
                        &l2.code_verifier,
                        &redirect_uri,
                        &l2.scopes,
                        proxy.as_ref(),
                        &config,
                    )
                    .await;

                    match exchange_result {
                        Ok(resp) => {
                            let email = extract_email_from_jwt(&resp.access_token);
                            let _ = tx.send(Ok(KiroSsoResult {
                                auth_method: "external_idp".to_string(),
                                access_token: resp.access_token,
                                refresh_token: resp.refresh_token,
                                expires_in: resp.expires_in,
                                email,
                                token_endpoint: Some(l2.token_endpoint),
                                issuer_url: Some(l2.issuer_url),
                                scopes: Some(l2.scopes),
                                client_id: Some(l2.client_id),
                            }));
                        }
                        Err(e) => {
                            let _ = tx.send(Err(format!("External IdP token 换取失败: {}", e)));
                        }
                    }
                }
            }
            break;
        } else {
            let _ = stream
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    }
}

/// Leg-2 状态（企业 IdP 第二段信息）
struct Leg2State {
    token_endpoint: String,
    issuer_url: String,
    scopes: String,
    client_id: String,
    code_verifier: String,
    #[allow(dead_code)]
    state: String,
}

// ─────────────────────────────────────────────── OIDC discovery & 验证 ──

/// OIDC discovery（内部使用，不跟随重定向，防 SSRF）
async fn oidc_discover_internal(
    issuer_url: &str,
    proxy: Option<&ProxyConfig>,
    config: &Config,
) -> anyhow::Result<OidcDiscovery> {
    validate_external_idp_issuer(issuer_url)?;

    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    );

    let client = build_client(proxy, 15, config.tls_backend)?;
    let resp = client
        .get(&discovery_url)
        .header("Accept", "application/json")
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "OIDC discovery 失败 {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    let doc: OidcDiscovery = resp.json().await?;

    let normalized_doc = doc.issuer.trim_end_matches('/');
    let normalized_input = issuer_url.trim_end_matches('/');
    if normalized_doc != normalized_input {
        anyhow::bail!(
            "OIDC issuer 不匹配：期望 {}, 实际 {}",
            normalized_input,
            normalized_doc
        );
    }

    validate_external_idp_endpoint(&doc.token_endpoint)?;

    Ok(doc)
}

/// 验证 issuer URL 是否属于允许的微软域名（防 SSRF）
pub fn validate_external_idp_issuer(issuer_url: &str) -> anyhow::Result<()> {
    validate_url_against_allowlist(issuer_url, "issuer_url")
}

/// 验证 token_endpoint 是否属于允许的微软域名（防 SSRF）
pub fn validate_external_idp_endpoint(endpoint: &str) -> anyhow::Result<()> {
    validate_url_against_allowlist(endpoint, "token_endpoint")
}

fn validate_url_against_allowlist(url: &str, field: &str) -> anyhow::Result<()> {
    // 拒绝 IP 字面量（从 URL 中提取 host 部分简单检测）
    if let Some(host) = extract_host(url) {
        if host.trim_start_matches('[').trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok()
        {
            anyhow::bail!("External IdP {} 不允许使用 IP 地址", field);
        }
    }

    let lower = url.to_lowercase();
    let allowed = ALLOWED_ISSUER_SUFFIXES.iter().any(|suffix| {
        if let Some(after_scheme) = lower.find("://").map(|i| &lower[i + 3..]) {
            let host = after_scheme.split('/').next().unwrap_or("");
            host.ends_with(*suffix)
        } else {
            false
        }
    });

    if !allowed {
        anyhow::bail!(
            "External IdP {} 域名不在白名单（允许: {}）",
            field,
            ALLOWED_ISSUER_SUFFIXES.join(", ")
        );
    }
    Ok(())
}

// ──────────────────────────────────────────────────── External IdP 授权 ──

/// 构建外部 IdP 授权 URL（带 PKCE）
fn external_idp_authorize_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
    scopes: &str,
) -> String {
    format!(
        "{}?client_id={}&response_type=code&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        authorization_endpoint,
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(scopes),
        urlencoding::encode(state),
        urlencoding::encode(code_challenge),
    )
}

/// 用 authorization code 换取 external IdP token（public client，无 client_secret）
pub async fn exchange_external_idp_code(
    token_endpoint: &str,
    client_id: &str,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    scopes: &str,
    proxy: Option<&ProxyConfig>,
    config: &Config,
) -> anyhow::Result<ExternalIdpTokenResponse> {
    validate_external_idp_endpoint(token_endpoint)?;

    let client = build_client(proxy, 30, config.tls_backend)?;
    let kiro_ver = kiro_version::effective(&config.kiro_version);

    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", code),
        ("code_verifier", code_verifier),
        ("redirect_uri", redirect_uri),
        ("scope", scopes),
    ];

    let resp = client
        .post(token_endpoint)
        .header("User-Agent", format!("KiroIDE-{}", kiro_ver))
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("External IdP code 换 token 失败 {}: {}", status, body);
    }

    resp.json::<ExternalIdpTokenResponse>()
        .await
        .map_err(|e| anyhow::anyhow!("解析 external IdP token 响应失败: {}", e))
}

// ─────────────────────────────────────────────── Token 刷新（直接调用） ──

/// 刷新 External IdP token（供 token_manager 调用）
#[allow(dead_code)]
pub async fn refresh_external_idp_token_direct(
    token_endpoint: &str,
    client_id: &str,
    refresh_token: &str,
    scopes: &str,
    proxy: Option<&ProxyConfig>,
    config: &Config,
) -> anyhow::Result<ExternalIdpTokenResponse> {
    validate_external_idp_endpoint(token_endpoint)?;

    let client = build_client(proxy, 60, config.tls_backend)?;
    let kiro_ver = kiro_version::effective(&config.kiro_version);

    let form = [
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token),
        ("scope", scopes),
    ];

    let resp = client
        .post(token_endpoint)
        .header("User-Agent", format!("KiroIDE-{}", kiro_ver))
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("External IdP refresh 失败 {}: {}", status, body);
    }

    resp.json::<ExternalIdpTokenResponse>()
        .await
        .map_err(|e| anyhow::anyhow!("解析 external IdP refresh 响应失败: {}", e))
}

// ──────────────────────────────────────────────────── JWT email 提取 ──

/// 从 JWT payload 提取 email（尝试 email → preferred_username → upn）
pub fn extract_email_from_jwt(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let payload = parts[1];
    let padded = match payload.len() % 4 {
        2 => format!("{}==", payload),
        3 => format!("{}=", payload),
        _ => payload.to_string(),
    };
    let bytes = base64_decode_url(&padded)?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;

    for field in &["email", "preferred_username", "upn"] {
        if let Some(v) = json.get(field).and_then(|v| v.as_str()) {
            if !v.is_empty() && v.contains('@') {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn base64_decode_url(input: &str) -> Option<Vec<u8>> {
    let std_b64 = input.replace('-', "+").replace('_', "/");
    let chars: Vec<u8> = std_b64.bytes().collect();
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 < chars.len() {
        let a = table.iter().position(|&c| c == chars[i])? as u32;
        let b = table.iter().position(|&c| c == chars[i + 1])? as u32;
        let c = if chars[i + 2] == b'=' {
            0u32
        } else {
            table.iter().position(|&c| c == chars[i + 2])? as u32
        };
        let d = if i + 3 >= chars.len() || chars[i + 3] == b'=' {
            0u32
        } else {
            table.iter().position(|&c| c == chars[i + 3])? as u32
        };
        out.push(((a << 2) | (b >> 4)) as u8);
        if chars[i + 2] != b'=' {
            out.push(((b << 4) | (c >> 2)) as u8);
        }
        if i + 3 < chars.len() && chars[i + 3] != b'=' {
            out.push(((c << 6) | d) as u8);
        }
        i += 4;
    }
    Some(out)
}

// ──────────────────────────────────────────────────── 辅助函数 ──

fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.find("://").map(|i| &url[i + 3..])?;
    let host_and_rest = after_scheme.split('/').next().unwrap_or("");
    let host = host_and_rest.split(':').next().unwrap_or("");
    if host.is_empty() { None } else { Some(host.to_string()) }
}

fn split_path_query(path_and_query: &str) -> (&str, &str) {
    if let Some(idx) = path_and_query.find('?') {
        (&path_and_query[..idx], &path_and_query[idx + 1..])
    } else {
        (path_and_query, "")
    }
}

fn parse_query_string(query: &str) -> std::collections::HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| {
            let mut iter = pair.splitn(2, '=');
            let key = iter.next()?.to_string();
            if key.is_empty() {
                return None;
            }
            let val = iter
                .next()
                .map(|v| {
                    let s = v.replace('+', " ");
                    urlencoding::decode(&s)
                        .map(|x| x.into_owned())
                        .unwrap_or_else(|_| s)
                })
                .unwrap_or_default();
            Some((key, val))
        })
        .collect()
}


fn success_page() -> String {
    let body = "<html><head><meta charset='utf-8'><title>登录成功</title></head>\
        <body style='font-family:sans-serif;text-align:center;padding:60px'>\
        <h2>&#10003; 登录成功</h2>\
        <p>Token 已更新，请返回 Kiro Admin UI。</p>\
        <p style='color:#888;font-size:13px'>此标签页可以关闭。</p>\
        </body></html>";
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn error_page(msg: &str) -> String {
    let body = format!(
        "<html><head><meta charset='utf-8'><title>登录失败</title></head>\
        <body style='font-family:sans-serif;text-align:center;padding:60px'>\
        <h2>&#10007; 登录失败</h2><p>{}</p>\
        <p style='color:#888;font-size:13px'>请关闭此标签页并重试。</p>\
        </body></html>",
        html_escape(msg)
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
