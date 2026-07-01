//! Kiro 请求类型定义
//!
//! 定义 Kiro API 的主请求结构

use serde::{Deserialize, Serialize};

use super::conversation::ConversationState;

/// Kiro API 请求
///
/// 用于构建发送给 Kiro API 的请求
///
/// # 示例
///
/// ```rust
/// use kiro_rs::kiro::model::requests::{
///     KiroRequest, ConversationState, CurrentMessage, UserInputMessage, Tool
/// };
///
/// // 创建简单请求
/// let state = ConversationState::new("conv-123")
///     .with_agent_task_type("vibe")
///     .with_current_message(CurrentMessage::new(
///         UserInputMessage::new("Hello", "claude-3-5-sonnet")
///     ));
///
/// let request = KiroRequest::new(state);
/// let json = request.to_json().unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KiroRequest {
    /// 对话状态
    pub conversation_state: ConversationState,
    /// Profile ARN（可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_arn: Option<String>,
    /// Additional model request fields advertised by Kiro `ListAvailableModels`.
    ///
    /// Captured Kiro CLI 2.6.0 `/effort xhigh` sends the minimal form:
    /// ```json
    /// "additionalModelRequestFields": {
    ///     "output_config": { "effort": "xhigh" }
    /// }
    /// ```
    /// Kiro IDE 0.12.301's bundled agent code additionally wraps the `output_config` schema path
    /// with `thinking: { type: "adaptive", display: "summarized" }` in the IDE endpoint path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_model_request_fields: Option<AdditionalModelRequestFields>,

    /// 推理配置（maxTokens / temperature / topP）
    ///
    /// 对齐 Go 版 Kiro-Go：不传 `maxTokens` 时，CodeWhisperer 对企业 SSO
    /// (external_idp) token 会套用较低的默认输出上限（约 6000 tokens），导致长
    /// 响应被 `ContentLengthExceededException` 截断。显式传入客户端请求的
    /// max_tokens 可覆盖该默认值。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inference_config: Option<InferenceConfig>,
}

/// CodeWhisperer 推理配置（顶层 `inferenceConfig`，字段 camelCase）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct InferenceConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
}

impl InferenceConfig {
    /// 仅在 max_tokens > 0 时构造，否则返回 None（与 Go 版 `req.MaxTokens > 0` 一致）
    pub fn from_max_tokens(max_tokens: i32) -> Option<Self> {
        if max_tokens > 0 {
            Some(Self {
                max_tokens: Some(max_tokens),
                temperature: None,
                top_p: None,
            })
        } else {
            None
        }
    }
}

/// Top-level container for the AWS Q CodeWhisperer `additionalModelRequestFields`
///
/// Note: in the real wire format the inner `output_config` field is `snake_case`,
/// unlike the outer `additionalModelRequestFields` (camelCase),
/// so this struct **must not** inherit `rename_all = "camelCase"`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdditionalModelRequestFields {
    /// Thinking mode control. Kiro model schema currently accepts adaptive/disabled
    /// and display summarized/omitted for Opus 4.6/4.7/4.8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking: Option<KiroThinkingConfig>,
    /// Output configuration (including reasoning effort)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_config: Option<KiroOutputConfig>,
    /// Alternate schema path used by some Kiro model schemas.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<KiroReasoningConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KiroThinkingConfig {
    #[serde(rename = "type")]
    pub thinking_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// The effort control field recognized by the AWS Q backend
///
/// Accepts five tiers: `low / medium / high / xhigh / max`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KiroOutputConfig {
    pub effort: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KiroReasoningConfig {
    pub effort: String,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_kiro_request_deserialize() {
        let json = r#"{
            "conversationState": {
                "conversationId": "conv-456",
                "currentMessage": {
                    "userInputMessage": {
                        "content": "Test message",
                        "modelId": "claude-3-5-sonnet",
                        "userInputMessageContext": {
                            "envState": {
                                "operatingSystem": "macos",
                                "currentWorkingDirectory": "/workspace"
                            }
                        }
                    }
                }
            }
        }"#;

        let request: KiroRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.conversation_state.conversation_id, "conv-456");
        assert_eq!(
            request
                .conversation_state
                .current_message
                .user_input_message
                .content,
            "Test message"
        );
    }

    #[test]
    fn test_additional_model_request_fields_wire_format() {
        // The wire format requires the outer key to be camelCase
        // (`additionalModelRequestFields`) while the inner key stays snake_case
        // (`output_config`), matching real Kiro CLI traffic.
        let fields = AdditionalModelRequestFields {
            thinking: None,
            output_config: Some(KiroOutputConfig {
                effort: "max".to_string(),
            }),
            reasoning: None,
        };
        let v = serde_json::to_value(&fields).unwrap();
        assert!(v.get("thinking").is_none());
        assert_eq!(v["output_config"]["effort"], "max");
        assert!(
            v.get("outputConfig").is_none(),
            "inner key must stay snake_case output_config, got {v}"
        );
    }
}
