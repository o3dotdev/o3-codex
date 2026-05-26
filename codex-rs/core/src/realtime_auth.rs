use std::sync::Arc;

use codex_api::Provider as ApiProvider;
use codex_api::SharedAuthProvider;
use codex_app_server_protocol::AuthMode;
use codex_model_provider::BearerAuthProvider;
use codex_model_provider_info::ModelProviderInfo;
use codex_protocol::error::CodexErr;
use codex_protocol::error::Result as CodexResult;
use http::HeaderMap;
use http::HeaderValue;
use http::header::AUTHORIZATION;

pub(crate) const O3_CODE_REALTIME_API_KEY_ENV_VAR: &str = "O3_CODE_REALTIME_API_KEY";
pub(crate) const O3_CODE_REALTIME_BASE_URL_ENV_VAR: &str = "O3_CODE_REALTIME_BASE_URL";

#[derive(Clone)]
pub(crate) struct RealtimeAuthRoute {
    pub(crate) api_provider: ApiProvider,
    pub(crate) api_auth: SharedAuthProvider,
    pub(crate) auth_headers: HeaderMap,
    #[cfg(test)]
    pub(crate) api_key: String,
}

pub(crate) fn resolve_realtime_auth_route(
    provider: &ModelProviderInfo,
    configured_base_url: Option<&str>,
) -> CodexResult<RealtimeAuthRoute> {
    let api_key = read_non_empty_env(O3_CODE_REALTIME_API_KEY_ENV_VAR).ok_or_else(|| {
        CodexErr::InvalidRequest(format!(
            "realtime conversation requires {O3_CODE_REALTIME_API_KEY_ENV_VAR}"
        ))
    })?;
    let mut api_provider = provider.to_api_provider(Some(AuthMode::ApiKey))?;
    let base_url = read_non_empty_env(O3_CODE_REALTIME_BASE_URL_ENV_VAR)
        .or_else(|| {
            configured_base_url
                .map(str::trim)
                .filter(|url| !url.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| api_provider.base_url.clone());
    api_provider.base_url = base_url;

    let auth_value = bearer_header_value(&api_key)?;
    let mut auth_headers = HeaderMap::new();
    auth_headers.insert(AUTHORIZATION, auth_value);

    Ok(RealtimeAuthRoute {
        api_provider,
        api_auth: Arc::new(BearerAuthProvider::new(api_key.clone())),
        auth_headers,
        #[cfg(test)]
        api_key,
    })
}

fn read_non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn bearer_header_value(api_key: &str) -> CodexResult<HeaderValue> {
    HeaderValue::from_str(&format!("Bearer {api_key}"))
        .map_err(|err| CodexErr::InvalidRequest(format!("invalid realtime api key header: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_model_provider_info::ModelProviderInfo;
    use serial_test::serial;
    use std::ffi::OsString;

    struct EnvVarGuard {
        key: &'static str,
        original: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var_os(key);
            // SAFETY: tests using this guard are serialized on `realtime_auth_env`.
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, original }
        }

        fn remove(key: &'static str) -> Self {
            let original = std::env::var_os(key);
            // SAFETY: tests using this guard are serialized on `realtime_auth_env`.
            unsafe {
                std::env::remove_var(key);
            }
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            // SAFETY: tests using this guard are serialized on `realtime_auth_env`.
            unsafe {
                match &self.original {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[test]
    #[serial(realtime_auth_env)]
    fn resolves_default_realtime_api_route_from_o3_key_only() {
        let _api_key = EnvVarGuard::set(O3_CODE_REALTIME_API_KEY_ENV_VAR, "sk-realtime");
        let _base_url = EnvVarGuard::remove(O3_CODE_REALTIME_BASE_URL_ENV_VAR);
        let provider = ModelProviderInfo::create_openai_provider(/*base_url*/ None);

        let route = resolve_realtime_auth_route(&provider, /*configured_base_url*/ None)
            .expect("realtime route should resolve");

        assert_eq!(route.api_provider.base_url, "https://api.openai.com/v1");
        assert_eq!(route.api_key, "sk-realtime");
        assert_eq!(
            route
                .auth_headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer sk-realtime")
        );
    }

    #[test]
    #[serial(realtime_auth_env)]
    fn o3_base_url_overrides_configured_realtime_base_url() {
        let _api_key = EnvVarGuard::set(O3_CODE_REALTIME_API_KEY_ENV_VAR, "sk-realtime");
        let _base_url = EnvVarGuard::set(
            O3_CODE_REALTIME_BASE_URL_ENV_VAR,
            "http://127.0.0.1:9000/v1",
        );
        let provider = ModelProviderInfo::create_openai_provider(/*base_url*/ None);

        let route = resolve_realtime_auth_route(&provider, Some("http://127.0.0.1:8000/v1"))
            .expect("realtime route should resolve");

        assert_eq!(route.api_provider.base_url, "http://127.0.0.1:9000/v1");
    }

    #[test]
    #[serial(realtime_auth_env)]
    fn missing_o3_key_does_not_fall_back_to_general_keys_or_provider_auth() {
        let _api_key = EnvVarGuard::remove(O3_CODE_REALTIME_API_KEY_ENV_VAR);
        let _base_url = EnvVarGuard::remove(O3_CODE_REALTIME_BASE_URL_ENV_VAR);
        let _openai_key = EnvVarGuard::set("OPENAI_API_KEY", "sk-openai");
        let _codex_key = EnvVarGuard::set("CODEX_API_KEY", "sk-codex");
        let provider = ModelProviderInfo {
            env_key: Some("PATH".to_string()),
            experimental_bearer_token: Some("provider-token".to_string()),
            ..ModelProviderInfo::create_openai_provider(/*base_url*/ None)
        };

        let err = match resolve_realtime_auth_route(&provider, /*configured_base_url*/ None) {
            Ok(_) => panic!("general keys must not be realtime fallbacks"),
            Err(err) => err,
        };

        assert_eq!(
            err.to_string(),
            format!("realtime conversation requires {O3_CODE_REALTIME_API_KEY_ENV_VAR}")
        );
    }
}
