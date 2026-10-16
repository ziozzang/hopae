//! The message catalogue of the authentication explain API: one entry per
//! stable reason code, in English and Korean. A console that keeps its own
//! catalogue uses `message_key`; `message` is this catalogue's text in the
//! request's language (`accept-language`, English by default).

use crate::portal::i18n::Lang;

/// `(short code, English, Korean)`. The wire code is `hopae.<short>` and the
/// message key `hopae.explain.<short>`.
pub const MESSAGES: &[(&str, &str, &str)] = &[
    (
        "allowed",
        "The request would be allowed.",
        "요청이 허용됩니다.",
    ),
    (
        "unknown_app",
        "No application is registered for this host.",
        "이 호스트에 등록된 애플리케이션이 없습니다.",
    ),
    (
        "app_disabled",
        "The application for this host is disabled.",
        "이 호스트의 애플리케이션이 비활성화되어 있습니다.",
    ),
    (
        "port_not_allowed",
        "The port is not one of the application's ports.",
        "포트가 애플리케이션의 포트 목록에 없습니다.",
    ),
    (
        "insecure_transport",
        "Plain HTTP is refused while secure cookies are configured.",
        "보안 쿠키를 쓰는 설정에서는 HTTP 요청을 거부합니다.",
    ),
    (
        "contract_violation",
        "The target URL is not a valid return target.",
        "대상 URL이 유효한 반환 대상이 아닙니다.",
    ),
    (
        "path_not_canonical",
        "The path is not canonical; the gateway refuses it.",
        "경로가 정규형이 아니어서 게이트웨이가 거부합니다.",
    ),
    (
        "reserved_path",
        "The path is in the reserved /_hopae namespace.",
        "경로가 예약된 /_hopae 이름공간에 있습니다.",
    ),
    (
        "entry_point",
        "The path is a Hopae entry point, not an access decision.",
        "경로가 Hopae 진입점이며 접근 결정 대상이 아닙니다.",
    ),
    (
        "login_required",
        "There is no session: the request is sent to sign in.",
        "세션이 없어 요청을 로그인으로 보냅니다.",
    ),
    (
        "handle_absent",
        "The session has no handle on this host: the browser goes to the portal, which hands a live session over without a new sign-in.",
        "세션에 이 호스트용 핸들이 없어 브라우저를 포털로 보내며, 살아 있는 세션은 다시 로그인하지 않고 넘겨받습니다.",
    ),
    (
        "unknown_handle",
        "The session does not exist.",
        "세션이 존재하지 않습니다.",
    ),
    (
        "session_terminated",
        "The session was terminated.",
        "세션이 종료되었습니다.",
    ),
    (
        "idle",
        "An idle timeout has expired.",
        "유휴 시간이 만료되었습니다.",
    ),
    (
        "absolute",
        "An absolute lifetime has expired.",
        "절대 수명이 만료되었습니다.",
    ),
    (
        "clock_skew",
        "A stored time lies in the future beyond the tolerance; the request is answered as unavailable.",
        "저장된 시각이 허용 범위를 넘어 미래에 있어 요청이 일시 불가로 응답됩니다.",
    ),
    (
        "binding_ip",
        "The client address does not match the session's binding.",
        "클라이언트 주소가 세션의 바인딩과 일치하지 않습니다.",
    ),
    (
        "binding_ua",
        "The user agent does not match the session's binding.",
        "사용자 에이전트가 세션의 바인딩과 일치하지 않습니다.",
    ),
    (
        "binding_not_evaluated",
        "No client address was given, so the binding policy was not evaluated.",
        "클라이언트 주소가 주어지지 않아 바인딩 정책을 평가하지 않았습니다.",
    ),
    (
        "user_disabled",
        "The user is disabled.",
        "사용자가 비활성화되어 있습니다.",
    ),
    (
        "authz_change",
        "The user's authorization changed since sign-in and this application ends such sessions.",
        "로그인 이후 사용자의 권한 정보가 바뀌었고 이 애플리케이션은 그런 세션을 종료합니다.",
    ),
    (
        "step_up_required",
        "A step-up rule requires a higher assurance level or a fresher second factor.",
        "단계 상향 규칙이 더 높은 보증 수준이나 더 최근의 2단계 인증을 요구합니다.",
    ),
    (
        "step_up_unavailable",
        "A step-up is required but no second factor is configured, so the request is refused.",
        "단계 상향이 필요하지만 2단계 인증이 설정되어 있지 않아 요청을 거부합니다.",
    ),
    (
        "reauth_required",
        "The sign-in is too old for this path; the user must sign in again.",
        "이 경로에 비해 로그인이 오래되어 다시 로그인해야 합니다.",
    ),
    (
        "subject_unknown",
        "The subject is not known to Hopae; a sign-in creates or links an account.",
        "Hopae가 알지 못하는 주체이며, 로그인하면 계정이 만들어지거나 연결됩니다.",
    ),
    (
        "subject_deleted",
        "The subject was deleted; a new sign-in creates a different subject.",
        "삭제된 주체이며, 새로 로그인하면 다른 주체가 만들어집니다.",
    ),
    (
        "service_credential_required",
        "A service profile serves this host and port and does not fall back to browser sessions.",
        "이 호스트와 포트는 서비스 프로필이 처리하며 브라우저 세션으로 대체하지 않습니다.",
    ),
    (
        "service_profile_absent",
        "A service credential is presented but no service profile serves this host and port.",
        "서비스 자격 증명을 제시했지만 이 호스트와 포트를 처리하는 서비스 프로필이 없습니다.",
    ),
    (
        "service_principal_unknown",
        "The principal is not an API-key subject of this profile.",
        "주체가 이 프로필의 API 키 주체가 아닙니다.",
    ),
    (
        "credential_expired",
        "The service credential has expired.",
        "서비스 자격 증명이 만료되었습니다.",
    ),
    (
        "network_denied",
        "The client address is outside the profile's networks.",
        "클라이언트 주소가 프로필의 네트워크 범위 밖에 있습니다.",
    ),
    (
        "network_not_evaluated",
        "No client address was given, so the profile's networks were not evaluated.",
        "클라이언트 주소가 주어지지 않아 프로필의 네트워크 범위를 평가하지 않았습니다.",
    ),
    (
        "eligibility_denied",
        "The profile's eligibility script refuses this principal.",
        "프로필의 적격성 스크립트가 이 주체를 거부합니다.",
    ),
    (
        "eligibility_unavailable",
        "The profile's eligibility script could not run now; the request is answered as unavailable.",
        "프로필의 적격성 스크립트를 지금 실행할 수 없어 요청이 일시 불가로 응답됩니다.",
    ),
    (
        "remote_verifier",
        "A remote connector verifies this credential at request time; its verdict cannot be simulated.",
        "자격 증명을 요청 시점에 원격 커넥터가 검증하므로 결과를 모의할 수 없습니다.",
    ),
    (
        "machine_step_up",
        "Service and workload principals have AAL 0 and cannot satisfy a step-up rule.",
        "서비스와 워크로드 주체는 AAL 0이어서 단계 상향 규칙을 만족할 수 없습니다.",
    ),
    (
        "authority_unavailable",
        "Service authentication is being republished; requests are answered as unavailable.",
        "서비스 인증을 다시 게시하는 중이어서 요청이 일시 불가로 응답됩니다.",
    ),
];

/// The catalogue entry of a short code (`step_up_required`).
pub fn message(code: &str, lang: Lang) -> Option<&'static str> {
    MESSAGES
        .iter()
        .find(|(c, _, _)| *c == code)
        .map(|(_, en, ko)| match lang {
            Lang::Ko => *ko,
            _ => *en,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_both_languages_once() {
        let mut seen = std::collections::HashSet::new();
        for (code, en, ko) in MESSAGES {
            assert!(seen.insert(*code), "{code} twice");
            assert!(
                code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{code}"
            );
            assert!(!en.is_empty() && en.is_ascii(), "{code}");
            assert!(ko.chars().any(|c| ('가'..='힣').contains(&c)), "{code}");
        }
        assert_eq!(
            message("idle", Lang::Ko),
            Some("유휴 시간이 만료되었습니다.")
        );
        assert_eq!(message("nope", Lang::En), None);
    }
}
