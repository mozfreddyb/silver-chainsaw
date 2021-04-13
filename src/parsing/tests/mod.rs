#[cfg(test)]
pub(crate) mod fixtures {
    pub(crate) const SAMPLE_BLOCK: &str = r"doContentSecurityCheck:
  - channelURI: https://incoming.telemetry.mozilla.org/submit/telemetry/b0a4b2dc-c5b7-44ed-b0d4-41e01a9abf4e/bhr/Firefox/89.0a1/nightly/20210412213434?v=4
  - httpMethod: POST
  - loadingPrincipal: SystemPrincipal
  - triggeringPrincipal: SystemPrincipal
  - principalToInherit: nullptr
  - redirectChain:
  - internalContentPolicyType: TYPE_INTERNAL_XMLHTTPREQUEST
  - externalContentPolicyType: TYPE_XMLHTTPREQUEST
  - upgradeInsecureRequests: false
  - initialSecurityChecksDone: false
  - allowDeprecatedSystemRequests: false
  - CSP:
  - securityFlags:
    - SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL
    - SEC_COOKIES_INCLUDE
    - SEC_COOKIES_SAME_ORIGIN
    - SEC_COOKIES_OMIT";
}
