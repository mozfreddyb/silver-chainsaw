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

    pub(crate) const REDIRECT_CSP_BLOCK: &str = r#"doContentSecurityCheck:
      - channelURI: https://www.raspberrypi.org/
      - httpMethod: GET
      - loadingPrincipal: https://www.raspberrypi.org/blog/edge-impulse-and-tinyml-on-raspberry-pi/
      - triggeringPrincipal: https://www.raspberrypi.org/blog/edge-impulse-and-tinyml-on-raspberry-pi/
      - principalToInherit: nullptr
      - redirectChain:
        -: https://www.raspberrypi.org/?wordfence_syncAttackData=14.395
      - internalContentPolicyType: TYPE_INTERNAL_SCRIPT_PRELOAD
      - externalContentPolicyType: TYPE_SCRIPT
      - upgradeInsecureRequests: true
      - initialSecurityChecksDone: true
      - allowDeprecatedSystemRequests: false
      - CSP:
        - "upgrade-insecure-requests; default-src https: data: 'unsafe-inline' 'unsafe-eval'; img-src https: 'self' blob: data:; report-uri https://e4f0000014a954844abf8fe208613d8.report-uri.com/r/d/csp/enforce"
      - securityFlags:
        - SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL
        - SEC_ALLOW_CHROME"#;
}
