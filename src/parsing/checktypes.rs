use crate::parsing::policytypes::nsContentPolicyType;
use crate::parsing::principal::Principal;
use crate::parsing::ProcessType;

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub(crate) struct WrappedCheck {
    pub(crate) doContentSecurityCheck: Vec<CheckLine>,
}
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case, non_camel_case_types)]
pub enum CheckLine {
    channelURI(String),
    httpMethod(Option<String>), // only shown for http channels
    loadingPrincipal(Principal),
    triggeringPrincipal(Principal),
    principalToInherit(Principal),
    redirectChain(Option<Vec<String>>),
    internalContentPolicyType(nsContentPolicyType),
    externalContentPolicyType(nsContentPolicyType),
    upgradeInsecureRequests(bool),
    initialSecurityChecksDone(bool),
    allowDeprecatedSystemRequests(bool),
    CSP(Option<Vec<String>>),
    securityFlags(Vec<String>),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ContentSecurityCheck {
    pub(crate) process_type: ProcessType,
    pub(crate) channel_uri: String,
    pub(crate) http_method: Option<String>, // only shown for http channels
    pub(crate) loading_principal: Principal,
    pub(crate) triggering_principal: Principal,
    pub(crate) principal_to_inherit: Principal,
    pub(crate) redirect_chain: Option<Vec<String>>,
    pub(crate) internal_content_policy_type: nsContentPolicyType,
    pub(crate) external_content_policy_type: nsContentPolicyType,
    pub(crate) upgrade_insecure_requests: bool,
    pub(crate) initial_security_checks_done: bool,
    pub(crate) allow_deprecated_system_requests: bool,
    pub(crate) csp: Option<Vec<String>>, // key always present, might be empty value
    pub(crate) security_flags: Vec<String>,
}
impl From<Vec<CheckLine>> for ContentSecurityCheck {
    fn from(lines: Vec<CheckLine>) -> Self {
        let mut channel_uri: String = "XX-MISSING_URL".to_string();
        let mut http_method: Option<String> = None;
        let mut loading_principal: Principal =
            Principal::ContentPrincipal("xxx://missing-url".to_string());
        let mut triggering_principal: Principal =
            Principal::ContentPrincipal("xxx://missing-url".to_string());
        let mut principal_to_inherit: Principal =
            Principal::ContentPrincipal("xxx://missing-url".to_string());
        let mut redirect_chain: Option<Vec<String>> = None;
        let mut internal_content_policy_type: nsContentPolicyType =
            nsContentPolicyType::TYPE_INVALID;
        let mut external_content_policy_type: nsContentPolicyType =
            nsContentPolicyType::TYPE_INVALID;
        let mut upgrade_insecure_requests: bool = false;
        let mut initial_security_checks_done: bool = false;
        let mut allow_deprecated_system_requests: bool = false;
        let mut csp: Option<Vec<String>> = None;
        let mut security_flags: Vec<String> = vec![];

        for line in lines {
            match line {
                CheckLine::channelURI(uri) => channel_uri = uri,
                CheckLine::httpMethod(m) => http_method = m,
                CheckLine::loadingPrincipal(lp) => loading_principal = lp,
                CheckLine::triggeringPrincipal(tp) => triggering_principal = tp,
                CheckLine::principalToInherit(pti) => principal_to_inherit = pti,
                CheckLine::redirectChain(rc) => redirect_chain = rc,
                CheckLine::internalContentPolicyType(it) => internal_content_policy_type = it,
                CheckLine::externalContentPolicyType(et) => external_content_policy_type = et,
                CheckLine::upgradeInsecureRequests(uir) => upgrade_insecure_requests = uir,
                CheckLine::initialSecurityChecksDone(isd) => initial_security_checks_done = isd,
                CheckLine::allowDeprecatedSystemRequests(adsr) => {
                    allow_deprecated_system_requests = adsr
                }
                CheckLine::CSP(c) => csp = c,
                CheckLine::securityFlags(sf) => security_flags = sf,
            }
        }
        ContentSecurityCheck {
            process_type: ProcessType::Unknown,
            channel_uri,
            http_method,
            loading_principal,
            triggering_principal,
            principal_to_inherit,
            redirect_chain,
            internal_content_policy_type,
            external_content_policy_type,
            upgrade_insecure_requests,
            initial_security_checks_done,
            allow_deprecated_system_requests,
            csp,
            security_flags,
        }
    }
}
