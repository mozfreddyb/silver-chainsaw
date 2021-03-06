use serde::de::{Deserialize, Deserializer, Unexpected, Visitor};
use serde::ser::{Serialize, Serializer};
use serde_json::Error;
use std::fmt;
use std::str::FromStr;
use url::Url;

#[derive(Debug, PartialEq)]
pub enum Principal {
    ContentPrincipal(String),
    ExpandedPrincipal(Vec<Principal>),
    SystemPrincipal,
    NullPrincipal,
    NullPtr,
}

impl<'de> Deserialize<'de> for Principal {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Principal, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PrincipalVisitor;

        impl<'de> Visitor<'de> for PrincipalVisitor {
            type Value = Principal;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON Principal")
            }

            fn visit_str<E>(self, value: &str) -> Result<Principal, E>
            where
                E: serde::de::Error,
            {
                //Principal::from_str(value)
                match Principal::from_str(value) {
                    Ok(p) => Ok(p),
                    Err(e) => {
                        println!("err {}", e);
                        Err(serde::de::Error::custom("not a JSON Principal"))
                    }
                }
            }
        }
        deserializer.deserialize_any(PrincipalVisitor)
    }
}

impl Serialize for Principal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 3 is the number of fields in the struct.
        serializer.serialize_str(&self.to_string())
    }
}

impl FromStr for Principal {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // serde::de::Error
        match text {
            "SystemPrincipal" => Ok(Principal::SystemPrincipal),
            "NullPrincipal" => Ok(Principal::NullPrincipal),
            "nullptr" => Ok(Principal::NullPtr),
            prin_str => {
                // parse URL
                //if starts with [Expa]
                if prin_str.starts_with("[Expanded Principal [") && prin_str.ends_with("]]") {
                    let mut principals: Vec<Principal> = vec![];
                    let str_len = prin_str.len();
                    let inner = &prin_str[21..str_len - 2];
                    for value in inner.split(' ') {
                        if let Ok(principal) = Principal::from_str(value) {
                            principals.push(principal);
                        } else {
                            return Err(serde::de::Error::invalid_type(
                                Unexpected::Str("Error parsing inner principal"),
                                &value,
                            ));
                        }
                    }
                    Ok(Principal::ExpandedPrincipal(principals))
                } else if let Ok(url) = Url::parse(prin_str) {
                    Ok(Principal::ContentPrincipal(url.into_string()))
                } else {
                    Err(serde::de::Error::invalid_type(
                        Unexpected::Str("Error parsing into principal"),
                        &prin_str,
                    ))
                }
            }
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s: String = match self {
            Principal::SystemPrincipal => "SystemPrincipal".into(),
            Principal::NullPrincipal => "NullPrincipal".into(),
            Principal::NullPtr => "nullptr".into(),
            Principal::ExpandedPrincipal(v) => {
                let mut t = "[Expanded Principal [".to_string();
                let mut i = v.len();
                for u in v {
                    t.push_str(&(u.to_string()));
                    if i > 1 {
                        t.push(' ');
                    }
                    i -= 1;
                }
                t.push_str("]]");
                t
            }
            Principal::ContentPrincipal(u) => u.clone(),
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests_principal_from_str {
    use super::Principal;
    use std::str::FromStr;

    #[test]
    fn parse_http_url() {
        assert_eq!(
            Principal::from_str("http://example.com/").unwrap(),
            Principal::ContentPrincipal("http://example.com/".to_string())
        );
    }

    #[test]
    fn parse_about_url() {
        assert_eq!(
            Principal::from_str("about:config").unwrap(),
            Principal::ContentPrincipal("about:config".to_string())
        );
    }

    #[test]
    fn parse_null_principal() {
        assert_eq!(
            Principal::from_str("NullPrincipal").unwrap(),
            Principal::NullPrincipal
        );
    }

    #[test]
    fn parse_nullptr_principal() {
        assert_eq!(Principal::from_str("nullptr").unwrap(), Principal::NullPtr);
    }

    #[test]
    fn parse_expanded_principal_1() {
        assert_eq!(
            Principal::from_str("[Expanded Principal [https://example.com/]]").unwrap(),
            Principal::ExpandedPrincipal(vec![Principal::ContentPrincipal(
                "https://example.com/".to_string()
            )])
        );
    }

    #[test]
    fn parse_expanded_principal_2() {
        assert_eq!(
            Principal::from_str("[Expanded Principal [moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/ https://example.com/]]").unwrap(),
            Principal::ExpandedPrincipal(vec![
                Principal::ContentPrincipal("moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/".to_string()),
                Principal::ContentPrincipal("https://example.com/".to_string())])
        );
    }

    #[test]
    fn parse_expanded_principal_2_preserves_order() {
        assert_eq!(
            Principal::from_str("[Expanded Principal [https://example.com/ moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/]]").unwrap(),
            Principal::ExpandedPrincipal(vec![
                Principal::ContentPrincipal("https://example.com/".to_string()),
                Principal::ContentPrincipal("moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/".to_string())])
        );
    }
}

#[cfg(test)]
mod tests_principal_to_str {
    use super::Principal;

    #[test]
    fn parse_http_url() {
        assert_eq!(
            "http://example.com/",
            Principal::ContentPrincipal("http://example.com/".to_string()).to_string()
        );
    }

    #[test]
    fn parse_about_url() {
        assert_eq!(
            "about:config",
            Principal::ContentPrincipal("about:config".to_string()).to_string()
        );
    }

    #[test]
    fn parse_null_principal() {
        assert_eq!("NullPrincipal", Principal::NullPrincipal.to_string());
    }

    #[test]
    fn parse_nullptr_principal() {
        assert_eq!("nullptr", Principal::NullPtr.to_string());
    }

    #[test]
    fn parse_expanded_principal_1() {
        assert_eq!(
            "[Expanded Principal [https://example.com/]]",
            Principal::ExpandedPrincipal(vec![Principal::ContentPrincipal(
                "https://example.com/".to_string()
            )])
            .to_string()
        );
    }

    #[test]
    fn parse_expanded_principal_2() {
        assert_eq!(
            "[Expanded Principal [moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/ https://example.com/]]",
            Principal::ExpandedPrincipal(vec![
                Principal::ContentPrincipal("moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/".to_string()),
                Principal::ContentPrincipal("https://example.com/".to_string())]).to_string()
        );
    }

    #[test]
    fn parse_expanded_principal_2_preserves_order() {
        assert_eq!(
            "[Expanded Principal [https://example.com/ moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/]]",
            Principal::ExpandedPrincipal(vec![
                Principal::ContentPrincipal("https://example.com/".to_string()),
                Principal::ContentPrincipal("moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/".to_string())]).to_string()
        );
    }
}
