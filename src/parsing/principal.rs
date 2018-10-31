use std::str::FromStr;
use std::fmt;
use serde_json::Error;
use serde::de::{Deserialize, Deserializer, Visitor, Unexpected};
use url::Url;


#[derive(Debug, PartialEq, Serialize)]
pub enum Principal {
    URLPrincipal(String),
    ///XXX decide whether we need URL parsing/validation
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

            /*#[cfg(feature = "arbitrary_precision")]
            #[inline]
            fn visit_map<V>(self, mut visitor: V) -> Result<Principal, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let value = visitor.next_key::<PrincipalKey>()?;
                if value.is_none() {
                    return Err(de::Error::invalid_type(Unexpected::Map, &self));
                }
                let v: PrincipalFromString = visitor.next_value()?;
                Ok(v.value)
            }*/
        }

        deserializer.deserialize_any(PrincipalVisitor)
    }
}

impl FromStr for Principal {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> { // serde::de::Error
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
                        let p = Principal::from_str(value);
                        if p.is_ok() {
                            principals.push(p.unwrap());
                        } else {
                            panic!("Error parsing inner principal in Expanded Principal: {}", &value);
                        }
                    }
                    Ok(Principal::ExpandedPrincipal(principals))
                } else {
                    let url = Url::parse(prin_str);
                    if url.is_ok() {
                        Ok(Principal::URLPrincipal(url.unwrap().into_string()))
                    } else {
                        Err(serde::de::Error::invalid_type(Unexpected::Str("Error parsing into principal"), &prin_str))
                    }
                }
            }
        }
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
            Principal::URLPrincipal("http://example.com/".to_string())
        );
    }

    #[test]
    fn parse_about_url() {
        assert_eq!(
            Principal::from_str("about:config").unwrap(),
            Principal::URLPrincipal("about:config".to_string())
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
            Principal::ExpandedPrincipal(vec![Principal::URLPrincipal(
                "https://example.com/".to_string()
            )])
        );
    }

    #[test]
    fn parse_expanded_principal_2() {
        assert_eq!(
            Principal::from_str("[Expanded Principal [moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/ https://example.com/]]").unwrap(),
            Principal::ExpandedPrincipal(vec![
                Principal::URLPrincipal("moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/".to_string()),
                Principal::URLPrincipal("https://example.com/".to_string())])
        );
    }

    #[test]
    fn parse_expanded_principal_2_preserves_order() {
        assert_eq!(
            Principal::from_str("[Expanded Principal [https://example.com/ moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/]]").unwrap(),
            Principal::ExpandedPrincipal(vec![
                Principal::URLPrincipal("https://example.com/".to_string()),
                Principal::URLPrincipal("moz-extension://3767278d-dead-beef-be81-c0ffeec0ffee/".to_string())])
        );
    }
}
