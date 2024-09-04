


#[derive(Debug, Clone)]
pub struct FilterAttributeValueAssertion {
    pub name: String,
    pub value: String
}

#[derive(Debug, Clone)]
pub struct FilterPresent {
    pub name: String
}

#[derive(Debug, Clone)]
pub struct FilterAnd {
    pub items: Vec<Filter>
}

#[derive(Debug, Clone)]
pub enum Filter {
    Empty(),
    EqualityMatch(FilterAttributeValueAssertion),
    Present(FilterPresent),
    And(FilterAnd)
}


#[derive(Debug, Clone)]
pub struct MsgBind{
    pub version: u32,
    pub name: String,
    pub password: String
}

#[derive(Debug, Clone)]
pub struct MsgBindResponse {
    pub res: u32,
    pub matched_dn: String,
    pub diag: String
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SearchScope {
    BaseObject,
    SingleLevel,
    WholeSubtree
}
impl TryFrom<u32> for SearchScope {
    type Error = std::io::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SearchScope::BaseObject),
            1 => Ok(SearchScope::SingleLevel),
            2 => Ok(SearchScope::WholeSubtree),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown search scope"))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DerefAliases {
    NeverDerefAliases,
    DerefInSearching,
    DerefFindingBaseObj,
    DerefAlways
}
impl TryFrom<u32> for DerefAliases {
    type Error = std::io::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DerefAliases::NeverDerefAliases),
            1 => Ok(DerefAliases::DerefInSearching),
            2 => Ok(DerefAliases::DerefFindingBaseObj),
            3 => Ok(DerefAliases::DerefAlways),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown deref alias"))
        }
    }
}

#[derive(Debug, Clone)]
pub struct MsgSearch {
    pub base_object: String,
    pub scope: SearchScope,
    pub deref: DerefAliases,
    pub filter: Filter,
    pub size_limit: u32,
    pub time_limit: u32
}


#[derive(Debug, Clone)]
pub struct PartialAttribute {
    pub name: String,
    pub values: Vec<String>
}

#[derive(Debug, Clone)]
pub struct MsgSearchResult {
    pub name: String,
    pub values: Vec<PartialAttribute>
}

#[derive(Debug, Clone)]
pub struct MsgSearchResultDone {
    pub res: u32
}


#[derive(Debug, Clone)]
pub struct MsgUnbind {
}

#[derive(Debug, Clone)]
pub enum MessageParams {
    Bind(MsgBind),
    BindResponse(MsgBindResponse),
    Search(MsgSearch),
    SearchResult(MsgSearchResult),
    MsgSearchResultDone(MsgSearchResultDone),
    Unbind(MsgUnbind),
}

#[derive(Debug, Clone)]
pub struct Message {
    pub id: u32,
    pub params: MessageParams
}