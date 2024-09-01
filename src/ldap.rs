


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

#[derive(Debug, Clone)]
pub struct MsgSearch {
    pub base_object: String,
    pub scope: u32,
    pub deref: u32,
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
pub enum MsgE {
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
    pub params: MsgE
}