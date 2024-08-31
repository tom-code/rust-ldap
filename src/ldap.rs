


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
    AttributeValueAssertion(FilterAttributeValueAssertion),
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
pub struct MsgSearch {
    pub base_object: String,
    pub scope: u32,
    pub deref: u32,
    pub filter: Filter,
    pub size_limit: u32,
    pub time_limit: u32
}

#[derive(Debug, Clone)]
pub struct MsgUnbind {
}

#[derive(Debug, Clone)]
pub enum MsgE {
    Bind(MsgBind),
    Search(MsgSearch),
    Unbind(MsgUnbind)
}

#[derive(Debug, Clone)]
pub struct Message {
    pub id: u32,
    pub params: MsgE
}