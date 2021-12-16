mod v1;
mod v2;

pub enum Header<'a> {
    VersionOne(v1::Header<'a>),
    VersionTwo(v2::Header<'a>)
}