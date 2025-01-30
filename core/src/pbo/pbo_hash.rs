use rsa::BigUint;

#[derive(Debug)]
pub struct PBOHash(pub BigUint, pub BigUint, pub BigUint);
