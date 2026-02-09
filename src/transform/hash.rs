use crate::commands::HashAlgorithm;
use md5::{Digest as Md5Digest, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

pub fn hash(input: &[u8], algorithm: HashAlgorithm) -> String {
    match algorithm {
        HashAlgorithm::Md5 => format!("{:x}", Md5::digest(input)),
        HashAlgorithm::Sha1 => format!("{:x}", Sha1::digest(input)),
        HashAlgorithm::Sha256 => format!("{:x}", Sha256::digest(input)),
        HashAlgorithm::Sha512 => format!("{:x}", Sha512::digest(input)),
    }
}

#[cfg(test)]
mod test {
    use super::hash;
    use crate::commands::HashAlgorithm;

    #[test]
    fn md5_vector() {
        assert_eq!(
            hash(b"abc", HashAlgorithm::Md5),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }

    #[test]
    fn sha1_vector() {
        assert_eq!(
            hash(b"abc", HashAlgorithm::Sha1),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn sha256_vector() {
        assert_eq!(
            hash(b"abc", HashAlgorithm::Sha256),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha512_vector() {
        assert_eq!(
            hash(b"abc", HashAlgorithm::Sha512),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn empty_input_hash() {
        assert_eq!(
            hash(b"", HashAlgorithm::Sha256),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
