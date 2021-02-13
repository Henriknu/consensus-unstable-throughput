pub use liberasurecode::{ErasureCoder, Error, Result};
pub use std::num::NonZeroUsize;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_it_works() {
        assert_eq!(erasure_example(), Ok(()))
    }

    #[test]
    fn test_reconstruct() {
        assert_eq!(erasure_reconstruct(), Ok(()))
    }

    fn erasure_example() -> Result<()> {
        let data_fragments = NonZeroUsize::new(4).ok_or("too few fragments").unwrap();
        let parity_fragments = NonZeroUsize::new(2).ok_or("too few fragments").unwrap();
        let mut coder = ErasureCoder::new(data_fragments, parity_fragments)?;
        let input: Vec<_> = (0..10000).map(|_| 23u8).collect();

        // Encodes `input` to data and parity fragments
        let fragments = coder.encode(&input)?;

        // Decodes the original data from the fragments (or a part of those)
        assert_eq!(Ok(&input), coder.decode(&fragments[0..]).as_ref());
        println!("Decoded: {:?}", coder.decode(&fragments[0..]).unwrap());
        assert_eq!(Ok(&input), coder.decode(&fragments[1..]).as_ref());
        println!("Decoded: {:?}", coder.decode(&fragments[1..]).unwrap());
        assert_eq!(Ok(&input), coder.decode(&fragments[2..]).as_ref());
        println!("Decoded: {:?}", coder.decode(&fragments[2..]).unwrap());
        assert_eq!(
            Err(Error::InsufficientFragments),
            coder.decode(&fragments[3..])
        );

        Ok(())
    }

    fn erasure_reconstruct() -> Result<()> {
        let data_fragments = NonZeroUsize::new(4).ok_or("too few fragments").unwrap();
        let parity_fragments = NonZeroUsize::new(2).ok_or("too few fragments").unwrap();
        let mut coder = ErasureCoder::new(data_fragments, parity_fragments)?;
        let input = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];

        // Encodes `input` to data and parity fragments
        let fragments = coder.encode(&input)?;

        assert_eq!(fragments.len(), 6);

        println!(
            "Fragments len: {:?}",
            fragments.iter().map(|f| f.len()).sum::<usize>()
        );

        // Some fragments were lost..

        let mut available_fragments = fragments.clone();
        available_fragments.remove(0);

        let reconstructed_fragment = coder.reconstruct(0, available_fragments.iter()).unwrap();

        assert_eq!(reconstructed_fragment, fragments[0]);

        Ok(())
    }
}
