pub struct Transaction {
    header: TransactionHeader,
    header_signature: String,
    payload: Vec<u8>,
}

pub struct TransactionHeader {}
