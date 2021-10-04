use common::mm_error::MmError;

#[derive(Debug, Serialize, Deserialize)]
pub struct SolanaTransactionTransfer {
    pub slot: u64,
    pub transaction: Transaction,
    pub meta: Meta,
    #[serde(rename = "blockTime")]
    pub block_time: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Meta {
    err: Option<serde_json::Value>,
    status: Status,
    pub fee: u64,
    #[serde(rename = "preBalances")]
    pre_balances: Vec<u64>,
    #[serde(rename = "postBalances")]
    post_balances: Vec<u64>,
    #[serde(rename = "innerInstructions")]
    inner_instructions: Vec<Option<serde_json::Value>>,
    #[serde(rename = "logMessages")]
    log_messages: Vec<String>,
    #[serde(rename = "preTokenBalances")]
    pre_token_balances: Vec<Option<serde_json::Value>>,
    #[serde(rename = "postTokenBalances")]
    post_token_balances: Vec<Option<serde_json::Value>>,
    rewards: Vec<Option<serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    #[serde(rename = "Ok")]
    ok: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub signatures: Vec<String>,
    pub message: Message,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    #[serde(rename = "accountKeys")]
    account_keys: Vec<AccountKey>,
    #[serde(rename = "recentBlockhash")]
    recent_blockhash: String,
    instructions: Vec<Instruction>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountKey {
    pubkey: String,
    writable: bool,
    signer: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Instruction {
    program: String,
    #[serde(rename = "programId")]
    program_id: String,
    parsed: Parsed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Parsed {
    info: Info,
    #[serde(rename = "type")]
    parsed_type: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Info {
    pub destination: String,
    pub lamports: u64,
    pub source: String,
}

#[derive(Debug)]
pub enum TransferInstructionError {
    NotAnyTransferInstruction,
    IsNotTransfer,
}

impl SolanaTransactionTransfer {
    pub fn extract_first_transfer_instructions(&self) -> Result<Info, MmError<TransferInstructionError>> {
        if self.transaction.message.instructions.is_empty() {
            return MmError::err(TransferInstructionError::NotAnyTransferInstruction);
        }

        let parsed = &self.transaction.message.instructions[0].parsed;
        if parsed.parsed_type != "transfer" {
            return MmError::err(TransferInstructionError::IsNotTransfer);
        }
        Ok(parsed.info.clone())
    }
}
