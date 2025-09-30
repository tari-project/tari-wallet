use tari_common::configuration::Network;
use tari_transaction_components::{consensus::ConsensusConstants, key_manager::TransactionKeyManagerInterface};
// Reuse transaction components types
pub use tari_transaction_components::{transaction_components::WalletOutput, TransactionBuilder};

pub async fn create_mainnet_transaction_builder<TKM: TransactionKeyManagerInterface>(
    key_manager: TKM,
    at_height: u64,
) -> Result<TransactionBuilder<TKM>, anyhow::Error> {
    let constants = ConsensusConstants::for_network_at_height(Network::MainNet, at_height);
    Ok(TransactionBuilder::new(constants, key_manager, Network::MainNet).await?)
}
