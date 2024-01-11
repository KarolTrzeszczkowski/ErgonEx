use crate::address::Address;
use bitcoinsuite_chronik_client::ChronikClient;
use serde::{Serialize, Deserialize};
use crate::incomplete_tx::{IncompleteTx, Utxo};
use crate::tx::{Tx, TxOutpoint, tx_hex_to_hash};
use crate::outputs::{P2PKHOutput};
use std::collections::HashSet;
use rand::thread_rng;
use rand::RngCore;
use secp256k1::{Secp256k1, PublicKey, SecretKey};
use hex;
use reqwest;



pub struct Wallet {
    secret_key: secp256k1::SecretKey,
    address: Address,
    chronik_client: ChronikClient, // Add the ChronikClient as a member
}

#[derive(Deserialize, Serialize, Debug)]
pub struct UtxoEntry {
    pub txid: String,
    pub vout: u32,
    pub amount: f64,
    pub satoshis: u64,
}


#[derive(Deserialize, Serialize, Debug)]
struct UtxoResult {
    utxos: Vec<UtxoEntry>,
}

impl Wallet {
    pub fn from_secret(secret: &[u8]) -> Result<Wallet, Box<dyn std::error::Error>> {
        let secret_key = secp256k1::SecretKey::from_slice(&secret)?;
        let curve = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&curve, &secret_key);
        let addr = Address::from_pub_key("ergon", &pk);
        let chronik_url = "https://chronik.be.cash/xrg";
        let chronik_client = ChronikClient::new(chronik_url.to_string())?;


        Ok(Wallet {
            secret_key,
            address: addr,
            chronik_client, // Initialize the ChronikClient here
        })
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn get_new_address(&self) -> Result<(Address, SecretKey), secp256k1::Error> {
        let secp = Secp256k1::new();
        let mut rng = thread_rng();
        
        // Generate a random 32-byte array
        let mut secret_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_key_bytes);
    
        // Create a secret key from the random bytes
        let secret_key = SecretKey::from_slice(&secret_key_bytes)
            .expect("32 bytes, within curve order, can't fail");
    
        // Derive the public key from the secret key
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    
        // Create an address from the public key
        let address = Address::from_pub_key("ergon", &public_key);
    
        Ok((address, secret_key))
    }

    pub async fn get_utxos(&self, address: &Address) -> Result<Vec<UtxoEntry>, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let address_str = address.cash_addr(); // Use the cash_addr method
        let url = format!("https://api.calory.money/utxos?address={}", address_str);
    
        let resp = client.get(&url).send().await?;
    
        if resp.status().is_success() {
            let utxos: Vec<UtxoEntry> = resp.json().await?;
            Ok(utxos)
        } else {
            let error_message = resp.text().await?;
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to fetch UTXOs: {}", error_message),
            )))
        }
    }
    

    pub async fn get_balance(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let utxos = self.get_utxos(&self.address).await?;
        Ok(utxos.iter().map(|utxo| utxo.satoshis).sum())
    }
    

    pub async fn wait_for_transaction(&self, address: &Address, already_existing: &HashSet<String>) -> Result<UtxoEntry, Box<dyn std::error::Error>> {
        loop {
            let utxos = self.get_utxos(address).await?;
            let mut remaining = utxos.into_iter()
                .filter(|utxo| !already_existing.contains(&utxo.txid))
                .collect::<Vec<_>>();
            if !remaining.is_empty() {
                return Ok(remaining.remove(0));
            }
            tokio::time::sleep(std::time::Duration::new(1, 0)).await;
        }
    }

    pub async fn init_transaction(&self, temp_address: Option<Address>, temp_secret_key: Option<SecretKey>) -> Result<(IncompleteTx, u64), Box<dyn std::error::Error>> {
        let address_to_use = temp_address.unwrap_or_else(|| self.address.clone());
        let key_to_use = temp_secret_key.unwrap_or_else(|| self.secret_key.clone());
    
        let mut tx_build = IncompleteTx::new_simple();
        let mut balance = 0;
        let utxos = self.get_utxos(&address_to_use).await?;
    
        for utxo in utxos.iter() {
            balance += utxo.satoshis;
            tx_build.add_utxo(Utxo {
                key: key_to_use.clone(),
                output: Box::new(P2PKHOutput {
                    address: address_to_use.clone(),
                    value: utxo.satoshis,
                }),
                outpoint: TxOutpoint {
                    tx_hash: tx_hex_to_hash(&utxo.txid),
                    output_idx: utxo.vout,
                },
                sequence: 0xffff_ffff,
            });
        }
    
        Ok((tx_build, balance))
    }
    
    pub async fn send_tx(&self, tx: &Tx) -> Result<String, Box<dyn std::error::Error>> {
        // Serialize the transaction
        let mut tx_ser = Vec::new();
        tx.write_to_stream(&mut tx_ser)?;

        // Encode the serialized transaction in hexadecimal format
        let tx_hex = hex::encode(&tx_ser);

        // Prepare the request payload for Chronik
        let raw_tx = hex::decode(&tx_hex).map_err(|e| e.to_string())?;

        // Use the ChronikClient associated with the Wallet to broadcast the transaction
        let response = self.chronik_client.broadcast_tx(raw_tx).await?;

        // Extract the transaction ID from the Chronik response
        let txid = response.txid;

        Ok(hex::encode(txid))
    }
    
    pub fn dust_amount(&self) -> u64 {
        5
    }
}
