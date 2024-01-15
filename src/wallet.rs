use crate::address::Address;
use bitcoinsuite_chronik_client::ChronikClient;
use bitcoinsuite_chronik_client::ScriptType;
use bitcoinsuite_chronik_client::proto::{ScriptUtxos};
use bitcoinsuite_chronik_client::proto::Tx as ProtoTx;
use bitcoinsuite_core::Sha256d;
use crate::address::AddressType;
use crate::incomplete_tx::{IncompleteTx, Utxo};
use crate::tx::{Tx, TxOutpoint};
use crate::outputs::{P2PKHOutput};
use std::collections::HashSet;
use std::error::Error;
use rand::thread_rng;
use reqwest::Client as ReqwestClient; 
use rand::RngCore;
use secp256k1::{Secp256k1, PublicKey, SecretKey};
use hex;


pub struct Wallet {
    secret_key: secp256k1::SecretKey,
    address: Address,
    chronik_client: ChronikClient, 
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
            chronik_client, 
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

    #[allow(unreachable_patterns)]
    pub async fn get_utxos(&self, address: &Address) -> Result<Vec<bitcoinsuite_chronik_client::proto::Utxo>, Box<dyn Error>> {
   
        let address_bytes = address.bytes();
        //println!("Address Bytes: {:?}", address_bytes);
        let script_type = match address.addr_type() {
            AddressType::P2PKH => ScriptType::P2pkh,
            AddressType::P2SH => ScriptType::P2sh,
            _ => return Err("Unsupported address type".into()),
        };
        let script_payload = hex::encode(&address_bytes);
        //println!("Payload Used: {:?}", script_payload);
        let script_endpoint = format!("script/{}/{}/utxos", script_type, script_payload);
        //println!("script_endpoint: {:?}", script_endpoint);
        // Create a reqwest client
        let client = ReqwestClient::new();
        let chronik_url = "https://chronik.be.cash/xrg";
        // Concatenate the base URL and the script endpoint to form the complete URL
        let full_url = format!("{}/{}", chronik_url, script_endpoint);
        //println!("full_url: {:?}", full_url);
        // Make a GET request to the complete URL
        let response = client.get(&full_url).send().await?;
        //println!("response: {:?}", response);
        // Check if the response status code is 200 OK
        if response.status() != reqwest::StatusCode::OK {
            return Err(format!("Error: {}", response.status()).into());
        }
        // Parse the response body as bytes
        let response_bytes = response.bytes().await?;
        //println!("response_bytes: {:?}", response_bytes);
        // Deserialize the response bytes into ScriptUtxos
        let utxos_response: ScriptUtxos = prost::Message::decode(&response_bytes[..])?;
        //println!("utxos_response: {:?}", utxos_response);
        // Access the serialized script
        let script_bytes: &[u8] = &utxos_response.output_script;
        //println!("script_bytes: {:?}", script_bytes);
        // Deserialize the byte array into a ScriptUtxos message
        let script_utxos: ScriptUtxos = prost::Message::decode(script_bytes).unwrap();
        //println!("script_utxos: {:?}", script_utxos);
        // Access the list of ScriptUtxo messages from script_utxos
        let utxos: Vec<bitcoinsuite_chronik_client::proto::Utxo> = script_utxos.utxos;
        //println!("utxos: {:?}", utxos);

        Ok(utxos)
    }
    
    
    pub async fn get_balance(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let utxos = self.get_utxos(&self.address).await?;
        Ok(utxos.iter().map(|utxo| utxo.value as u64).sum())
    }
    
    pub async fn get_transaction_details(&self, txid: &Sha256d) -> Result<ProtoTx, Box<dyn Error>> {
        let transaction_details = self.chronik_client.tx(txid).await?;
        //println!("Transaction Details: {:?}", transaction_details);
        Ok(transaction_details)
    }

    pub async fn fetch_token(&self, token_id: &Sha256d) -> Result<bitcoinsuite_chronik_client::proto::Token, Box<dyn std::error::Error>> {
        let token_info = self.chronik_client.token(token_id).await?;
        println!("Token Info: {:?}", token_info);
        Ok(token_info)
    }

    pub async fn wait_for_transaction(
        &self, 
        address: &Address, 
        already_existing: &HashSet<Vec<u8>>) -> Result<bitcoinsuite_chronik_client::proto::Utxo, Box<dyn std::error::Error>> 
    {
        loop {
            let utxos = self.get_utxos(address).await?;
            let mut remaining = utxos.into_iter()
                .filter(|utxo| {
                    if let Some(ref outpoint) = utxo.outpoint {
                        !already_existing.contains(&outpoint.txid)
                    } else {
                        false
                    }
                })
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
            balance += utxo.value as u64;
    
            let tx_hash_bytes = match utxo.outpoint.as_ref() {
                Some(outpoint) => outpoint.txid.clone(),
                None => return Err("Outpoint is None".into()),
            };
    
            // Ensure the length is 32 and convert to array
            let tx_hash_array = if tx_hash_bytes.len() == 32 {
                let mut array = [0u8; 32];
                array.copy_from_slice(&tx_hash_bytes);
                array
            } else {
                return Err("Invalid tx_hash_bytes length".into());
            };
    
            let output_idx = match utxo.outpoint.as_ref() {
                Some(outpoint) => outpoint.out_idx,
                None => return Err("Outpoint is None".into()),
            };
    
            tx_build.add_utxo(Utxo {
                key: key_to_use.clone(),
                output: Box::new(P2PKHOutput {
                    address: address_to_use.clone(),
                    value: utxo.value as u64,
                }),
                outpoint: TxOutpoint {
                    tx_hash: tx_hash_array, // Use the array here
                    output_idx: output_idx,
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
        //println!("Raw tx: {:?}", tx_hex);

    
        // Prepare the request payload for Chronik
        let raw_tx = hex::decode(&tx_hex).map_err(|e| e.to_string())?;

    
        // Use the ChronikClient associated with the Wallet to broadcast the transaction
        let response = self.chronik_client.broadcast_tx(raw_tx).await?;
    
        // Extract the transaction ID from the Chronik response
        let txid = response.txid;
        // Reverse the bytes in place
        let mut txid_rev = txid.clone();
        txid_rev.reverse();

        // Now encode the reversed bytes
        let txid_hex = hex::encode(txid_rev);

        Ok(txid_hex)

    }
    
    pub fn dust_amount(&self) -> u64 {
        5
    }
}