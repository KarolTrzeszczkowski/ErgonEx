use crate::wallet::Wallet;
use crate::outputs::{EnforceOutputsOutput, SLPSendOutput, P2PKHOutput, TradeOfferOutput, P2SHOutput};
use crate::address::{Address, AddressType};
use crate::hash::hash160;
use crate::incomplete_tx::{IncompleteTx, Output, Utxo};
use crate::tx::{tx_hex_to_hash, TxOutpoint};
use crate::script::{Script, Op, OpCodeType};
use std::io::{self, Write, Cursor};
use byteorder::{BigEndian, ReadBytesExt};
use text_io::{read};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use futures::stream::{self, StreamExt};
use std::sync::{Arc, Mutex};
use std::cmp::Ordering;





#[derive(Deserialize, Serialize, Debug)]
pub struct TokenEntry {
    id: String,
    timestamp: String,
    symbol: Option<String>,
    name: Option<String>,
    #[serde(alias = "documentUri")]
    document_uri: Option<String>,
    #[serde(alias = "documentHash")]
    document_hash: Option<String>,
    decimals: u64,
    #[serde(alias = "initialTokenQty")]
    initial_token_qty: f64,
}

#[derive(Deserialize, Serialize, Debug)]
struct TradeEntryTx {
    h: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct TradeEntryOut {
    h1: Option<String>,
    h2: Option<String>,
    h3: Option<String>,
    h4: Option<String>,
    h5: Option<String>,
    h6: Option<String>,
    h7: Option<String>,
    h8: Option<String>,
    h9: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct SlpTxValidity {
    txid: String,
    valid: bool,
}

#[derive(Deserialize, Serialize, Debug)]
struct TxDetails {
    txid: String,
    vout: Vec<TxDetailsVout>,
}

#[derive(Deserialize, Serialize, Debug)]
struct TxDetailsVout {
    value: String,
    #[serde(alias = "scriptPubKey")]
    script_pub_key: TxDetailsScriptPubKey,
    #[serde(alias = "spent")]
    spent: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct TxDetailsScriptPubKey {
    hex: String,
    r#type: Option<String>,
}

#[derive(serde::Deserialize)]
struct SLPTxResponse {
    token_id: String,
    token_value: u64, 
    sender: String, 
}


#[derive(Deserialize, Serialize, Debug)]
pub struct TradeEntry {
    tx: TradeEntryTx,
    out: Vec<TradeEntryOut>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct TradesResult {
    c: Vec<TradeEntry>,
}
async fn fetch_tokens(ids: &[&str]) -> Result<Vec<TokenEntry>, Box<dyn std::error::Error>> {
    // Clone the IDs from the slice to create a new Vec<String>
    let ids: Vec<String> = ids.iter().map(|&id| id.to_string()).collect();

    // Print the received IDs
    //println!("Received IDs: {:?}", ids);

    let query: Vec<_> = ids.iter().map(|id| ("tokenIds", id)).collect();
    let url = reqwest::Url::parse_with_params("http://localhost:5000/api/tokens", &query)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    reqwest::get(url).await?.json::<Vec<TokenEntry>>().await.map_err(|e| e.into())
}


fn option_str(s: &Option<String>) -> &str {
    s.as_ref().map(|x| x.as_str()).unwrap_or("<empty>")
}

pub async fn create_trade_interactive(wallet: &Wallet) -> Result<(), Box<dyn std::error::Error>> {
    let (tx_build, balance) = wallet.init_transaction(None, None).await?;
    if balance < 1000 {
        println!("Your balance ({}) is too low.", balance);
        println!("You need at least 1000 ergoshis to access trading.");
        println!("Please fund some XRG to your wallet's address: {}", wallet.address().cash_addr());                  
        return Ok(());
    }
    print!("Enter the token id or token name/symbol you want to sell: ");
    io::stdout().flush()?;
    let token_str: String = read!("{}\n");
    let token_str = token_str.trim().to_string();

    let mut tokens_found = fetch_tokens(&[&token_str]).await?;
    if tokens_found.len() == 0 {
        let all_tokens = fetch_tokens(&[]).await?; // If you want to fetch all tokens without a specific ID
        let mut tokens_found_name = all_tokens.into_iter().filter(|token| {
            token.name.as_ref() == Some(&token_str) || token.symbol.as_ref() == Some(&token_str)
        }).collect::<Vec<_>>();
        if tokens_found_name.len() == 0 {
            println!("Didn't find any tokens with id/name/hash '{}'.", token_str);
            return Ok(())
        }
        tokens_found.append(&mut tokens_found_name);
    }
    let token = if tokens_found.len() == 1 {
        tokens_found.remove(0)
    } else {
        println!("Found multiple tokens with those criteria: ");
        println!(
            "{:3} {:64} {:>12} {:20} {}",
            "#",
            "ID",
            "Symbol",
            "Name",
            "Uri",
        );
        for (i, token) in tokens_found.iter().enumerate() {
            println!(
                "{:3} {:64} {:>12} {:20} {}",
                i,
                token.id,
                option_str(&token.symbol),
                option_str(&token.name),
                option_str(&token.document_uri),
            );
        }
        print!("Enter the number (0-{}) you want to sell: ", tokens_found.len() - 1);
        io::stdout().flush()?;
        let token_idx_str: String = read!("{}\n");
        let token_idx_str = token_idx_str.trim();
        if token_idx_str.len() == 0 {
            return Ok(());
        }
        match token_idx_str.parse::<usize>() {
            Ok(token_idx) => if tokens_found.len() > token_idx {
                tokens_found.remove(token_idx)
            } else {
                println!("Index {} not in the list. Exit.", token_idx);
                return Ok(())
            },
            Err(err) => {
                println!("Invalid number: {}", err);
                println!("Exit.");
                return Ok(())
            }
        }
    };

    println!("Selected token: ");
    println!("{:>18} {}", "ID:", token.id);
    println!("{:>18} {}", "Timestamp:", token.timestamp);
    println!("{:>18} {}", "Symbol:", option_str(&token.symbol));
    println!("{:>18} {}", "Name:", option_str(&token.name));
    println!("{:>18} {}", "Document URI:", option_str(&token.document_uri));
    println!("{:>18} {}", "Document Hash:", option_str(&token.document_hash));
    println!("{:>18} {}", "Decimals:", token.decimals);
    println!("{:>18} {}", "Initial Token Qty:", token.initial_token_qty);

    print!("Enter the amount of {} you want to sell (decimal): ", option_str(&token.symbol));
    io::stdout().flush()?;
    let sell_amount_str: String = read!("{}\n");
    let sell_amount_str = sell_amount_str.trim();
    let sell_amount_display: f64 = sell_amount_str.parse().map_err(|err| {
        println!("Invalid number: {}", err);
        println!("Exit.");
        err
    })?;
    let sell_amount = (sell_amount_display * (10.0f64).powi(token.decimals as i32)) as u64;
    //println!("Sell amount: {}", sell_amount);

    print!("Enter the amount of XRG you want to receive (ergoshis): ");
    io::stdout().flush()?;
    let buy_amount_str: String = read!("{}\n");
    let buy_amount_str = buy_amount_str.trim();
    let buy_amount: u64 = buy_amount_str.parse().map_err(|err| {
        println!("Invalid number: {}", err);
        println!("Exit.");
        err
    })?;

    confirm_trade_interactive(wallet,
                              tx_build,
                              balance,
                              &token,
                              sell_amount,
                              sell_amount_display,
                              buy_amount).await?;

    Ok(())
}

async fn confirm_trade_interactive(wallet: &Wallet,
                             _tx_build: IncompleteTx,
                             _balance: u64,
                             token: &TokenEntry,
                             sell_amount: u64,
                             sell_amount_display: f64,
                             buy_amount: u64) -> Result<(), Box<dyn std::error::Error>> {
    let mut token_id = [0; 32];
    token_id.copy_from_slice(&hex::decode(&token.id)?);
    let receiving_address = wallet.address().clone();
    let cancel_address = wallet.address().clone();
    let signal_address_str = "ergon:qz79ga40fgzw0zuvzhtjqd5pyzhm5ah7vvepv2l4u4";
    let signal_address = Address::from_cash_addr(signal_address_str.to_string())
        .expect("Invalid address"); // Handle this error appropriately
    let (temp_address, temp_secret_key) = wallet.get_new_address()?;

    let already_existing = wallet.get_utxos(&temp_address).await?
    .iter()
    .map(|utxo| utxo.txid.clone())
    .collect::<HashSet<_>>();

    println!("--------------------------------------------------");
    crate::display_qr::display(temp_address.cash_addr().as_bytes());
    println!("Please send EXACTLY {} {} to the following address:", sell_amount_display, option_str(&token.symbol));
    println!("{}", temp_address.cash_addr());
    println!("You can also scan the QR code above.");
    println!("Sending a different amount or incorrect token will likely burn the tokens.");

    println!("\nDO NOT CLOSE THIS PROGRAM YET BEFORE OR AFTER YOU SENT THE PAYMENT");

    println!("Waiting for transaction...");
    let utxo = wallet.wait_for_transaction(&temp_address, &already_existing).await?;
    println!("Received tx: {}", utxo.txid);
    println!("--------------------------------------------------");
    println!("Let's be sure you are not about to burn tokens...");

    // Make HTTP request to Flask server
    let client = reqwest::Client::new();
    let slp_tx_route = format!("http://localhost:5000/api/parse_slp_tx?txid={}&vout={}", utxo.txid, utxo.vout);
    let res = client.get(&slp_tx_route).send().await?.json::<SLPTxResponse>().await?;

    println!("Let's first fund the disposable wallet with some ergoshis for fees");

    // Initialize the transaction builder and get the current wallet balance
    let (mut funding_tx_build, balance) = wallet.init_transaction(None, None).await?;
    let refund_fees = 50;

    // Now sender_address is an Address object
    let fund_output = P2PKHOutput {
        value: refund_fees,
        address: temp_address.clone(),
    };

    let mut output_back_to_wallet = P2PKHOutput {
        value: 0,  // for generating tx size
        address: wallet.address().clone(),
    };

    funding_tx_build.add_output(&fund_output);


    let back_to_wallet_idx = funding_tx_build.add_output(&output_back_to_wallet);

    let fee = 10;
    let total_spent =
            fund_output.value() +
            fee;

    output_back_to_wallet.value = balance - total_spent;
    funding_tx_build.replace_output(back_to_wallet_idx, &output_back_to_wallet);
    let funding_tx = funding_tx_build.sign();

    let result = wallet.send_tx(&funding_tx).await?;
    println!("Disposable wallet funded with transaction: {}", result);

    // Verify the token id and value
    if res.token_id != token.id || res.token_value != sell_amount {
        println!("Token ID or value does not match. Expected token ID: {}, Value: {}", token.id, sell_amount);
        println!("Preparing to refund the transaction on wallet {} to save your funds", res.sender);

        println!("Let's send back the tokens to their owner");

        let (mut refund_tx_build, balance) = wallet.init_transaction(Some(temp_address), Some(temp_secret_key)).await?;

        let mut token_id = [0; 32];
        token_id.copy_from_slice(&hex::decode(&res.token_id)?);
        
        let output_slp = SLPSendOutput {
            token_type: 1,
            token_id,
            output_quantities: vec![res.token_value, 0],
        };

        // Convert the sender address from String to Address
        let sender_address = match Address::from_cash_addr(res.sender.clone()) {
            Ok(addr) => addr,
            Err(_) => return Err("Invalid sender address".into()),
        };

        let mut output_back_to_wallet = P2PKHOutput {
            value: 0,  // for generating tx size
            address: wallet.address().clone(),
        };

        // Now sender_address is an Address object
        let send_output = P2PKHOutput {
            value: 5,
            address: sender_address,
        };
        refund_tx_build.add_output(&output_slp);
        refund_tx_build.add_output(&send_output);

        let back_to_wallet_idx = refund_tx_build.add_output(&output_back_to_wallet);

        let fee = 10;
        let total_spent =
            output_slp.value() +
                send_output.value() +
                fee;

        output_back_to_wallet.value = balance - total_spent;
        refund_tx_build.replace_output(back_to_wallet_idx, &output_back_to_wallet);
        let refund_tx = refund_tx_build.sign();
        

        let result = wallet.send_tx(&refund_tx).await?;
        println!("Refund transaction sent with ID: {}", result);
        println!("You can now restart the process with the correct amount or token");

        return Ok(());  // This returns control back to the main menu
    }

    println!("Deposit ok... Let's publish the sell offer on Ergon chain");

    let (mut listing_tx_build, _balance) = wallet.init_transaction(None, None).await?;


    let output = EnforceOutputsOutput {
        value: 5,  // ignored for script hash generation
        enforced_outputs: vec![
            Box::new(SLPSendOutput {
                token_type: 1,
                token_id,
                output_quantities: vec![0, sell_amount],
            }),
            Box::new(P2PKHOutput {
                value: buy_amount,
                address: receiving_address.clone(),
            }),
        ],
        cancel_address: cancel_address.clone(),
        is_cancel: None,
    };
    let pkh = hash160(&output.script().to_vec());
    let addr_slp = Address::from_bytes_prefix(
        "ergon",
        AddressType::P2SH,
        pkh.clone(),
    );
    
    // Print the P2SH addresses
    println!("SLP Address: {}", addr_slp.cash_addr());

    let (mut lock_tx_build, balance) = wallet.init_transaction(Some(temp_address.clone()), Some(temp_secret_key)).await?;

    let mut token_id = [0; 32];
    token_id.copy_from_slice(&hex::decode(&res.token_id)?);
    
    let output_slp = SLPSendOutput {
        token_type: 1,
        token_id,
        output_quantities: vec![res.token_value, 0],
    };


    let send_output = P2SHOutput {
        output: output,
    };
    
    let back_output = P2PKHOutput {
        value: 5, // Value in satoshis
        address: temp_address.clone(),
    };


    let mut output_back_to_wallet = P2PKHOutput {
        value: 0,  // for generating tx size
        address: wallet.address().clone(),
    };

    lock_tx_build.add_output(&output_slp);
    lock_tx_build.add_output(&send_output);
    lock_tx_build.add_output(&back_output);


    let back_to_wallet_idx = lock_tx_build.add_output(&output_back_to_wallet);

    let fee = 10;
    let total_spent =
        output_slp.value() +
            send_output.value() +
            back_output.value() +
            fee;

    output_back_to_wallet.value = balance - total_spent;
    lock_tx_build.replace_output(back_to_wallet_idx, &output_back_to_wallet);
    let lock_tx = lock_tx_build.sign();
    
    let lock_result = wallet.send_tx(&lock_tx).await?;
    println!("Locking transaction sent with ID: {}", lock_result);

    let trade_offer_output = TradeOfferOutput {
        tx_id: tx_hex_to_hash(&lock_result),
        output_idx: 1,
        sell_amount,
        buy_amount,
        receiving_address: receiving_address.clone(),
        cancel_address: cancel_address.clone(),
    };

    println!("TradeOfferOutput Details: tx_id: {:?}, output_idx: {}, sell_amount: {}, buy_amount: {}, receiving_address: {:?}, cancel_address: {:?}", 
        trade_offer_output.tx_id, trade_offer_output.output_idx, trade_offer_output.sell_amount, trade_offer_output.buy_amount, trade_offer_output.receiving_address, trade_offer_output.cancel_address);

    listing_tx_build.add_output(&trade_offer_output.into_output());

    println!("Added TradeOfferOutput to transaction build.");


    let mut send_output = P2PKHOutput {
        value: 0,
        address: wallet.address().clone(),
    };

    let signal_output = P2PKHOutput {
        value: 5,
        address: signal_address.clone(),
    };
    listing_tx_build.add_output(&signal_output);

    let fee = 10;
    let total_spent =
        signal_output.value() +
            fee;

    if total_spent > balance {
        println!("The broadcast transaction cannot be sent due to insufficient funds");
    }
    send_output.value = balance - total_spent;
    listing_tx_build.add_output(&send_output);

    let listing_tx = listing_tx_build.sign();
    let result = wallet.send_tx(&listing_tx).await?;
    println!("The trade listing transaction ID is: {}", result);


    Ok(())
}

pub async fn accept_trades_interactive(wallet: &Wallet,  token_symbol: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let (_tx_build, balance) = wallet.init_transaction(None, None).await?;
    if balance < 1000 {
        println!("Your balance ({}) is too low.", balance);
        println!("You need at least 1000 ergoshis to access trading.");
        println!("Please fund some XRG to your wallet's address: {}", wallet.address().cash_addr());                  
        return Ok(());
    }
    println!("Loading trades... (Note: this might take a few seconds and a trade might need to be \
              confirmed to show up due to bitdb)");

    let response = reqwest::get(
        "http://localhost:5000/api/trades").await?;
    let trades_result: TradesResult = response.json().await?;


    let mut trades = Vec::new();
    trades_result.c.iter().for_each(|tx| tx.out.iter().for_each(|out| {
        (|| -> Option<()> {
            if out.h1.as_ref() != Some(&hex::encode(b"EXCH")) {
                return None;
            }
    
            // Print the 'h1' field
            //println!("h1: {:?}", out.h1);
    
            let tx_id: [u8; 32] = {
                let mut tx_id = [0; 32];
                let tx_id_hex = out.h4.as_ref()?.clone();
                tx_id.copy_from_slice(&hex::decode(&tx_id_hex).unwrap());
                //println!("tx_id (decoded): {:?}", tx_id_hex); // Print the decoded 'tx_id'
                tx_id
            };
    
            let output_idx = Cursor::new(hex::decode(out.h5.as_ref()?).unwrap()).read_u32::<BigEndian>().unwrap();
            //println!("output_idx: {}", output_idx); // Print 'output_idx'
    
            let sell_amount = Cursor::new(hex::decode(out.h6.as_ref()?).unwrap()).read_u64::<BigEndian>().unwrap();
            //println!("sell_amount: {}", sell_amount); // Print 'sell_amount'
    
            let buy_amount = Cursor::new(hex::decode(out.h7.as_ref()?).unwrap()).read_u64::<BigEndian>().unwrap();
            //println!("buy_amount: {}", buy_amount); // Print 'buy_amount'
    
            let receiving_address = Address::from_bytes(AddressType::P2PKH, {
                let mut addr = [0; 20];
                let addr_hex = out.h8.as_ref()?.clone();
                addr.copy_from_slice(&hex::decode(&addr_hex).unwrap());
               // println!("receiving_address (decoded): {:?}", addr); // Print the decoded 'receiving_address'
                addr
            });
    
            let cancel_address = Address::from_bytes(AddressType::P2PKH, {
                let mut addr = [0; 20];
                let addr_hex = out.h9.as_ref()?.clone();
                addr.copy_from_slice(&hex::decode(&addr_hex).unwrap());
                //println!("cancel_address (decoded): {:?}", addr); // Print the decoded 'cancel_address'
                addr
            });
    
            trades.push(TradeOfferOutput {
                tx_id,
                output_idx,
                sell_amount,
                buy_amount,
                receiving_address,
                cancel_address,
            });
    
            None
        })();
    }));
    

    let tx_hashes = trades.iter().map(|trade| {
        hex::encode(&trade.tx_id.iter().cloned().rev().collect::<Vec<_>>())
    }).collect::<Vec<_>>();

    let tx_hashes_chunks: Vec<Vec<String>> = tx_hashes.chunks(20)
        .map(|chunk| chunk.to_vec())
        .collect();
    let trades_validity = Arc::new(Mutex::new(Vec::new()));

    stream::iter(tx_hashes_chunks)
        .then(|chunk| {
            let client = reqwest::Client::new();
            async move {
                let futures = chunk.into_iter().map(|txid| {
                    let url = format!("http://localhost:5000/api/validate_slp/{}", txid);
                    client.get(&url).send()
                });

                let responses = futures::future::join_all(futures).await;

                let validities = responses.into_iter().map(|response| {
                    async move {
                        match response {
                            Ok(resp) => {
                                match resp.json::<SlpTxValidity>().await {
                                    Ok(validity) => Ok(validity),
                                    Err(e) => Err(e)
                                }
                            },
                            Err(e) => Err(e)
                        }
                    }
                });

                let results = futures::future::join_all(validities).await;
                let validities: Result<Vec<SlpTxValidity>, reqwest::Error> = results.into_iter().collect();
                validities
            }
        })
        .for_each(|result| async {
            match result {
                Ok(validities) => {
                    let mut trades_validity_locked = trades_validity.lock().unwrap();
                    trades_validity_locked.extend(validities);
                },
                Err(e) => {
                    eprintln!("Error: {}", e);
                }
            }
        })
        .await;


    let trades_validity = trades_validity.lock().unwrap();
    
    let valid_txs = trades_validity.iter()
        .filter(|validity| validity.valid)
        .map(|validity| validity.txid.clone())
        .collect::<HashSet<_>>();


    let mut tx_details = Vec::new();
    for chunk in valid_txs.iter().collect::<Vec<_>>().chunks(20) {
        // Construct the URL with transaction IDs as parameters
        let url = format!("http://localhost:5000/api/tx_details?{}", chunk.iter()
            .map(|txid| format!("txid={}", txid))
            .collect::<Vec<String>>()
            .join("&"));
    
        let response = reqwest::Client::new()
            .get(&url)
            .send().await?
            .json::<Vec<TxDetails>>().await?;
    
        // Print the response for each chunk
        //println!("Response for chunk: {:?}", response);
    
        tx_details.extend(response);
    }
    
    
    let token_ids = tx_details.into_iter().filter_map(|tx| {
        let mut p2sh_amount = None;
        let mut tx_id = None;
        let mut token_id = None;
        for (i, out) in tx.vout.into_iter().enumerate() {
            //println!("Processing transaction: {}", tx.txid);
    
            if option_str(&out.script_pub_key.r#type) == "scripthash" && i == 1 { // enforced position
                p2sh_amount = Some((out.value.parse::<f64>().unwrap() * 100_000_000.0) as u64);
                if out.spent == Some("true".to_string()) {
                    //println!("Transaction {} is spent, skipping.", tx.txid);
                    return None;
                }
                //println!("P2SH amount found in transaction {}: {}", tx.txid, p2sh_amount.unwrap());
                break;
            }
            if option_str(&out.script_pub_key.r#type) == "pubkeyhash" {
                continue;
            }
            let script = Script::from_serialized(
                &hex::decode(&out.script_pub_key.hex).unwrap()
            );
            //println!("Script {}.", script);

    
            if script.ops().len() < 6 || // op_return + SLP\0 + version + SEND + token_id + v1 + v2
                script.ops()[0] != Op::Code(OpCodeType::OpReturn) ||
                script.ops()[1] != Op::Push(b"SLP\0".to_vec()) ||
                script.ops()[2] != Op::Push(vec![0x01]) ||
                script.ops()[3] != Op::Push(b"SEND".to_vec()) {
                continue;
            }
    
            if let Op::Push(vec) = &script.ops()[4] {
                tx_id = Some(tx.txid.clone());
                token_id = Some(hex::encode(vec));
            }
    
            //println!("Transaction {} has valid SLP script.", tx.txid);
        }
        Some((tx_id?, (token_id?, p2sh_amount?)))
    }).collect::<HashMap<_, _>>();
    

    // Inside your async function
    let token_id_set = token_ids.values().map(|(x, _)| x).collect::<HashSet<_>>();

    let chunks: Vec<Vec<&String>> = token_id_set.into_iter().collect::<Vec<_>>().chunks(20).map(|chunk| chunk.to_vec()).collect();
    let token_details_futures = stream::iter(chunks)
        .then(|chunk| {
            async move {
                let ids: Vec<&str> = chunk.iter().map(AsRef::as_ref).collect();
                fetch_tokens(&ids).await
            }
        })
        .collect::<Vec<_>>().await;



    let mut token_details = HashMap::new();
    for result in token_details_futures {
        match result {
            Ok(details) => {
                for detail in details {
                    token_details.insert(detail.id.clone(), detail);
                    
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    // Create valid_trades as a mutable vector
    let mut valid_trades = trades.into_iter()
        .filter_map(|trade| {
            let tx_id = trade.tx_id.iter().cloned().rev().collect::<Vec<_>>();
            let tx_id_hex = hex::encode(&tx_id);
            if !valid_txs.contains(&tx_id_hex) {
                return None
            }
            let (trade_token_id, amount) = token_ids.get(&tx_id_hex)?;
            let trade_token_details = token_details.get(trade_token_id)?;
            Some((tx_id_hex, trade, trade_token_details, *amount))
        })
        .collect::<Vec<_>>();
    // Filter trades based on token_symbol
    if let Some(symbol) = token_symbol {
        valid_trades.retain(|(_, _, trade_token_details, _)| {
            trade_token_details.symbol.as_ref() == Some(&symbol)
        });
    }

    // Sort the valid_trades vector by price from lowest to highest
    valid_trades.sort_by(|(_, trade1, trade_token_details1, _), (_, trade2, trade_token_details2, _)| {
        let factor1 = 10.0f64.powi(-(trade_token_details1.decimals as i32));
        let sell_amount_display1 = trade1.sell_amount as f64 * factor1;
        let price1 = trade1.buy_amount as f64 / sell_amount_display1;

        let factor2 = 10.0f64.powi(-(trade_token_details2.decimals as i32));
        let sell_amount_display2 = trade2.sell_amount as f64 * factor2;
        let price2 = trade2.buy_amount as f64 / sell_amount_display2;

        price1.partial_cmp(&price2).unwrap_or(Ordering::Equal)
    });

    // Create a HashMap to group valid_trades by tokenID
    let mut grouped_trades: HashMap<String, Vec<(&String, &TradeOfferOutput)>> = HashMap::new();

    for (tx_id_hex, trade, trade_token_details, _) in valid_trades.iter() {
        let token_id = trade_token_details.id.clone(); // Assuming trade_token_details is a HashMap

        if let Some(token_trades) = grouped_trades.get_mut(&token_id) {
            token_trades.push((&tx_id_hex, trade));
        } else {
            grouped_trades.insert(token_id, vec![(&tx_id_hex, trade)]);
        }
    }

    // Now the valid_trades vector is sorted by price

    let (mut tx_build, balance) = wallet.init_transaction(None, None).await?;
    println!("Your balance: {} ergoshis", balance);
    println!("Current trade offers:");
    println!("{:^3} | {:^15} | {:^14} | {:^10} | {:^11} |",
             "#", "Selling", "Asking", "Price", "Token ID");
    println!("-------------------------------------------------------------------");
    for (idx, (_, trade, trade_token_details, _))
            in valid_trades.iter().enumerate() {
        let factor = 10.0f64.powi(-(trade_token_details.decimals as i32));
        let sell_amount_display = trade.sell_amount as f64 * factor;
        let price = trade.buy_amount as f64 / sell_amount_display;
        let symbol = option_str(&trade_token_details.symbol);
        println!("{:3} | {:8} {:<6} | {:10} ergoshi | {:6.0} ergoshi | {:8}... |",
                 idx,
                 sell_amount_display,
                 &symbol[..6usize.min(symbol.len())],
                 trade.buy_amount,
                 price,
                 &trade_token_details.id[..8]);
    }

    if valid_trades.len() == 0 {
        println!("There currently aren't any open trades on the entire network.");
        return Ok(());
    }
    if balance < wallet.dust_amount() {
        println!("Your balance ({}) isn't sufficient to broadcast a transaction. Please fund some \
                  XRG to your wallet's address: {}", balance, wallet.address().cash_addr());
        return Ok(());
    }

    print!("Enter the trade offer number to accept (0-{}): ", valid_trades.len() - 1);
    io::stdout().flush()?;
    let offer_idx_str: String = read!("{}\n");
    let offer_idx_str = offer_idx_str.trim();
    if offer_idx_str.len() == 0 {
        println!("Bye!");
        return Ok(());
    }
    let offer_idx: usize = offer_idx_str.parse().map_err(|err| {
        println!("Invalid number: {}", err);
        println!("Exit.");
        err
    })?;

    let (tx_id, trade, trade_token_details, amount) =
        match valid_trades.get(offer_idx) {
            Some(trade) => trade,
            None => {
                println!("Invalid number");
                println!("Exit.");
                return Ok(());
            },
        };
    let trade: &TradeOfferOutput = trade;
    let trade_token_details: &&TokenEntry = trade_token_details;
    println!("You selected the following trade:");
    println!("{:20}{:10} {:<}",
             "Purchase amount:",
             trade.sell_amount as f64 * 10.0f64.powi(-(trade_token_details.decimals as i32)),
             option_str(&trade_token_details.symbol));
    println!("{:20}{:10} sats", "Spend amount:", trade.buy_amount);
    println!("{:20}{}", "Token ID:", trade_token_details.id);
    println!("{:20}{}", "Token symbol:", option_str(&trade_token_details.symbol));
    println!("{:20}{}", "Token name:", option_str(&trade_token_details.name));
    println!("{:20}{}", "Token timestamp:", trade_token_details.timestamp);
    println!("{:20}{}", "Token document URI:", option_str(&trade_token_details.document_uri));
    println!("------------------------------------");
    if balance < trade.buy_amount {
        println!(
            "Insufficient funds. The trade asks for {} sats but your wallet's balance is only {} sats",
            trade.buy_amount,
            balance,
        );
        println!("Note that you also need to pay for the transaction fees, which are ~1000 sats");
    }

    let addr = loop {
        print!("Enter the ergon address to send the tokens to: ");
        io::stdout().flush()?;
        let receiving_addr_str: String = read!("{}\n");
        let receiving_addr_str = receiving_addr_str.trim();
        if receiving_addr_str.len() == 0 {
            println!("Bye!");
            return Ok(());
        }
        let addr = match Address::from_cash_addr(receiving_addr_str.to_string()) {
            Ok(addr) => addr,
            Err(err) => {
                println!("Please enter a valid address: {:?}", err);
                continue;
            }
        };
        if addr.prefix() != "ergon" {
            println!("Please enter a ergon address, it starts with 'ergon'.");
            continue;
        }
        break addr;
    };

    let mut token_id = [0; 32];
    token_id.copy_from_slice(&hex::decode(&trade_token_details.id)?);
    let output_slp = SLPSendOutput {
        token_type: 1,
        token_id,
        output_quantities: vec![0, trade.sell_amount],
    };
    let output_buy_amount = P2PKHOutput {
        value: trade.buy_amount,
        address: trade.receiving_address.clone(),
    };
    let input_output = EnforceOutputsOutput {
        value: *amount,
        enforced_outputs: vec![
            Box::new(output_slp.clone()),
            Box::new(output_buy_amount.clone()),
        ],
        cancel_address: trade.cancel_address.clone(),
        is_cancel: Some(false),
    };
    let output_sell_amount = P2PKHOutput {
        value: wallet.dust_amount(),
        address: addr,
    };
    let mut output_back_to_wallet = P2PKHOutput {
        value: 0,  // for generating tx size
        address: wallet.address().clone(),
    };

    tx_build.add_utxo(Utxo {
        outpoint: TxOutpoint {
            tx_hash: tx_hex_to_hash(&tx_id),
            output_idx: trade.output_idx,
        },
        sequence: 0xffff_ffff,
        output: Box::new(
            P2SHOutput { output: input_output },
        ),
        // arbitrary, totally randomly generated, key
        key: secp256k1::SecretKey::from_slice(b"TruthIsTreasonInTheEmpireOfLies.")?,
    });
    tx_build.add_output(&output_slp);
    tx_build.add_output(&output_buy_amount);
    tx_build.add_output(&output_sell_amount);
    let back_to_wallet_idx = tx_build.add_output(&output_back_to_wallet);

    let fee = 20;
    let total_spent =
        output_slp.value() +
            output_buy_amount.value() +
            output_sell_amount.value() +
            fee;
    if total_spent > balance {
        println!("Including fees and dust outputs, this transaction will spend {} sats, but \
                  your wallet's balance is only {} sats", total_spent, balance);
        return Ok(());
    }
    output_back_to_wallet.value = balance - total_spent;
    tx_build.replace_output(back_to_wallet_idx, &output_back_to_wallet);
    let tx = tx_build.sign();

    let mut tx_ser = Vec::new();
    tx.write_to_stream(&mut tx_ser)?;

    println!("Type \"hex\" (without quotes) to show the transaction hex instead of broadcasting.");
    println!("After broadcasting, your balance will be {} sats.", balance - total_spent);
    print!("Should the transaction be broadcast now to seal the deal? Type \"yes\" \
            (without quotes): ");
    io::stdout().flush()?;
    let confirm_send: String = read!("{}\n");
    match confirm_send.to_ascii_lowercase().trim() {
        "yes" => {
            let response = wallet.send_tx(&tx).await?;
            println!("Sent transaction. Transaction ID is: {}", response);
        },
        "hex" => {
            println!("{}", hex::encode(&tx_ser));
        },
        _ => {},
    }

    Ok(())
}
