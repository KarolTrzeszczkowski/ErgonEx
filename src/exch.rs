use crate::address::Address;
use crate::address::AddressType;
use crate::outputs::TradeOfferOutput;

pub struct EXCH;


impl EXCH {
    pub fn parse_exch_script(output_script: Vec<u8>) -> Result<TradeOfferOutput, &'static str> {
        // Parse Lokad ID
        let _lokad_id = hex::encode(&output_script[2..6]);
        // Parse Version
        let _version = hex::encode(&output_script[7..8]);
        // Parse Operation Type Length
        let operation_type_len = output_script[8] as usize;
        // Parse Operation Type
        let operation_type = hex::encode(&output_script[9..9 + operation_type_len]);
        //println!("Type {:#?}", operation_type); // Print the parsed trade offer

        let mut current_index = 9 + operation_type_len;
        //println!("current_index {:#?}", current_index); // Print the parsed trade offer

        if operation_type == "53454c4c" {
            // The operation type is "SELL," proceed with parsing

            // Parse Operation Txid Length
            let operation_txid_len = output_script[current_index] as usize;
            current_index += 1;

            let mut operation_txid_bytes = vec![0; operation_txid_len];
            operation_txid_bytes.copy_from_slice(&output_script[current_index..current_index + operation_txid_len]);
            let mut _operation_txid = hex::encode(&operation_txid_bytes);
            operation_txid_bytes.reverse(); // Reverse the byte order
            current_index += operation_txid_len;

            //println!("operation_txid {:#?}", operation_txid);


            // Parse Output Index Length
            let output_idx_len = output_script[current_index] as usize;
            current_index += 1;

            // Parse Output Index
            let output_idx = hex::encode(&output_script[current_index..current_index + output_idx_len]);
            current_index += output_idx_len;
            //println!("output_idx {:#?}", output_idx);

            // Parse Sell Amount Length
            let sell_amount_len = output_script[current_index] as usize;
            current_index += 1;

            // Parse Sell Amount
            let sell_amount = hex::encode(&output_script[current_index..current_index + sell_amount_len]);
            current_index += sell_amount_len;
            //println!("sell_amount {:#?}", sell_amount);

            // Parse Buy Amount Length
            let buy_amount_len = output_script[current_index] as usize;
            current_index += 1;

            // Parse Buy Amount
            let buy_amount = hex::encode(&output_script[current_index..current_index + buy_amount_len]);
            current_index += buy_amount_len;
            //println!("buy_amount {:#?}", buy_amount);

            // Parse Receiving Address Length
            let receiving_address_len = output_script[current_index] as usize;
            current_index += 1;

            // Parse Receiving Address
            let receiving_address = hex::encode(&output_script[current_index..current_index + receiving_address_len]);
            current_index += receiving_address_len;
            //println!("receiving_address {:#?}", receiving_address);

            // Parse Cancel Address Length
            let cancel_address_len = output_script[current_index] as usize;
            current_index += 1;
            //println!("cancel_address_len {:#?}", cancel_address_len);

            // Parse Cancel Address
            let cancel_address = hex::encode(&output_script[current_index..current_index + cancel_address_len]);
            //println!("cancel_address_len {:#?}", cancel_address_len);

    
            let receiving_address = Address::from_bytes(AddressType::P2PKH, {
                let mut addr = [0; 20];
                addr.copy_from_slice(&hex::decode(&receiving_address).unwrap());
                //println!("receiving_address (decoded): {:?}", addr); // Print the decoded 'receiving_address'
                addr
            });
    
            let cancel_address = Address::from_bytes(AddressType::P2PKH, {
                let mut addr = [0; 20];
                addr.copy_from_slice(&hex::decode(&cancel_address).unwrap());
                //println!("cancel_address (decoded): {:?}", addr); // Print the decoded 'cancel_address'
                addr
            });
    
            // Convert operation_txid_bytes to [u8; 32]
            let mut tx_id = [0u8; 32];
            tx_id.copy_from_slice(&operation_txid_bytes);

            // Construct and return the TradeOfferOutput
            return Ok(TradeOfferOutput {
                tx_id,
                output_idx: u32::from_str_radix(&output_idx, 16).unwrap_or_default(),
                sell_amount: u64::from_str_radix(&sell_amount, 16).unwrap_or_default(),
                buy_amount: u64::from_str_radix(&buy_amount, 16).unwrap_or_default(),
                receiving_address,
                cancel_address,
            });
        }

        Err("Invalid operation type")
    }
}
