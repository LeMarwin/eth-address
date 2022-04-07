#![allow(dead_code)]
//! The functions are rust implementations of functions from ethers.js library,
//! one of the most popular web3 libraries out there.
//! https://github.com/ethers-io/ethers.js/blob/master/packages/address/src.ts/index.ts

use anyhow::{anyhow, Result};
use crypto::{digest::Digest, sha3::Sha3};
use regex::Regex;

fn is_adddress(addr: String) -> Result<bool> {
    let basic = Regex::new(r"^(0x)?[0-9a-f]{40}$")?;
    let all_lowercase = Regex::new("^(0x|0X)?[0-9a-f]{40}$")?;
    let all_uppercase = Regex::new("^(0x|0X)?[0-9A-F]{40}$")?;

    if !basic.is_match(&addr) {
        Ok(false)
    } else if all_lowercase.is_match(&addr) || all_uppercase.is_match(&addr) {
        Ok(true)
    } else {
        Ok(true)
    }
}

fn is_hex_string(value: String, length: usize) -> Result<bool> {
    let re = Regex::new("^0x[0-9A-Fa-f]*$")?;
    let is_hex = if !re.is_match(&value) {
        false
    } else if length > 0 && value.len() != 2 + 2 * length {
        false
    } else {
        true
    };
    Ok(is_hex)
}

fn get_checksum_address(a: String) -> Result<String> {
    if !is_hex_string(a.clone(), 20)? {
        return Err(anyhow!("Invalid address. Not a hex address {}", a));
    }
    let addr = a.trim_start_matches("0x").to_lowercase();
    let address_hash = {
        let mut hasher = Sha3::keccak256();
        hasher.input(addr.as_bytes());
        hasher.result_str()
    };

    Ok(addr
        .char_indices()
        .fold(String::from("0x"), |mut acc, (index, address_char)| {
            // this cannot fail since it's Keccak256 hashed
            let n = u16::from_str_radix(&address_hash[index..index + 1], 16).unwrap();

            if n > 7 {
                // make char uppercase if ith character is 9..f
                acc.push_str(&address_char.to_uppercase().to_string())
            } else {
                // already lowercased
                acc.push(address_char)
            }

            acc
        }))
}

fn get_address(addr: String) -> Result<String> {
    let re = Regex::new("^(0x)?[0-9a-fA-F]{40}$")?;
    let mut prefixed_addr = String::from("0x");
    let result: String;

    if re.is_match(&addr) {
        // Add the missing the 0x prefix
        if &addr[..2] != "0x" {
            prefixed_addr.push_str(&addr);
        } else {
            prefixed_addr = addr;
        }

        result = get_checksum_address(prefixed_addr.clone())?;

        // Checksum regex
        let checksum_re = Regex::new("([A-F].*[a-f])|([a-f].*[A-F])")?;

        // Check if it is a checksummed address with a bad checksum
        if checksum_re.is_match(&prefixed_addr) && result != prefixed_addr {
            return Err(anyhow!(
                "Bad address checksum for address {}",
                prefixed_addr
            ));
        }
    } else {
        return Err(anyhow!("Invalid address"));
    }

    Ok(result)
}

fn is_address(addr: String) -> bool {
    match get_address(addr) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[test]
fn test_is_address() {
    let good = String::from("0xC0404ed740a69d11201f5eD297c5732F562c6E4e");
    assert_eq!(is_address(good), true);

    let bad = String::from("0xC0404ed740a69d11201fffr5y7c5732F562c6E4e");
    assert_eq!(is_address(bad), false);
}
