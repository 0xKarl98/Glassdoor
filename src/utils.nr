//Helper functions for domain extraction and validation 
use std::{collections::bounded_vec::BoundedVec, hash::pedersen_hash};
use crate::constants::{MAX_EMAIL_ADDRESS_LENGTH, MAX_DOMAIN_LENGTH};

// Extract domain from email 
// todo: check if this is right 
fn extract_domain(
    email: BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH>
) -> BoundedVec<u8, MAX_DOMAIN_LENGTH> {
    let mut domain = BoundedVec::new(MAX_DOMAIN_LENGTH);
    let mut found_at = false;
    
    for i in 0..email.len() {
        if found_at {
            domain.push(email[i]);
        }
        if email[i] == '@' as u8 {
            found_at = true;
        }
    }
    
    domain
}


// Create a mask that hides username but reveals domain
fn create_domain_mask(
    email: BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH>
) -> [bool; MAX_EMAIL_ADDRESS_LENGTH] {
    let mut mask = [false; MAX_EMAIL_ADDRESS_LENGTH];
    let mut found_at = false;
    
    for i in 0..email.len() {
        if email[i] == '@' as u8 {
            found_at = true;
            mask[i] = true; // reveal the @ symbol
        } else if found_at {
            mask[i] = true; // reveal domain characters
        }
    }
    
    mask
}

// Hash the domain to allow grouping reviews by company
fn hash_domain(domain: BoundedVec<u8, MAX_DOMAIN_LENGTH>) -> Field {
    pedersen_hash(domain.storage)
}