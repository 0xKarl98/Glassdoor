// src/main.nr
mod lib ;

use std::{collections::bounded_vec::BoundedVec, hash::{pedersen_hash}};
use zkemail::{
    dkim::RSAPubkey,
    headers::email_address::get_email_address,
    masking::mask_text,
    KEY_LIMBS_2048,
    MAX_EMAIL_ADDRESS_LENGTH,
    Sequence
};

// Using the separate module approach:
use crate::lib::{
    MAX_EMAIL_HEADER_LENGTH,
    MAX_EMAIL_BODY_LENGTH,
    MAX_DOMAIN_LENGTH,
    MAX_REVIEW_LENGTH,
    extract_domain,
    create_domain_mask,
    hash_domain
};

struct ReviewSubmission {
    review_text: BoundedVec<u8, MAX_REVIEW_LENGTH>,
    domain_hash: Field,
    masked_email: BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH>,
    nullifier: Field
}

/**
 * Anonymous Workplace Review Verification Circuit
 * 
 * Verifies an email belongs to a workplace domain and allows anonymous review submission
 * while preventing duplicate reviews from the same email address.
 *
 * @param header - The email header, 0-padded at end to MAX_EMAIL_HEADER_LENGTH
 * @param pubkey - The DKIM RSA Public Key modulus and reduction parameter
 * @param signature - The DKIM RSA Signature
 * @param from_header_sequence - The index and length of the "From" header field
 * @param from_address_sequence - The index and length of the "From" email address
 * @param review - The review text submitted by the user
 * @return - 
 *         0: Domain hash (public, used to group by company)
 *         1: Email nullifier (prevents multiple reviews)
 *         2: Public key hash (root of trust)
 */
 fn main(
    header: BoundedVec<u8, MAX_EMAIL_HEADER_LENGTH>,
    pubkey: RSAPubkey<KEY_LIMBS_2048>,
    signature: [Field; KEY_LIMBS_2048],
    from_header_sequence: Sequence,
    from_address_sequence: Sequence,
    review: BoundedVec<u8, MAX_REVIEW_LENGTH>
) -> pub (Field, Field, Field) {
    // Verify DKIM signature to ensure email authenticity
    pubkey.verify_dkim_signature(header, signature);
    
    // Extract sender's email address
    let from = comptime { "from".as_bytes() };
    let email_address = get_email_address(header, from_header_sequence, from_address_sequence, from);
    
    // Extract and hash the domain (company identifier)
    let domain = extract_domain(email_address);
    let domain_hash = hash_domain(domain);
    
    // Create mask to reveal only the domain
    let email_mask = create_domain_mask(email_address);
    
    // Apply mask to the email (hides personal info, shows only domain)
    let masked_email = mask_text(email_address, email_mask);
    
    // Create nullifier to prevent multiple reviews from same email
    let email_nullifier = pedersen_hash(signature);
    
    // Create hash of the public key for verification
    let pubkey_hash = pubkey.hash();
    
    // Return public outputs
    (domain_hash, email_nullifier, pubkey_hash)
}