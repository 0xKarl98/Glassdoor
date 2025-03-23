pub global MAX_EMAIL_HEADER_LENGTH: u32 = 1024;
pub global MAX_EMAIL_BODY_LENGTH: u32 = 2048;
pub global MAX_EMAIL_ADDRESS_LENGTH: u32 = 64;
pub global MAX_DOMAIN_LENGTH: u32 = 32;
pub global MAX_REVIEW_LENGTH: u32 = 1024;

pub global REVEAL_DOMAIN_ONLY: bool = true;
pub global INCLUDE_NULLIFIER: bool = true;


/**
 * Extracts the domain portion from an email address
 * 
 * This function finds the '@' symbol in an email address and collects
 * all characters that follow it, creating a new BoundedVec containing
 * only the domain part (e.g., "company.com" from "employee@company.com").
 * 
 * @param email - The full email address as a BoundedVec of bytes
 * @return A new BoundedVec containing only the domain portion of the email
 */
pub fn extract_domain(
    email: BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH>
) -> BoundedVec<u8, MAX_DOMAIN_LENGTH> {
    let mut domain: BoundedVec<u8, 32> = BoundedVec::new();
    let mut found_at: bool  = false;
    
    for i in 0..email.len() {
        // 64 is ASCII value for '@'
        if email.get(i) == 64 { 
            found_at = true;
        }
        
        if found_at {
            if domain.len() < MAX_DOMAIN_LENGTH {
                domain.push(email.get(i));
            }
        }
       
    }
    
    domain
}

/**
 * Creates a boolean mask that reveals only the domain part of an email
 * 
 * The resulting mask has 'true' values for positions that should be revealed
 * (domain and @ symbol) and 'false' for positions that should be hidden (username).
 * This is used with the mask_text function to create a partially revealed email.
 * 
 * Example: For "john.doe@company.com", the mask would hide "john.doe" but reveal "@company.com"
 * 
 * @param email - The full email address as a BoundedVec of bytes
 * @return A boolean array with the same length as the email, with true values for characters to reveal
 */
pub fn create_domain_mask(
    email: BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH>
) -> [bool; MAX_EMAIL_ADDRESS_LENGTH] {
    let mut mask = [false; MAX_EMAIL_ADDRESS_LENGTH];
    let mut found_at = false;
    
    for i in 0..email.len() {
        if email.get(i) == 64 { // 64 is ASCII value for '@'
            found_at = true;
            mask[i] = true; // reveal the @ symbol
        } else if found_at {
            mask[i] = true; // reveal domain characters
        }
    }
    
    mask
}

/**
 * Hashes a domain to create a unique identifier for grouping reviews by company
 * 
 * This function converts the domain bytes to Field elements and then
 * applies a Pedersen hash to create a unique, deterministic identifier.
 * This allows reviews from the same company to be grouped together without
 * storing the actual domain text, enhancing privacy.
 * 
 * @param domain - The domain portion of an email as a BoundedVec of bytes
 * @return A Field value representing the hashed domain
 */
pub fn hash_domain(
    domain: BoundedVec<u8, MAX_DOMAIN_LENGTH>
) -> Field {
    // Create a Field array to store the domain bytes converted to Field values
    let mut field_array = [0; MAX_DOMAIN_LENGTH];
    
    // Convert u8 bytes to Field values
    for i in 0..domain.len() {
        field_array[i] = domain.get(i) as Field;
    }
    
    // Hash the Field array
    std::hash::pedersen_hash(field_array)
}