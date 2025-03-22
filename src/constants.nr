// Maximum sizes for email components
global MAX_EMAIL_HEADER_LENGTH: u32 = 1024;
global MAX_EMAIL_BODY_LENGTH: u32 = 2048;
global MAX_EMAIL_ADDRESS_LENGTH: u32 = 64;
global MAX_DOMAIN_LENGTH: u32 = 32;
global MAX_REVIEW_LENGTH: u32 = 1024;

// Circuit visibility configuration
global REVEAL_DOMAIN_ONLY: bool = true;
global INCLUDE_NULLIFIER: bool = true;