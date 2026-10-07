// Version
pub const SOCKS5_VERSION: u8 = 0x05;

// Address types
pub const ADDRESS_TYPE_IPV4: u8 = 0x01;
pub const ADDRESS_TYPE_DOMAIN: u8 = 0x03;
pub const ADDRESS_TYPE_IPV6: u8 = 0x04;

// General
pub const RESERVED: u8 = 0x00;

// Authentication methods
pub const NO_AUTH: u8 = 0x00;
pub const USERNAME_PASSWORD: u8 = 0x02;
pub const NO_ACCEPTABLE_METHOD: u8 = 0xff;

// Username/password authentication
pub const AUTH_VERSION: u8 = 0x01;
pub const AUTH_SUCCESS: u8 = 0x00;
pub const AUTH_FAILURE: u8 = 0x01;

// Reply codes
pub const REPLY_SUCCEEDED: u8 = 0x00;
pub const REPLY_GENERAL_FAILURE: u8 = 0x01;
pub const REPLY_NOT_ALLOWED: u8 = 0x02;
pub const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REPLY_HOST_UNREACHABLE: u8 = 0x04;
pub const REPLY_CONNECTION_REFUSED: u8 = 0x05;
pub const REPLY_TTL_EXPIRED: u8 = 0x06;
pub const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

// Empty reply fields
pub const EMPTY_IPV4: [u8; 4] = [0x00; 4];
pub const EMPTY_PORT: [u8; 2] = [0x00; 2];
