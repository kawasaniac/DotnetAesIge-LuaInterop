local ffi = require("ffi")

-- Define the C function signatures
ffi.cdef[[
    // Memory management
    void free_memory(void* ptr);
    
    // Version info
    char* get_version();
    
    // AES-IGE functions
    int encrypt_ige(
        const uint8_t* plainText, int plainTextLen,
        const uint8_t* key, int keyLen,
        const uint8_t* iv, int ivLen,
        void** cipherText, int* cipherTextLen
    );
    
    int decrypt_ige(
        const uint8_t* cipherText, int cipherTextLen,
        const uint8_t* key, int keyLen,
        const uint8_t* iv, int ivLen,
        void** plainText, int* plainTextLen
    );
    
    // Bi-directional IGE functions
    int encrypt_bi_ige(
        const uint8_t* plainText, int plainTextLen,
        const uint8_t* key1, int key1Len,
        const uint8_t* key2, int key2Len,
        const uint8_t* iv, int ivLen,
        void** cipherText, int* cipherTextLen
    );
    
    int decrypt_bi_ige(
        const uint8_t* cipherText, int cipherTextLen,
        const uint8_t* key1, int key1Len,
        const uint8_t* key2, int key2Len,
        const uint8_t* iv, int ivLen,
        void** plainText, int* plainTextLen
    );
    
    // HMAC-authenticated encryption
    int encrypt_ige_hmac(
        const uint8_t* plainText, int plainTextLen,
        const uint8_t* encryptionKey, int encryptionKeyLen,
        const uint8_t* hmacKey, int hmacKeyLen,
        const uint8_t* iv, int ivLen,
        void** result, int* resultLen
    );
    
    int decrypt_ige_hmac(
        const uint8_t* encryptedData, int encryptedDataLen,
        const uint8_t* encryptionKey, int encryptionKeyLen,
        const uint8_t* hmacKey, int hmacKeyLen,
        void** plainText, int* plainTextLen
    );
    
    int encrypt_bi_ige_hmac(
        const uint8_t* plainText, int plainTextLen,
        const uint8_t* encryptionKey1, int encryptionKey1Len,
        const uint8_t* encryptionKey2, int encryptionKey2Len,
        const uint8_t* hmacKey, int hmacKeyLen,
        const uint8_t* iv, int ivLen,
        void** result, int* resultLen
    );
    
    int decrypt_bi_ige_hmac(
        const uint8_t* encryptedData, int encryptedDataLen,
        const uint8_t* encryptionKey1, int encryptionKey1Len,
        const uint8_t* encryptionKey2, int encryptionKey2Len,
        const uint8_t* hmacKey, int hmacKeyLen,
        void** plainText, int* plainTextLen
    );
]]

-- Load the Native AOT compiled library
local lib_path
if jit.os == "Windows" then
    lib_path = "./AesIgeLuaBridge.dll"
elseif jit.os == "Linux" then
    lib_path = "./libAesIgeLuaBridge.so"
elseif jit.os == "OSX" then
    lib_path = "./libAesIgeLuaBridge.dylib"
else
    error("Unsupported OS: " .. jit.os)
end

local aes = ffi.load(lib_path)

-- Helper function to convert Lua string to byte array
local function string_to_bytes(str)
    local bytes = ffi.new("uint8_t[?]", #str)
    ffi.copy(bytes, str, #str)
    return bytes, #str
end

-- Helper function to convert byte pointer to Lua string
local function bytes_to_string(ptr, len)
    if ptr == nil or len <= 0 then
        return nil
    end
    local str = ffi.string(ptr, len)
    -- Free the memory allocated by the .NET library
    aes.free_memory(ptr)
    return str
end

-- Wrapper for encrypt_ige
local function encrypt_ige(plaintext, key, iv)
    local pt_bytes, pt_len = string_to_bytes(plaintext)
    local key_bytes, key_len = string_to_bytes(key)
    local iv_bytes, iv_len = string_to_bytes(iv)
    
    local ct_ptr = ffi.new("void*[1]")
    local ct_len = ffi.new("int[1]")
    
    local result = aes.encrypt_ige(
        pt_bytes, pt_len,
        key_bytes, key_len,
        iv_bytes, iv_len,
        ct_ptr, ct_len
    )
    
    if result == 0 then
        return bytes_to_string(ct_ptr[0], ct_len[0])
    else
        error("Encryption failed")
    end
end

-- Wrapper for decrypt_ige
local function decrypt_ige(ciphertext, key, iv)
    local ct_bytes, ct_len = string_to_bytes(ciphertext)
    local key_bytes, key_len = string_to_bytes(key)
    local iv_bytes, iv_len = string_to_bytes(iv)
    
    local pt_ptr = ffi.new("void*[1]")
    local pt_len = ffi.new("int[1]")
    
    local result = aes.decrypt_ige(
        ct_bytes, ct_len,
        key_bytes, key_len,
        iv_bytes, iv_len,
        pt_ptr, pt_len
    )
    
    if result == 0 then
        return bytes_to_string(pt_ptr[0], pt_len[0])
    else
        error("Decryption failed")
    end
end

-- Wrapper for encrypt_bi_ige
local function encrypt_bi_ige(plaintext, key1, key2, iv)
    local pt_bytes, pt_len = string_to_bytes(plaintext)
    local key1_bytes, key1_len = string_to_bytes(key1)
    local key2_bytes, key2_len = string_to_bytes(key2)
    local iv_bytes, iv_len = string_to_bytes(iv)
    
    local ct_ptr = ffi.new("void*[1]")
    local ct_len = ffi.new("int[1]")
    
    local result = aes.encrypt_bi_ige(
        pt_bytes, pt_len,
        key1_bytes, key1_len,
        key2_bytes, key2_len,
        iv_bytes, iv_len,
        ct_ptr, ct_len
    )
    
    if result == 0 then
        return bytes_to_string(ct_ptr[0], ct_len[0])
    else
        error("Bi-directional encryption failed")
    end
end

-- Wrapper for decrypt_bi_ige
local function decrypt_bi_ige(ciphertext, key1, key2, iv)
    local ct_bytes, ct_len = string_to_bytes(ciphertext)
    local key1_bytes, key1_len = string_to_bytes(key1)
    local key2_bytes, key2_len = string_to_bytes(key2)
    local iv_bytes, iv_len = string_to_bytes(iv)
    
    local pt_ptr = ffi.new("void*[1]")
    local pt_len = ffi.new("int[1]")
    
    local result = aes.decrypt_bi_ige(
        ct_bytes, ct_len,
        key1_bytes, key1_len,
        key2_bytes, key2_len,
        iv_bytes, iv_len,
        pt_ptr, pt_len
    )
    
    if result == 0 then
        return bytes_to_string(pt_ptr[0], pt_len[0])
    else
        error("Bi-directional decryption failed")
    end
end

-- Get version
local function get_version()
    local version_ptr = aes.get_version()
    local version = ffi.string(version_ptr)
    aes.free_memory(version_ptr)
    return version
end

-- Example usage
local function main()
    print("AES-IGE Lua Bridge Version: " .. get_version())
    print("=" .. string.rep("=", 50))
    
    -- Test data (must be multiple of 16 bytes for AES)
    local plaintext = "Hello from Lua! This is a test message that is exactly 64 bytes"
    local key = string.rep("\x01", 32)  -- 256-bit key
    local iv = string.rep("\x00", 32)   -- 32-byte IV for IGE
    
    -- Standard IGE encryption/decryption
    print("\n[Standard IGE Mode]")
    print("Original: " .. plaintext)
    
    local encrypted = encrypt_ige(plaintext, key, iv)
    print("Encrypted (hex): " .. encrypted:gsub(".", function(c) 
        return string.format("%02x", string.byte(c)) 
    end))
    
    local decrypted = decrypt_ige(encrypted, key, iv)
    print("Decrypted: " .. decrypted)
    
    assert(decrypted == plaintext, "Decryption failed - data mismatch!")
    print("✓ IGE encryption/decryption successful!")
    
    -- Bi-directional IGE encryption/decryption
    print("\n[Bi-directional IGE Mode]")
    local key1 = string.rep("\x02", 32)  -- First 256-bit key
    local key2 = string.rep("\x03", 32)  -- Second 256-bit key
    local bi_iv = string.rep("\x00", 64) -- 64-byte IV for bi-directional IGE
    
    local bi_encrypted = encrypt_bi_ige(plaintext, key1, key2, bi_iv)
    print("Bi-IGE Encrypted (hex): " .. bi_encrypted:gsub(".", function(c) 
        return string.format("%02x", string.byte(c)) 
    end))
    
    local bi_decrypted = decrypt_bi_ige(bi_encrypted, key1, key2, bi_iv)
    print("Bi-IGE Decrypted: " .. bi_decrypted)
    
    assert(bi_decrypted == plaintext, "Bi-directional decryption failed - data mismatch!")
    print("✓ Bi-directional IGE encryption/decryption successful!")
end

-- Module export
return {
    encrypt_ige = encrypt_ige,
    decrypt_ige = decrypt_ige,
    encrypt_bi_ige = encrypt_bi_ige,
    decrypt_bi_ige = decrypt_bi_ige,
    get_version = get_version,
    
    -- Run example if executed directly
    example = main
}