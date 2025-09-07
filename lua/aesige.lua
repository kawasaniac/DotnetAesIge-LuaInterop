-- Load the module from the correct file path
local aes = require("bridge")

-- Get library version
print("Version: " .. aes.get_version())

-- Prepare data (must be multiple of 16 bytes)
local plaintext = "Hello from Lua! This message is exactly 48 bytes!!!"
local key = string.rep("\x01", 32)  -- 256-bit key
local iv = string.rep("\x00", 32)   -- 32-byte IV for IGE

-- Encrypt
local encrypted = aes.encrypt_ige(plaintext, key, iv)

-- Decrypt
local decrypted = aes.decrypt_ige(encrypted, key, iv)

assert(decrypted == plaintext)
print("Success!")