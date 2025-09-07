-- Load the module from the correct file path
local aes = require("bridge")

-- Bi-directional IGE requires two keys and a 64-byte IV
local plaintext = "Secret message that needs extra security!!!!!!!"  -- 48 bytes
local key1 = string.rep("\x01", 32)  -- First 256-bit key
local key2 = string.rep("\x02", 32)  -- Second 256-bit key
local iv = string.rep("\x00", 64)    -- 64-byte IV for bi-IGE

-- Encrypt with bi-directional IGE
local encrypted = aes.encrypt_bi_ige(plaintext, key1, key2, iv)

-- Decrypt
local decrypted = aes.decrypt_bi_ige(encrypted, key1, key2, iv)

assert(decrypted == plaintext)