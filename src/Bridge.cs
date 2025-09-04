using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using DotnetAesIge_LuaInterop.src;

namespace src
{
    /// <summary>
    /// Native AOT compatible bridge for Lua FFI using .NET 9.0 features.
    /// This class exposes unmanaged entry points that can be called from Lua.
    /// </summary>
    public unsafe static class Bridge
    {
        /// <summary>
        /// Helper method to safely copy data from an unmanaged memory pointer to a managed byte array.
        /// Uses Span<T> for better performance in .NET 9.0
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ReadOnlySpan<byte> PtrToSpan(nint ptr, int len)
        {
            if (ptr == 0 || len <= 0)
            {
                return ReadOnlySpan<byte>.Empty;
            }
            unsafe
            {
                return new ReadOnlySpan<byte>((void*)ptr, len);
            }
        }

        /// <summary>
        /// Allocates unmanaged memory and copies the byte array to it.
        /// Returns the pointer to the allocated memory.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static nint AllocateAndCopy(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty)
                return 0;

            var ptr = Marshal.AllocHGlobal(data.Length);
            unsafe
            {
                var dest = new Span<byte>((void*)ptr, data.Length);
                data.CopyTo(dest);
            }
            return ptr;
        }

        /// <summary>
        /// Frees a block of unmanaged memory that was allocated by this library.
        /// It's crucial for the calling code (Lua) to call this to prevent memory leaks.
        /// </summary>
        [UnmanagedCallersOnly(EntryPoint = "free_memory", CallConvs = [typeof(CallConvCdecl)])]
        public static void FreeMemory(nint ptr)
        {
            if (ptr != 0)
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        [UnmanagedCallersOnly(EntryPoint = "encrypt_ige", CallConvs = [typeof(CallConvCdecl)])]
        public static int EncryptIge(
            nint plainText, int plainTextLen,
            nint key, int keyLen,
            nint iv, int ivLen,
            nint* cipherText, int* cipherTextLen)
        {
            if (cipherText == null || cipherTextLen == null)
                return -1;

            *cipherText = 0;
            *cipherTextLen = 0;

            try
            {
                var plainTextSpan = PtrToSpan(plainText, plainTextLen);
                var keySpan = PtrToSpan(key, keyLen);
                var ivSpan = PtrToSpan(iv, ivLen);

                byte[] resultBytes = AesIge.EncryptIge(plainTextSpan, keySpan, ivSpan);

                *cipherTextLen = resultBytes.Length;
                *cipherText = AllocateAndCopy(resultBytes);

                return 0; // Success
            }
            catch
            {
                return -1; // Failure
            }
        }

        [UnmanagedCallersOnly(EntryPoint = "decrypt_ige", CallConvs = [typeof(CallConvCdecl)])]
        public static int DecryptIge(
            nint cipherText, int cipherTextLen,
            nint key, int keyLen,
            nint iv, int ivLen,
            nint* plainText, int* plainTextLen)
        {
            if (plainText == null || plainTextLen == null)
                return -1;

            *plainText = 0;
            *plainTextLen = 0;

            try
            {
                var cipherTextSpan = PtrToSpan(cipherText, cipherTextLen);
                var keySpan = PtrToSpan(key, keyLen);
                var ivSpan = PtrToSpan(iv, ivLen);

                byte[] resultBytes = AesIge.DecryptIge(cipherTextSpan, keySpan, ivSpan);

                *plainTextLen = resultBytes.Length;
                *plainText = AllocateAndCopy(resultBytes);

                return 0; // Success
            }
            catch
            {
                return -1; // Failure
            }
        }

        [UnmanagedCallersOnly(EntryPoint = "encrypt_bi_ige", CallConvs = [typeof(CallConvCdecl)])]
        public static int EncryptBiIge(
            nint plainText, int plainTextLen,
            nint key1, int key1Len,
            nint key2, int key2Len,
            nint iv, int ivLen,
            nint* cipherText, int* cipherTextLen)
        {
            if (cipherText == null || cipherTextLen == null)
                return -1;

            *cipherText = 0;
            *cipherTextLen = 0;

            try
            {
                var plainTextSpan = PtrToSpan(plainText, plainTextLen);
                var key1Span = PtrToSpan(key1, key1Len);
                var key2Span = PtrToSpan(key2, key2Len);
                var ivSpan = PtrToSpan(iv, ivLen);

                byte[] resultBytes = AesBiIge.EncryptBiIge(plainTextSpan, key1Span, key2Span, ivSpan);

                *cipherTextLen = resultBytes.Length;
                *cipherText = AllocateAndCopy(resultBytes);

                return 0; // Success
            }
            catch
            {
                return -1; // Failure
            }
        }

        [UnmanagedCallersOnly(EntryPoint = "decrypt_bi_ige", CallConvs = [typeof(CallConvCdecl)])]
        public static int DecryptBiIge(
            nint cipherText, int cipherTextLen,
            nint key1, int key1Len,
            nint key2, int key2Len,
            nint iv, int ivLen,
            nint* plainText, int* plainTextLen)
        {
            if (plainText == null || plainTextLen == null)
                return -1;

            *plainText = 0;
            *plainTextLen = 0;

            try
            {
                var cipherTextSpan = PtrToSpan(cipherText, cipherTextLen);
                var key1Span = PtrToSpan(key1, key1Len);
                var key2Span = PtrToSpan(key2, key2Len);
                var ivSpan = PtrToSpan(iv, ivLen);

                byte[] resultBytes = AesBiIge.DecryptBiIge(cipherTextSpan, key1Span, key2Span, ivSpan);

                *plainTextLen = resultBytes.Length;
                *plainText = AllocateAndCopy(resultBytes);

                return 0; // Success
            }
            catch
            {
                return -1; // Failure
            }
        }

        // Additional HMAC-based methods
        [UnmanagedCallersOnly(EntryPoint = "encrypt_ige_hmac", CallConvs = [typeof(CallConvCdecl)])]
        public static int EncryptIgeWithHmac(
            nint plainText, int plainTextLen,
            nint encryptionKey, int encryptionKeyLen,
            nint hmacKey, int hmacKeyLen,
            nint iv, int ivLen,
            nint* result, int* resultLen)
        {
            if (result == null || resultLen == null)
                return -1;

            *result = 0;
            *resultLen = 0;

            try
            {
                var plainTextSpan = PtrToSpan(plainText, plainTextLen);
                var encryptionKeySpan = PtrToSpan(encryptionKey, encryptionKeyLen);
                var hmacKeySpan = PtrToSpan(hmacKey, hmacKeyLen);
                var ivSpan = PtrToSpan(iv, ivLen);

                byte[] resultBytes = AesIgeHmac.EncryptWithHmac(
                    plainTextSpan, encryptionKeySpan, hmacKeySpan, ivSpan);

                *resultLen = resultBytes.Length;
                *result = AllocateAndCopy(resultBytes);

                return 0; // Success
            }
            catch
            {
                return -1; // Failure
            }
        }

        [UnmanagedCallersOnly(EntryPoint = "decrypt_ige_hmac", CallConvs = [typeof(CallConvCdecl)])]
        public static int DecryptIgeWithHmac(
            nint encryptedData, int encryptedDataLen,
            nint encryptionKey, int encryptionKeyLen,
            nint hmacKey, int hmacKeyLen,
            nint* plainText, int* plainTextLen)
        {
            if (plainText == null || plainTextLen == null)
                return -1;

            *plainText = 0;
            *plainTextLen = 0;

            try
            {
                var encryptedDataSpan = PtrToSpan(encryptedData, encryptedDataLen);
                var encryptionKeySpan = PtrToSpan(encryptionKey, encryptionKeyLen);
                var hmacKeySpan = PtrToSpan(hmacKey, hmacKeyLen);

                byte[] resultBytes = AesIgeHmac.DecryptWithHmac(
                    encryptedDataSpan, encryptionKeySpan, hmacKeySpan);

                *plainTextLen = resultBytes.Length;
                *plainText = AllocateAndCopy(resultBytes);

                return 0; // Success
            }
            catch
            {
                return -1; // Failure
            }
        }

        [UnmanagedCallersOnly(EntryPoint = "encrypt_bi_ige_hmac", CallConvs = [typeof(CallConvCdecl)])]
        public static int EncryptBiIgeWithHmac(
            nint plainText, int plainTextLen,
            nint encryptionKey1, int encryptionKey1Len,
            nint encryptionKey2, int encryptionKey2Len,
            nint hmacKey, int hmacKeyLen,
            nint iv, int ivLen,
            nint* result, int* resultLen)
        {
            if (result == null || resultLen == null)
                return -1;

            *result = 0;
            *resultLen = 0;

            try
            {
                var plainTextSpan = PtrToSpan(plainText, plainTextLen);
                var encryptionKey1Span = PtrToSpan(encryptionKey1, encryptionKey1Len);
                var encryptionKey2Span = PtrToSpan(encryptionKey2, encryptionKey2Len);
                var hmacKeySpan = PtrToSpan(hmacKey, hmacKeyLen);
                var ivSpan = PtrToSpan(iv, ivLen);

                byte[] resultBytes = AesIgeHmac.EncryptBiIgeWithHmac(
                    plainTextSpan, encryptionKey1Span, encryptionKey2Span, hmacKeySpan, ivSpan);

                *resultLen = resultBytes.Length;
                *result = AllocateAndCopy(resultBytes);

                return 0; // Success
            }
            catch
            {
                return -1; // Failure
            }
        }

        [UnmanagedCallersOnly(EntryPoint = "decrypt_bi_ige_hmac", CallConvs = [typeof(CallConvCdecl)])]
        public static int DecryptBiIgeWithHmac(
            nint encryptedData, int encryptedDataLen,
            nint encryptionKey1, int encryptionKey1Len,
            nint encryptionKey2, int encryptionKey2Len,
            nint hmacKey, int hmacKeyLen,
            nint* plainText, int* plainTextLen)
        {
            if (plainText == null || plainTextLen == null)
                return -1;

            *plainText = 0;
            *plainTextLen = 0;

            try
            {
                var encryptedDataSpan = PtrToSpan(encryptedData, encryptedDataLen);
                var encryptionKey1Span = PtrToSpan(encryptionKey1, encryptionKey1Len);
                var encryptionKey2Span = PtrToSpan(encryptionKey2, encryptionKey2Len);
                var hmacKeySpan = PtrToSpan(hmacKey, hmacKeyLen);

                byte[] resultBytes = AesIgeHmac.DecryptBiIgeWithHmac(
                    encryptedDataSpan, encryptionKey1Span, encryptionKey2Span, hmacKeySpan);

                *plainTextLen = resultBytes.Length;
                *plainText = AllocateAndCopy(resultBytes);

                return 0; // Success
            }
            catch
            {
                return -1; // Failure
            }
        }

        // Get library version for verification
        [UnmanagedCallersOnly(EntryPoint = "get_version", CallConvs = [typeof(CallConvCdecl)])]
        public static nint GetVersion()
        {
            var version = "1.0.0"u8;
            var ptr = Marshal.AllocHGlobal(version.Length + 1);
            unsafe
            {
                var dest = new Span<byte>((void*)ptr, version.Length + 1);
                version.CopyTo(dest);
                dest[version.Length] = 0; // Null terminator
            }
            return ptr;
        }
    }
}