use std::{ffi::c_void, ptr::null_mut, slice};

use thiserror::Error;
use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree},
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
};
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum DpapiError {
    #[error("{api} failed with Windows error {code}")]
    Windows { api: &'static str, code: u32 },

    #[error("{api} returned a null output buffer")]
    NullOutput { api: &'static str },

    #[error("input is too large for DPAPI")]
    InputTooLarge,
}

/// Owns a buffer allocated by Windows DPAPI.
struct OwnedBlob(CRYPT_INTEGER_BLOB);

impl Default for OwnedBlob {
    fn default() -> Self {
        Self(CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        })
    }
}

impl OwnedBlob {
    fn copy_bytes(&self, api: &'static str) -> Result<Vec<u8>, DpapiError> {
        if self.0.pbData.is_null() {
            return Err(DpapiError::NullOutput { api });
        }

        // SAFETY:
        // DPAPI reported success and returned cbData readable bytes.
        let bytes = unsafe { slice::from_raw_parts(self.0.pbData, self.0.cbData as usize) };

        Ok(bytes.to_vec())
    }
}

impl Drop for OwnedBlob {
    fn drop(&mut self) {
        if self.0.pbData.is_null() {
            return;
        }

        // SAFETY:
        // The pointer was allocated by DPAPI. Wipe it before freeing,
        // because it can contain recovered plaintext.
        unsafe {
            std::ptr::write_bytes(self.0.pbData, 0, self.0.cbData as usize);

            let _ = LocalFree(self.0.pbData.cast::<c_void>());
        }
    }
}

fn input_blob(data: &[u8]) -> Result<CRYPT_INTEGER_BLOB, DpapiError> {
    let length = u32::try_from(data.len()).map_err(|_| DpapiError::InputTooLarge)?;

    Ok(CRYPT_INTEGER_BLOB {
        cbData: length,

        // Win32 uses a mutable pointer even though these functions
        // do not modify the input data.
        pbData: data.as_ptr().cast_mut(),
    })
}

/// Protect bytes using the current Windows user account.
pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    let mut input = input_blob(plaintext)?;
    let mut output = OwnedBlob::default();

    // No optional entropy and no LOCAL_MACHINE flag.
    let succeeded = unsafe {
        CryptProtectData(
            &mut input,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.0,
        )
    };

    if succeeded == 0 {
        return Err(DpapiError::Windows {
            api: "CryptProtectData",
            code: unsafe { GetLastError() },
        });
    }

    output.copy_bytes("CryptProtectData")
}

/// Recover bytes previously protected for this Windows user.
pub fn unprotect(protected_data: &[u8]) -> Result<Zeroizing<Vec<u8>>, DpapiError> {
    let mut input = input_blob(protected_data)?;
    let mut output = OwnedBlob::default();

    let succeeded = unsafe {
        CryptUnprotectData(
            &mut input,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.0,
        )
    };

    if succeeded == 0 {
        return Err(DpapiError::Windows {
            api: "CryptUnprotectData",
            code: unsafe { GetLastError() },
        });
    }

    Ok(Zeroizing::new(output.copy_bytes("CryptUnprotectData")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_round_trip() {
        // Fixed bytes are acceptable here because this is only a test fixture.
        let original_secret = [0xA5_u8; 32];

        let protected = protect(&original_secret).expect("DPAPI protection should succeed");

        assert_ne!(
            protected.as_slice(),
            original_secret.as_slice(),
            "protected bytes must differ from plaintext"
        );

        let recovered = unprotect(&protected).expect("DPAPI recovery should succeed");

        assert_eq!(recovered.as_slice(), original_secret.as_slice());
    }
}
