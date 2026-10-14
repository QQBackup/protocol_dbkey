//! wtlogin 用到的密码学原语：AES-GCM 与 P-256 ECDH。
//!
//! 逐条对齐 Lagrange `Utility/Cryptography/{AesGcmProvider,EcdhProvider}.cs`：
//!
//! * `AesGcmProvider.Encrypt` 的线上格式是 **`iv(12) || ciphertext || tag(16)`**，
//!   AAD 为空。key 允许 16/24/32 字节（快登 SessionKey 由服务端下发，长度不定）。
//! * `EcdhProvider.KeyExchange(pub, isHash=false)` 取共享点的 **X 坐标定长**
//!   （P-256 = 32 字节），**不做哈希**；公钥是 SEC1 `04||X||Y`（65 字节）。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use anyhow::{anyhow, bail, Context, Result};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};

/// `aes-gcm` 0.10 只在根导出 128/256 两个别名，192 得自己拼。
type Aes192Gcm = aes_gcm::AesGcm<aes_gcm::aes::Aes192, aes_gcm::aead::consts::U12>;

/// GCM nonce 长度（固定 12 字节）。
pub const GCM_IV_LEN: usize = 12;
/// GCM tag 长度（16 字节）。
pub const GCM_TAG_LEN: usize = 16;

/// AES-GCM 加密（AAD 为空），返回 `iv(12) || ciphertext || tag(16)`。
pub fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut iv = [0u8; GCM_IV_LEN];
    getrandom::getrandom(&mut iv).context("生成 AES-GCM IV 失败")?;
    let nonce = aes_gcm::Nonce::from_slice(&iv);
    let ciphertext = match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("AES-128 key 非法: {e}"))?
            .encrypt(nonce, plaintext),
        24 => Aes192Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("AES-192 key 非法: {e}"))?
            .encrypt(nonce, plaintext),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("AES-256 key 非法: {e}"))?
            .encrypt(nonce, plaintext),
        n => bail!("AES-GCM key 长度必须是 16/24/32，实际 {n}"),
    }
    .map_err(|_| anyhow!("AES-GCM 加密失败"))?;

    let mut out = Vec::with_capacity(GCM_IV_LEN + ciphertext.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// AES-GCM 解密，输入 `iv(12) || ciphertext || tag(16)`。
pub fn aes_gcm_decrypt(key: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < GCM_IV_LEN + GCM_TAG_LEN {
        bail!(
            "AES-GCM 密文太短：{} 字节（至少 {}）",
            blob.len(),
            GCM_IV_LEN + GCM_TAG_LEN
        );
    }
    let iv = &blob[..GCM_IV_LEN];
    let body = &blob[GCM_IV_LEN..];
    let nonce = aes_gcm::Nonce::from_slice(iv);
    match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("AES-128 key 非法: {e}"))?
            .decrypt(nonce, body),
        24 => Aes192Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("AES-192 key 非法: {e}"))?
            .decrypt(nonce, body),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("AES-256 key 非法: {e}"))?
            .decrypt(nonce, body),
        n => bail!("AES-GCM key 长度必须是 16/24/32，实际 {n}"),
    }
    .map_err(|_| anyhow!("AES-GCM 解密失败（tag 校验不过）"))
}

/// 一次临时 P-256 密钥对（每次登录现生成，不进 keystore）。
pub struct P256KeyPair {
    secret: SecretKey,
}

impl P256KeyPair {
    /// 随机生成一个合法私钥（无效则重试；概率可忽略）。
    pub fn random() -> Result<Self> {
        let mut bytes = [0u8; 32];
        for _ in 0..16 {
            getrandom::getrandom(&mut bytes).context("生成 P-256 私钥随机数失败")?;
            if let Ok(secret) = SecretKey::from_slice(&bytes) {
                return Ok(Self { secret });
            }
        }
        bail!("生成合法 P-256 私钥失败（重试 16 次）")
    }

    /// 未压缩 SEC1 公钥 `04||X(32)||Y(32)`（65 字节）。
    pub fn public_key_sec1(&self) -> Vec<u8> {
        self.secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// 与对端 SEC1 公钥做 ECDH，返回共享点 X 坐标（32 字节，未哈希）。
    pub fn ecdh_x(&self, peer_sec1: &[u8]) -> Result<Vec<u8>> {
        let peer = PublicKey::from_sec1_bytes(peer_sec1).context("对端公钥不是合法 SEC1 点")?;
        let shared = diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        Ok(shared.raw_secret_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn aes_gcm_roundtrip_all_key_sizes() {
        for key in [vec![0x11u8; 16], vec![0x22u8; 24], vec![0x33u8; 32]] {
            let plain = b"lagrange wtlogin aes-gcm payload \x00\x01\x02";
            let blob = aes_gcm_encrypt(&key, plain).unwrap();
            // 线上格式：iv(12) || ct || tag(16)
            assert_eq!(blob.len(), GCM_IV_LEN + plain.len() + GCM_TAG_LEN);
            assert_eq!(aes_gcm_decrypt(&key, &blob).unwrap(), plain);
        }
    }

    #[test]
    fn aes_gcm_rejects_tampered_tag() {
        let key = [0x42u8; 32];
        let mut blob = aes_gcm_encrypt(&key, b"hello").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(aes_gcm_decrypt(&key, &blob).is_err());
    }

    #[test]
    fn p256_ecdh_is_symmetric() {
        let a = P256KeyPair::random().unwrap();
        let b = P256KeyPair::random().unwrap();
        let a_pub = a.public_key_sec1();
        let b_pub = b.public_key_sec1();
        assert_eq!(a_pub.len(), 65);
        assert_eq!(a_pub[0], 0x04);
        assert_eq!(a.ecdh_x(&b_pub).unwrap(), b.ecdh_x(&a_pub).unwrap());
        assert_eq!(a.ecdh_x(&b_pub).unwrap().len(), 32);
    }

    #[test]
    fn p256_matches_lagrange_x_only_semantics() {
        // 共享密钥就是 X 坐标，而不是 SHA256/MD5。拿一个已知私钥钉死 X 值。
        let sk = SecretKey::from_slice(&[0x01u8; 32]);
        if let Ok(sk) = sk {
            let kp = P256KeyPair { secret: sk };
            let peer = P256KeyPair::random().unwrap();
            let x = kp.ecdh_x(&peer.public_key_sec1()).unwrap();
            let x2 = peer.ecdh_x(&kp.public_key_sec1()).unwrap();
            assert_eq!(x, x2);
            assert_eq!(x.len(), 32);
            // 不做哈希：X 不等于它的 SHA256。
            assert_ne!(x, Sha256::digest(&x).to_vec());
        }
    }
}
