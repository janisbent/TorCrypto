extern crate crypto;
extern crate rand;
use crypto::curve25519;
use crypto::aes_gcm::AesGcm;
use crypto::aes::KeySize::KeySize256;
use crypto::aead::{AeadEncryptor, AeadDecryptor};
use rand::Rng;
use std::path::Path;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;


#[derive(Clone, Debug)]
pub struct Crypt {
    sk:  [u8; 32],
    pub pk:  [u8; 32],
    pkb: [u8; 32],
    ss:  [u8; 32],
}

#[allow(dead_code)]
impl Crypt {
    /// Constructs a new Crypt with a random key.
    /// 
    /// # Example 
    ///
    /// ```
    /// fn main() {
    ///     let mut c = Crypt::new();
    ///     // can now use Crypt
    /// }
    /// ```
    pub fn new() -> Crypt {
        let mut rng = rand::thread_rng();
        let mut c = Crypt { sk: rng.gen(), pk: [0; 32], pkb: [0; 32], ss: [0; 32] };
        c.gen_sk();
        c
    }

    /// Constructs a new Crypt with a private key saved in a file.
    /// 
    /// # Example 
    ///
    /// ```
    /// fn main() {
    ///     let mut c = Crypt::from_file("privkey");
    ///     // can now use Crypt
    /// }
    /// ```
    pub fn from_file(filen: &str) -> Crypt {
		let path = Path::new(filen);
        let display = path.display();
		let mut file = match File::open(&path) {
			Err(why) => panic!("couldn't open {}: {}", display,
								why.description()),
			Ok(file) => file,
    	};
		let mut sk = [0; 32];
    	match file.read(&mut sk) {
        	Err(why) => panic!("couldn't read {}: {}", display,
                               why.description()),
        	Ok(_) => (),
    	}
        let mut c = Crypt { sk: sk, pk: [0; 32], pkb: [0; 32], ss: [0; 32] };
        c.gen_sk();
        c
    }

    /// Exports the private key to a file.
    ///
    /// # Example
    ///
    /// ```
    /// fn main() {
    ///     let mut c = Crypt::new();
    ///     c.export("privkey");
    /// }
    /// ```
    pub fn export_pri(&self, filen: &str)  {
		let path = Path::new(filen);
        let display = path.display();
		let mut file = match File::create(&path) {
			Err(why) => panic!("couldn't open {}: {}", display,
								why.description()),
			Ok(file) => file,
    	};
    	match file.write(&self.sk) {
        	Err(why) => panic!("couldn't write to {}: {}", display,
                               why.description()),
        	Ok(_) => (),
    	}
    }

    /// Exports the public key to a file.
    ///
    /// # Example
    ///
    /// ```
    /// fn main() {
    ///     let mut c = Crypt::new();
    ///     c.export("pubkey");
    /// }
    /// ```
    pub fn export_pub(&self, filen: &str)  {
		let path = Path::new(filen);
        let display = path.display();
		let mut file = match File::create(&path) {
			Err(why) => panic!("couldn't open {}: {}", display,
								why.description()),
			Ok(file) => file,
    	};
    	match file.write(&self.pk) {
        	Err(why) => panic!("couldn't write to {}: {}", display,
                               why.description()),
        	Ok(_) => (),
    	}
    }

    fn gen_sk(&mut self) {
        self.pk = curve25519::curve25519_base(self.sk.as_ref());
    }

    /// Performs Elliptic Curve Diffie-Hellman to generate a shared key.
    ///
    /// # Example
    ///
    /// ```
    /// fn main() {
    ///     let mut c = Crypt::new();
    ///     let pubkeyb = [0; 32];
    ///     c.ecdh(&pubkeyb);
    ///     // proceed with encryption
    /// }
    /// ```
    pub fn ecdh(&mut self, &pkb: &[u8; 32]) {
        self.pkb = pkb;
        self.ss = curve25519::curve25519(self.sk.as_ref(), pkb.as_ref());
    }

    /// Encrypts a buffer using AES GCM.
    ///
    /// # Example
    ///
    /// ```
    /// fn main() {
    ///     let mut c = Crypt::new();
    ///     let pubkeyb = [0; 32];
    ///     c.ecdh(&pubkey);
    ///     let pt = [1; 32];
    ///     let ct = [2; 32];
    ///     let n  = [3; 12];
    ///     let t  = [4; 16];
    ///     c.encrypt(&pt, &ct, &n, &t);
    /// }
    pub fn encrypt(&self, pt: &[u8], ct: &mut [u8], n: &mut [u8; 12], t: &mut [u8; 16]) {
        let mut rng = rand::thread_rng();
        *n = rng.gen();
        let mut a = AesGcm::new(KeySize256, &self.ss, n, &self.pk);
        a.encrypt(pt, ct, t);
    }

    /// Decrypts a buffer using AES GCM.
    ///
    /// # Example
    ///
    /// ```
    /// fn main() {
    ///     let mut c = Crypt::new();
    ///     let pubkeyb = [0; 32];
    ///     c.ecdh(&pubkey);
    ///     let pt = [1; 32];
    ///     let mut ct = [2; 32];
    ///     let n  = [3; 12];
    ///     let mut t  = [4; 16];
    ///     c.encrypt(&pt, &mut ct, &n, &mut t);
    ///     let mut pt2 = [5; 32];
    ///     c.decrypt(&ct, &mut pt2, &n, &t);
    ///     assert!(pt.to_vec() = pt2.to_vec());
    /// }
    pub fn decrypt(&self, ct: &mut [u8], pt: &mut [u8], n: &[u8; 12], t: &mut [u8; 16]) -> bool {
        let mut a = AesGcm::new(KeySize256, &self.ss, n, &self.pkb);
        a.decrypt(&ct, pt, t)
    }
}

#[allow(dead_code)]
fn aes_example() {
    let mut rng = rand::thread_rng();
    let pk: [u8; 32] = rng.gen();
    let k: [u8; 32] = rng.gen();
    let n: [u8; 12] = rng.gen();
    let mut a1 = AesGcm::new(KeySize256, &k, &n, &pk);

    let pt: [u8; 32] = rng.gen();
    let mut ct = [0; 32];
    let mut t = [0; 16];
    a1.encrypt(&pt, &mut ct, &mut t);
    println!("pt: {:?}", pt);
    println!("ct: {:?}", ct);
    println!("t: {:?}", t);

    let mut a2 = AesGcm::new(KeySize256, &k, &n, &pk);
    let mut out = [0; 32];
    match a2.decrypt(&ct, &mut out, &t) {
        false => println!("Encryption failed!"),
        true  => println!("out: {:?}", out),
    }

}

#[allow(dead_code)]
fn crypt_example() {
    let mut c = Crypt::from_file("privkey");
    let mut rng = rand::thread_rng();
    let pkb: [u8; 32] = c.pk.clone();
    c.ecdh(&pkb);

    let mut pt: [u8; 32] = rng.gen();
    let mut ct = [0; 32];
    let mut out = [0; 32];
    let mut n = [0; 12];
    let mut t = [0; 16];
    c.encrypt(&mut pt, &mut ct, &mut n, &mut t);
    match c.decrypt(&mut ct, &mut out, &mut n, &mut t) {
        true  => println!("pt2: {:?}", out),
        false => println!("Failed to decrypt!"),
    }
}

