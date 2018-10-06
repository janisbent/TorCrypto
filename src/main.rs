extern crate crypto;
extern crate rand;
use crypto::curve25519;
use crypto::aes_gcm::AesGcm;
use crypto::aes::KeySize::KeySize256;
use crypto::aead::AeadEncryptor;
use crypto::aead::AeadDecryptor;
use rand::Rng;
use std::path::Path;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;


#[derive(Clone, Debug)]
struct Crypt {
    sk:  [u8; 32],
    pk:  [u8; 32],
    pkb: [u8; 32],
    ss:  [u8; 32],
}

#[allow(dead_code)]
impl Crypt {
    pub fn new() -> Crypt {
        let mut rng = rand::thread_rng();
        let mut c = Crypt { sk: rng.gen(), pk: [0; 32], pkb: [0; 32], ss: [0; 32] };
        c.gen_sk();
        c
    }

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

    pub fn export(&self, filen: &str)  {
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

    fn gen_sk(&mut self) {
        self.pk = curve25519::curve25519_base(self.sk.as_ref());
    }

    pub fn ecdh(&mut self, pkb: [u8; 32]) {
        self.pkb = pkb;
        self.ss = curve25519::curve25519(self.sk.as_ref(), pkb.as_ref());
    }

    pub fn encrypt(&self, pt: &[u8], ct: &mut [u8], n: &mut [u8; 12], t: &mut [u8; 16]) {
        let mut rng = rand::thread_rng();
        *n = rng.gen();
        let mut a = AesGcm::new(KeySize256, &self.ss, n, &self.pk);
        a.encrypt(pt, ct, t);
    }

    /*
     * 
     */
    pub fn decrypt(&self, ct: &mut [u8], pt: &mut [u8], n: &[u8; 12], t: &mut [u8; 16]) -> bool {
        let mut a = AesGcm::new(KeySize256, &self.ss, n, &self.pk);
        a.decrypt(&ct, pt, t)
    }
}

#[allow(dead_code)]
fn base_example() {
	let sk : [u8; 32] = [
		0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
		0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
		0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a ];
	let pk = curve25519::curve25519_base(sk.as_ref());
	let correct : [u8; 32] = [
		 0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54
		,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a
		,0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4
		,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a ];
	assert_eq!(pk.to_vec(), correct.to_vec());

	let pk2 : [u8; 32] = [
		 0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4
		,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37
		,0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d
		,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f ];

    let ss = curve25519::curve25519(sk.as_ref(), pk2.as_ref());
    let correct : [u8; 32] = [
         0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1
        ,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25
        ,0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33
        ,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42 ];
    assert_eq!(ss.to_vec(), correct.to_vec());
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
    let pkb: [u8; 32] = rng.gen();
    c.ecdh(pkb);

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


fn main() {
    crypt_example();
}
