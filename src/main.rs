use std::fs;
use std::io;
use std::str::FromStr;
use std::env;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
struct Credential {
  nonce: Box<[u8]>,
  name: String,
  username: String,
  password: Box<[u8]>,
}

fn read_store_file() -> io::Result<String> {
  // hardcoded ftw
  fs::read_to_string("/home/oskar/passwords.txt")
}

fn read_store() -> Result<Vec<Credential>, Box<dyn std::error::Error>> {
  let file_contents = match read_store_file() {
    Ok(contents) => contents,
    Err(e) => {
      eprintln!("Error reading file: {}", e);
      return Err(e.into());
    }
  };

  let deserialized: Vec<Credential> = serde_json::from_str(&file_contents).unwrap();
  Ok(deserialized)
}

fn decrypt_password(credential: &Credential, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    use chacha20poly1305::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        ChaCha20Poly1305, Nonce, Key,
    };
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(key);
    let key: Key = Key::clone_from_slice(&hash);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from_slice(&credential.nonce);
    let ciphertext = match cipher.decrypt(&nonce, &*credential.password) {
        Ok(pass) => String::from_utf8(pass),
        Err(e) => panic!("Panic decrypt: {}", e)
    };
    Ok(ciphertext?)
}

fn get_credential(credentials: Vec<Credential>, name: &str) -> Result<Credential, Box<dyn std::error::Error>> {
  // seach by similarity. If found one, print it, if found multiple, ask which one you meant
  for cred in credentials {
    if cred.name == *name {
      return Ok(cred);
    }
  }

  Err(format!("Credentials for \"{}\" not found", name).into())
}

fn print_password(credentials: Vec<Credential>, name: &str) {
  match get_credential(credentials, name) {
    Ok(cred) => {
      let key = rpassword::prompt_password("Provide Key: ").unwrap();
      let decrypted_password = match decrypt_password(&cred, &key) {
        Ok(dpass) => dpass,
        Err(e) => panic!("Panic print password, {}", e),
      };

      println!("Name: {}, Username: {}, Password: {}", cred.name, cred.username, decrypted_password);
      return;
    },
    Err(_) => println!("Credentials for \"{}\" not found", name)
  }
}

fn print_all_passwords(credentials: Vec<Credential>) {
  for cred in credentials {
    println!("Name: {}", cred.name);
  }
}

fn asd() -> Result<(), Box<dyn std::error::Error>> {
    use chacha20poly1305::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        ChaCha20Poly1305, Nonce, Key,
    };
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(b"password");
    let key: Key = Key::clone_from_slice(&hash);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, b"asd".as_ref());
    let noncestr = serde_json::to_string(&nonce.as_slice()).unwrap();
    let ciphertextstr = match ciphertext {
        Ok(v) => v,
        Err(e) => panic!("Panic, {}", e),
    };

    let ciphertext2 = match cipher.encrypt(&nonce, b"asd".as_ref()) {
        Ok(pass) => String::from_utf8(pass),
        Err(e) => panic!("Panic decrypt: {}", e)
    };
    let ciphertext3 = match ciphertext2 {
        Ok(passt) => passt,
        Err(e) => panic!("Panic decyrpt2: {}", e)
    };
    println!("encrypted: {}", ciphertext3);

    let ciphertextstr2 = serde_json::to_string(&ciphertextstr.as_slice()).unwrap();
    println!("{}", noncestr);
    println!("{}", ciphertextstr2);
   
    Ok(())
}

fn main() {
  // asd();
  let args: Vec<String> = env::args().collect();

  let search_name: Option<&String> = args.get(1);

  let credentials = match read_store() {
    Ok(s) => s,
    Err(e) => {
      eprintln!("An error occurred: {}", e);
      return;
    }
  };

  match search_name {
    Some(name) => {
      print_password(credentials, name);
      return;
    },
    None => {
      print_all_passwords(credentials);
      return;
    }
  }
}
